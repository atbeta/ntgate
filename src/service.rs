use std::path::Path;

use crate::config::Config;
#[cfg(not(windows))]
use crate::error::Error;
use crate::error::Result;

#[cfg(windows)]
const TASK_NAME: &str = "cntlm-next";

pub fn install(config_path: &Path) -> Result<()> {
    #[cfg(windows)]
    {
        windows::install(config_path)
    }
    #[cfg(not(windows))]
    {
        let _ = config_path;
        Err(Error::Unsupported(
            "install registers a Windows logon task; this OS is not supported",
        ))
    }
}

pub fn uninstall() -> Result<()> {
    #[cfg(windows)]
    {
        windows::uninstall()
    }
    #[cfg(not(windows))]
    {
        Err(Error::Unsupported("uninstall is Windows-only"))
    }
}

pub fn status(cfg: &Config) -> Result<()> {
    println!(
        "config      {}",
        crate::config::default_config_path().display()
    );
    println!("listen      {}", cfg.listen);
    println!("mode        {:?}", cfg.mode);
    #[cfg(windows)]
    {
        windows::print_task_status();
    }
    #[cfg(not(windows))]
    {
        println!("service     not applicable (Windows-only)");
    }
    Ok(())
}

#[cfg(windows)]
mod windows {
    use std::io::Write;
    use std::path::Path;
    use std::process::Command;

    use super::TASK_NAME;
    use crate::error::{Error, Result};

    pub fn install(config_path: &Path) -> Result<()> {
        let exe = std::env::current_exe()?;
        let exe_s = exe.to_string_lossy().replace('/', "\\");
        let cfg_s = config_path.to_string_lossy().replace('/', "\\");
        let xml = task_xml(&exe_s, &cfg_s);
        let tmp = std::env::temp_dir().join("cntlm-next-task.xml");
        {
            let mut f = std::fs::File::create(&tmp)?;
            f.write_all(xml.as_bytes())?;
        }
        let out = Command::new("schtasks")
            .args(["/Create", "/TN", TASK_NAME, "/XML"])
            .arg(&tmp)
            .arg("/F")
            .output()?;
        let _ = std::fs::remove_file(&tmp);
        if !out.status.success() {
            return Err(Error::msg(format!(
                "schtasks failed: {}",
                String::from_utf8_lossy(&out.stderr)
            )));
        }
        println!("installed logon task `{TASK_NAME}`");
        println!("  exe     {exe_s}");
        println!("  config  {cfg_s}");
        println!("  starts at user logon, restarts on failure");
        Ok(())
    }

    pub fn uninstall() -> Result<()> {
        let out = Command::new("schtasks")
            .args(["/Delete", "/TN", TASK_NAME, "/F"])
            .output()?;
        if !out.status.success() {
            let err = String::from_utf8_lossy(&out.stderr);
            if !err.to_ascii_lowercase().contains("cannot find") {
                return Err(Error::msg(format!("schtasks delete failed: {err}")));
            }
        }
        println!("removed logon task `{TASK_NAME}`");
        Ok(())
    }

    pub fn print_task_status() {
        let out = Command::new("schtasks")
            .args(["/Query", "/TN", TASK_NAME, "/FO", "LIST"])
            .output();
        match out {
            Ok(o) if o.status.success() => {
                println!("service     installed (Task Scheduler `{TASK_NAME}`)");
            }
            _ => println!("service     not installed"),
        }
    }

    fn xml_escape(s: &str) -> String {
        s.replace('&', "&amp;")
            .replace('<', "&lt;")
            .replace('>', "&gt;")
            .replace('"', "&quot;")
    }

    fn task_xml(exe: &str, config: &str) -> String {
        let exe = xml_escape(exe);
        let args = xml_escape(&format!("run -c \"{config}\""));
        format!(
            r#"<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Description>cntlm-next local NTLM/Negotiate proxy facade</Description>
  </RegistrationInfo>
  <Triggers>
    <LogonTrigger>
      <Enabled>true</Enabled>
    </LogonTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <LogonType>InteractiveToken</LogonType>
      <RunLevel>LeastPrivilege</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <StartWhenAvailable>true</StartWhenAvailable>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <IdleSettings>
      <StopOnIdleEnd>false</StopOnIdleEnd>
      <RestartOnIdle>false</RestartOnIdle>
    </IdleSettings>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>true</Hidden>
    <RunOnlyIfIdle>false</RunOnlyIfIdle>
    <WakeToRun>false</WakeToRun>
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
    <Priority>7</Priority>
    <RestartOnFailure>
      <Interval>PT5S</Interval>
      <Count>3</Count>
    </RestartOnFailure>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>{exe}</Command>
      <Arguments>{args}</Arguments>
    </Exec>
  </Actions>
</Task>
"#
        )
    }
}
