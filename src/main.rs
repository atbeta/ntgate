use std::path::PathBuf;

use clap::{Parser, Subcommand};
use tracing_subscriber::EnvFilter;

use cntlm_next::config::{self, Config};
use cntlm_next::error::Result;

#[derive(Parser, Debug)]
#[command(
    name = "cntlm-next",
    version,
    about = "Windows NTLM/Negotiate local proxy facade"
)]
struct Cli {
    /// Config file (default: %LOCALAPPDATA%\cntlm-next\cntlm-next\config.toml)
    #[arg(short, long, global = true)]
    config: Option<PathBuf>,

    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Run the local proxy (default)
    Run,
    /// Probe upstream using current Windows credentials
    Doctor,
    /// Print HTTP_PROXY / HTTPS_PROXY for the local listener
    PrintEnv,
    /// Register a logon task so the proxy starts after you sign in
    Install,
    /// Remove the logon task
    Uninstall,
    /// Show config path and whether the logon task exists
    Status,
}

fn main() -> anyhow::Result<()> {
    init_tracing();
    let cli = Cli::parse();
    let config_path = cli.config.unwrap_or_else(config::default_config_path);

    match cli.command.unwrap_or(Command::Run) {
        Command::Run => {
            let cfg = load_or_create(&config_path)?;
            tokio::runtime::Runtime::new()?.block_on(cntlm_next::server::run(cfg))?;
        }
        Command::Doctor => {
            let cfg = load_or_create(&config_path)?;
            tokio::runtime::Runtime::new()?.block_on(cntlm_next::doctor::run(&cfg))?;
        }
        Command::PrintEnv => {
            let cfg = load_or_create(&config_path)?;
            let proxy = format!("http://{}", cfg.listen);
            println!("set HTTP_PROXY={proxy}");
            println!("set HTTPS_PROXY={proxy}");
            println!("set NO_PROXY=localhost,127.0.0.1");
            println!("git config --global http.proxy {proxy}");
            println!("git config --global https.proxy {proxy}");
        }
        Command::Install => {
            let _ = load_or_create(&config_path)?;
            cntlm_next::service::install(&config_path)?;
        }
        Command::Uninstall => cntlm_next::service::uninstall()?,
        Command::Status => {
            let cfg = load_or_create(&config_path)?;
            cntlm_next::service::status(&cfg)?;
        }
    }
    Ok(())
}

fn load_or_create(path: &std::path::Path) -> Result<Config> {
    if config::write_example_if_missing(path)? {
        eprintln!("wrote default config {}", path.display());
    }
    Config::load_path(path)
}

fn init_tracing() {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .init();
}
