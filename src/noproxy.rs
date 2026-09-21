use std::net::IpAddr;

/// Return true if `host` should bypass the corporate proxy.
pub fn matches(host: &str, rules: &[String]) -> bool {
    let host = host.trim().trim_end_matches('.');
    if host.is_empty() {
        return false;
    }
    let host_ip = host.parse::<IpAddr>().ok();
    rules.iter().any(|rule| rule_matches(host, host_ip, rule))
}

fn rule_matches(host: &str, host_ip: Option<IpAddr>, rule: &str) -> bool {
    let rule = rule.trim();
    if rule.is_empty() {
        return false;
    }
    if let Some(net) = rule.split_once('/').and_then(|(n, p)| {
        let ip = n.parse::<IpAddr>().ok()?;
        let prefix: u8 = p.parse().ok()?;
        Some((ip, prefix))
    }) {
        return host_ip.is_some_and(|ip| cidr_contains(net.0, net.1, ip));
    }
    if rule.contains('*') {
        return wildcard_match(&rule.to_ascii_lowercase(), &host.to_ascii_lowercase());
    }
    if let Ok(rule_ip) = rule.parse::<IpAddr>() {
        return host_ip == Some(rule_ip);
    }
    let host_l = host.to_ascii_lowercase();
    let rule_l = rule.to_ascii_lowercase();
    host_l == rule_l || host_l.ends_with(&format!(".{rule_l}"))
}

fn wildcard_match(pattern: &str, value: &str) -> bool {
    let parts: Vec<&str> = pattern.split('*').collect();
    if parts.len() == 1 {
        return pattern == value;
    }
    let mut rest = value;
    if !parts[0].is_empty() {
        if !rest.starts_with(parts[0]) {
            return false;
        }
        rest = &rest[parts[0].len()..];
    }
    for (i, part) in parts.iter().enumerate().skip(1) {
        if part.is_empty() {
            if i == parts.len() - 1 {
                return true;
            }
            continue;
        }
        match rest.find(part) {
            Some(idx) => rest = &rest[idx + part.len()..],
            None => return false,
        }
    }
    parts.last().is_none_or(|p| p.is_empty() || rest.is_empty())
}

fn cidr_contains(net: IpAddr, prefix: u8, host: IpAddr) -> bool {
    match (net, host) {
        (IpAddr::V4(n), IpAddr::V4(h)) => {
            let mask = if prefix == 0 {
                0
            } else if prefix >= 32 {
                u32::MAX
            } else {
                !((1u32 << (32 - prefix)) - 1)
            };
            u32::from(n) & mask == u32::from(h) & mask
        }
        (IpAddr::V6(n), IpAddr::V6(h)) => {
            let n = u128::from(n);
            let h = u128::from(h);
            let mask = if prefix == 0 {
                0
            } else if prefix >= 128 {
                u128::MAX
            } else {
                !((1u128 << (128 - prefix)) - 1)
            };
            n & mask == h & mask
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rules(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| (*s).to_string()).collect()
    }

    #[test]
    fn localhost_and_lan() {
        let r = rules(&["localhost", "127.0.0.1", "10.0.0.0/8", "*.corp.local"]);
        assert!(matches("localhost", &r));
        assert!(matches("127.0.0.1", &r));
        assert!(matches("10.1.2.3", &r));
        assert!(!matches("example.com", &r));
        assert!(matches("app.corp.local", &r));
    }

    #[test]
    fn wildcard_ip() {
        let r = rules(&["192.168.*"]);
        assert!(matches("192.168.1.1", &r));
        assert!(!matches("192.169.1.1", &r));
    }
}
