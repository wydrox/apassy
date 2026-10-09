//! AutoFill (contract sections 5.7 and 8): which logins match a page or an app, and
//! the identities for the QuickType bar.

use serde::Serialize;

use apassy::vault::Vault;

use super::errors::CoreResult;
use super::items::{self, Archived, Row};

/// A host and a port, from a website value or a service identifier of iOS.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Site {
    pub host: String,
    pub port: Option<u16>,
}

impl Site {
    /// Parse `https://www.example.com:8443/path`, `example.com`, or a bare domain. A
    /// value without a scheme gets `https://`. None for a value without a host.
    pub fn parse(text: &str) -> Option<Self> {
        let text = text.trim();
        let rest = match text.split_once("://") {
            Some((scheme, rest))
                if !scheme.is_empty()
                    && scheme
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"+-.".contains(&b)) =>
            {
                rest
            }
            Some(_) => return None,
            None => text,
        };
        // A backslash ends the host as `/` does in a browser.
        let authority = rest.split(['/', '?', '#', '\\']).next().unwrap_or("");
        let authority = authority
            .rsplit_once('@')
            .map_or(authority, |(_, host)| host);
        let (host, port) = match authority.rsplit_once(':') {
            Some((host, port)) if !host.contains(']') || host.ends_with(']') => {
                (host, Some(port.parse::<u16>().ok()?))
            }
            _ => (authority, None),
        };
        let host = host.trim_end_matches('.').to_lowercase();
        let host = host.strip_prefix("www.").unwrap_or(&host).to_owned();
        if host.is_empty()
            || !host
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-.[]:".contains(&b))
        {
            return None;
        }
        Some(Self { host, port })
    }

    /// Whether a login for `self` (its website) may fill on `page` (contract section 8).
    pub fn matches(&self, page: &Site) -> bool {
        if self.port.is_some() && self.port != page.port {
            return false;
        }
        if page.port.is_some() && self.port.is_none() {
            return false;
        }
        if self.host == page.host {
            return true;
        }
        let (short, long) = if self.host.len() < page.host.len() {
            (&self.host, &page.host)
        } else {
            (&page.host, &self.host)
        };
        short.contains('.') && long.ends_with(&format!(".{short}"))
    }
}

/// A login that AutoFill can offer.
#[derive(Debug, Serialize)]
pub struct Fill {
    pub id: u64,
    pub title: String,
    pub username: String,
    pub website: Option<String>,
    pub has_totp: bool,
}

#[derive(Debug, Serialize)]
pub struct FillList {
    pub matches: Vec<Fill>,
    pub others: Vec<Fill>,
}

fn logins(vault: &Vault) -> CoreResult<Vec<Row>> {
    Ok(items::rows(vault, Archived::No)?
        .into_iter()
        .filter(|row| row.kind == "login")
        .collect())
}

fn fill(row: &Row) -> Fill {
    Fill {
        id: row.id,
        title: row.title.clone(),
        username: row.subtitle.clone(),
        website: row.websites.first().cloned(),
        has_totp: row.has_totp,
    }
}

pub fn list(vault: &Vault, domains: &[String]) -> CoreResult<FillList> {
    let pages: Vec<Site> = domains
        .iter()
        .filter_map(|domain| Site::parse(domain))
        .collect();
    let mut matches = Vec::new();
    let mut others = Vec::new();
    for row in logins(vault)? {
        let hit = row
            .websites
            .iter()
            .filter_map(|site| Site::parse(site))
            .any(|site| pages.iter().any(|page| site.matches(page)));
        if hit {
            matches.push(fill(&row))
        } else {
            others.push(fill(&row))
        }
    }
    Ok(FillList { matches, others })
}

/// A login for the QuickType bar: no password.
#[derive(Debug, Serialize, PartialEq, Eq)]
pub struct Identity {
    pub id: u64,
    pub username: String,
    pub host: String,
}

pub fn identities(vault: &Vault) -> CoreResult<Vec<Identity>> {
    let mut out = Vec::new();
    for row in logins(vault)? {
        for site in row.websites.iter().filter_map(|site| Site::parse(site)) {
            let host = match site.port {
                Some(port) => format!("{}:{port}", site.host),
                None => site.host,
            };
            if !out
                .iter()
                .any(|known: &Identity| known.id == row.id && known.host == host)
            {
                out.push(Identity {
                    id: row.id,
                    username: row.subtitle.clone(),
                    host,
                });
            }
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::Site;

    fn matches(website: &str, page: &str) -> bool {
        Site::parse(website)
            .unwrap()
            .matches(&Site::parse(page).unwrap())
    }

    #[test]
    fn hosts_and_subdomains() {
        assert!(matches("https://github.com", "github.com"));
        assert!(matches("github.com", "https://gist.github.com/x"));
        assert!(matches("https://www.github.com/login", "github.com"));
        assert!(matches("https://accounts.example.com", "example.com"));
        assert!(!matches("https://github.com", "notgithub.com"));
        assert!(!matches("https://github.com", "github.com.evil.example"));
        assert!(!matches("https://localhost", "evil.localhost"));
        assert!(!matches("com", "github.com"));
    }

    #[test]
    fn ports() {
        assert!(matches("http://127.0.0.1:8443", "https://127.0.0.1:8443/"));
        assert!(!matches("http://127.0.0.1:8443", "127.0.0.1"));
        assert!(!matches("example.com", "example.com:8443"));
    }

    #[test]
    fn junk() {
        assert!(Site::parse("").is_none());
        assert!(Site::parse("javascript alert(1)").is_none());
        assert!(Site::parse("https://").is_none());
        assert_eq!(
            Site::parse("https://user@Example.COM./x").unwrap().host,
            "example.com"
        );
        // A browser reads the host before the backslash.
        assert_eq!(
            Site::parse("https://evil.com\\@github.com/").unwrap().host,
            "evil.com"
        );
    }
}
