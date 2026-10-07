//! Which site gets a login (ADR 0021, section 5).
//!
//! A wrong match gives a password to the wrong site, so the match is strict:
//!
//! - The page must be `https:`. `http:` works only for `localhost` and the loopback
//!   addresses.
//! - The page host matches when it is the website host, or ends with "." and that
//!   host. A website with one label matches only itself. A website `www.example.com`
//!   also matches `example.com`, but not the other subdomains of `example.com`.
//! - An IP address matches only itself. The port of the page must be the port of the
//!   website: a website without a port matches only the default port. On a loopback
//!   host another port is another program.
//!
//! The code needs no URL crate and no public suffix list. The browser gives the page
//! address in its canonical form (lowercase, punycode), so the page parser refuses what
//! it does not expect. The website parser takes what an owner types or what an import
//! brings: no scheme, uppercase, a path.

use std::fmt;

use super::wire::MAX_URL_BYTES;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Scheme {
    Https,
    Http,
}

impl Scheme {
    fn as_str(self) -> &'static str {
        match self {
            Self::Https => "https",
            Self::Http => "http",
        }
    }

    fn default_port(self) -> u16 {
        match self {
            Self::Https => 443,
            Self::Http => 80,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Host {
    /// A domain name: lowercase ASCII labels.
    Name(String),
    V4([u8; 4]),
    /// The address in brackets, lowercase, as the browser writes it.
    V6(String),
}

impl fmt::Display for Host {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Name(name) => f.write_str(name),
            Self::V4([a, b, c, d]) => write!(f, "{a}.{b}.{c}.{d}"),
            Self::V6(text) => f.write_str(text),
        }
    }
}

impl Host {
    fn is_loopback(&self) -> bool {
        match self {
            Self::Name(name) => name == "localhost" || name.ends_with(".localhost"),
            Self::V4(octets) => octets[0] == 127,
            Self::V6(text) => text == "[::1]",
        }
    }
}

/// Why a page cannot get a login.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PageError {
    /// Not an `http:` or `https:` page, for example `chrome://` or `file://`.
    NotWeb,
    /// An `http:` page that is not on this Mac.
    Insecure,
    /// The address is too long, has a user name, or has a host that is not valid.
    Invalid,
}

impl PageError {
    /// Text for the owner.
    pub fn message(self) -> &'static str {
        match self {
            Self::NotWeb => "Apassy fills logins on web pages only.",
            Self::Insecure => {
                "Apassy fills logins on https pages only. http works only for localhost."
            }
            Self::Invalid => "Apassy cannot read the address of this page.",
        }
    }
}

/// The page in the active tab.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Page {
    scheme: Scheme,
    host: Host,
    /// `None` for the default port of the scheme.
    port: Option<u16>,
}

impl Page {
    /// Parse the address that the browser gives for the active tab.
    pub fn parse(url: &str) -> Result<Self, PageError> {
        if url.len() > MAX_URL_BYTES {
            return Err(PageError::Invalid);
        }
        let Some((scheme, rest)) = url.split_once("://") else {
            return Err(PageError::NotWeb);
        };
        let scheme = match scheme.to_ascii_lowercase().as_str() {
            "https" => Scheme::Https,
            "http" => Scheme::Http,
            _ => return Err(PageError::NotWeb),
        };
        let (host, port) = parse_authority(authority(rest), scheme).ok_or(PageError::Invalid)?;
        if scheme == Scheme::Http && !host.is_loopback() {
            return Err(PageError::Insecure);
        }
        Ok(Self { scheme, host, port })
    }

    /// `scheme://host`, and `:port` when the port is not the default.
    pub fn origin(&self) -> String {
        match self.port {
            Some(port) => format!("{}://{}:{port}", self.scheme.as_str(), self.host),
            None => format!("{}://{}", self.scheme.as_str(), self.host),
        }
    }

    /// The host, for the owner.
    pub fn host(&self) -> String {
        self.host.to_string()
    }
}

/// One website of a login.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Website {
    host: Host,
    /// `None` when the value names no port, or the default port of its scheme. Then only
    /// a page on the default port matches.
    port: Option<u16>,
}

impl Website {
    /// Parse a website value. `None` for a value that is not a web address, for
    /// example an app link of a 1Password item.
    pub fn parse(value: &str) -> Option<Self> {
        let value = value.trim();
        if value.is_empty() || value.len() > MAX_URL_BYTES {
            return None;
        }
        let (scheme, rest) = match value.split_once("://") {
            Some((scheme, rest)) => match scheme.to_ascii_lowercase().as_str() {
                "https" => (Scheme::Https, rest),
                "http" => (Scheme::Http, rest),
                _ => return None,
            },
            None => (Scheme::Https, value),
        };
        let (host, port) = parse_authority(&authority(rest).to_ascii_lowercase(), scheme)?;
        Some(Self { host, port })
    }

    /// True when this website may get its login on `page`.
    pub fn matches(&self, page: &Page) -> bool {
        if self.port != page.port {
            return false;
        }
        match (&self.host, &page.host) {
            (Host::Name(site), Host::Name(host)) => {
                host == site
                    || site
                        .strip_prefix("www.")
                        .is_some_and(|bare| bare.contains('.') && host == bare)
                    || (site.contains('.')
                        && host.len() > site.len()
                        && host.ends_with(site.as_str())
                        && host.as_bytes()[host.len() - site.len() - 1] == b'.')
            }
            (Host::V4(site), Host::V4(host)) => site == host,
            (Host::V6(site), Host::V6(host)) => site == host,
            _ => false,
        }
    }
}

/// True when a visible field of a login holds a website: the field `website` or `url`,
/// or a custom detail whose label starts with "website" or "url" without regard to case.
/// `label` is the label of a custom detail, `None` for another field.
pub fn is_website_field(name: &str, label: Option<&str>) -> bool {
    if name == "website" || name == "url" {
        return true;
    }
    label.is_some_and(|label| {
        let label = label.trim().to_lowercase();
        label.starts_with("website") || label.starts_with("url")
    })
}

/// The authority of an address without its scheme: up to the path, the query, or the
/// fragment.
fn authority(rest: &str) -> &str {
    let end = rest.find(['/', '?', '#', '\\']).unwrap_or(rest.len());
    &rest[..end]
}

/// The host and the port of an authority. A user name, an empty host, or a character
/// that a host cannot have gives `None`. The default port of `scheme` becomes `None`.
fn parse_authority(authority: &str, scheme: Scheme) -> Option<(Host, Option<u16>)> {
    if authority.is_empty() || authority.contains('@') {
        return None;
    }
    let (host_text, port_text) = if authority.starts_with('[') {
        let end = authority.find(']')?;
        let after = &authority[end + 1..];
        let port = match after {
            "" => None,
            _ => Some(after.strip_prefix(':')?),
        };
        (&authority[..=end], port)
    } else {
        match authority.rsplit_once(':') {
            Some((host, port)) => (host, Some(port)),
            None => (authority, None),
        }
    };
    let port = match port_text {
        None | Some("") => None,
        Some(text) => {
            if !text.bytes().all(|byte| byte.is_ascii_digit()) || text.len() > 5 {
                return None;
            }
            let port: u16 = text.parse().ok()?;
            if port == 0 {
                return None;
            }
            (port != scheme.default_port()).then_some(port)
        }
    };
    Some((parse_host(host_text)?, port))
}

fn parse_host(text: &str) -> Option<Host> {
    if let Some(inner) = text.strip_prefix('[') {
        let inner = inner.strip_suffix(']')?;
        let valid = !inner.is_empty()
            && inner.contains(':')
            && inner
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() || byte == b':' || byte == b'.');
        return valid.then(|| Host::V6(format!("[{}]", inner.to_ascii_lowercase())));
    }
    let name = text.strip_suffix('.').unwrap_or(text).to_ascii_lowercase();
    if name.is_empty() || name.len() > 253 {
        return None;
    }
    if let Some(octets) = parse_v4(&name) {
        return Some(Host::V4(octets));
    }
    let labels_ok = name.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    });
    // A name of digits and dots only is a malformed address, not a domain.
    let all_numeric = name
        .bytes()
        .all(|byte| byte.is_ascii_digit() || byte == b'.');
    (labels_ok && !all_numeric).then_some(Host::Name(name))
}

fn parse_v4(text: &str) -> Option<[u8; 4]> {
    let mut octets = [0u8; 4];
    let mut parts = text.split('.');
    for octet in &mut octets {
        let part = parts.next()?;
        if part.is_empty() || part.len() > 3 || !part.bytes().all(|byte| byte.is_ascii_digit()) {
            return None;
        }
        *octet = part.parse().ok()?;
    }
    parts.next().is_none().then_some(octets)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn page(url: &str) -> Page {
        Page::parse(url).unwrap_or_else(|err| panic!("{url}: {err:?}"))
    }

    fn matches(website: &str, url: &str) -> bool {
        Website::parse(website)
            .unwrap_or_else(|| panic!("website {website}"))
            .matches(&page(url))
    }

    #[test]
    fn pages_must_be_https_or_local_http() {
        assert_eq!(
            page("https://github.com/login").origin(),
            "https://github.com"
        );
        assert_eq!(
            page("https://github.com:8443/x").origin(),
            "https://github.com:8443"
        );
        assert_eq!(
            page("https://github.com:443/").origin(),
            "https://github.com"
        );
        assert_eq!(
            page("http://localhost:3000/login").origin(),
            "http://localhost:3000"
        );
        assert_eq!(
            page("http://127.0.0.1:8080/").origin(),
            "http://127.0.0.1:8080"
        );
        assert_eq!(page("http://[::1]:8080/").origin(), "http://[::1]:8080");
        assert_eq!(
            page("http://app.localhost/").origin(),
            "http://app.localhost"
        );
        assert_eq!(Page::parse("http://github.com/"), Err(PageError::Insecure));
        assert_eq!(Page::parse("http://10.0.0.1/"), Err(PageError::Insecure));
        assert_eq!(Page::parse("chrome://settings"), Err(PageError::NotWeb));
        assert_eq!(Page::parse("file:///etc/hosts"), Err(PageError::NotWeb));
        assert_eq!(Page::parse("about:blank"), Err(PageError::NotWeb));
        assert_eq!(
            Page::parse("https://user:pw@github.com/"),
            Err(PageError::Invalid)
        );
        assert_eq!(Page::parse("https:///path"), Err(PageError::Invalid));
        assert_eq!(
            Page::parse("https://exa mple.com/"),
            Err(PageError::Invalid)
        );
        assert_eq!(Page::parse("https://a..com/"), Err(PageError::Invalid));
        assert_eq!(
            Page::parse("https://github.com:0/"),
            Err(PageError::Invalid)
        );
        assert_eq!(
            Page::parse("https://github.com:99999/"),
            Err(PageError::Invalid)
        );
    }

    #[test]
    fn a_website_matches_its_host_and_its_subdomains() {
        assert!(matches("github.com", "https://github.com/login"));
        assert!(matches(
            "https://github.com/login",
            "https://gist.github.com/"
        ));
        assert!(matches("https://www.github.com", "https://github.com/"));
        assert!(matches("www.github.com", "https://www.github.com/"));
        assert!(matches("github.com", "https://www.github.com/"));
        // "www." does not widen the match to the other subdomains of the site.
        assert!(!matches("www.tumblr.com", "https://attacker.tumblr.com/"));
        assert!(matches("GitHub.com/", "https://github.com/"));
        assert!(matches("http://github.com", "https://github.com/"));
        assert!(matches(" https://github.com ", "https://github.com/"));
        assert!(!matches("github.com", "https://evilgithub.com/"));
        assert!(!matches("github.com", "https://github.com.evil.example/"));
        assert!(!matches("accounts.google.com", "https://google.com/"));
        assert!(!matches("github.com", "https://github.co/"));
    }

    #[test]
    fn ports_and_addresses_match_exactly() {
        assert!(matches("localhost:3000", "http://localhost:3000/"));
        assert!(!matches("localhost:3000", "http://localhost:4000/"));
        // Another port on this Mac is another program: no port means the default port.
        assert!(!matches("localhost", "http://localhost:4000/"));
        assert!(matches("localhost", "http://localhost/"));
        assert!(matches("https://example.com:443", "https://example.com/"));
        assert!(!matches("https://example.com:8443", "https://example.com/"));
        assert!(!matches("example.com", "https://example.com:8443/"));
        assert!(matches("127.0.0.1:8080", "http://127.0.0.1:8080/"));
        assert!(!matches("127.0.0.1", "http://127.0.0.1:8080/"));
        assert!(!matches("127.0.0.1", "http://127.0.0.2/"));
        assert_eq!(Website::parse("0.0.1"), None);
        assert!(matches("[::1]:8080", "http://[::1]:8080/"));
        assert!(!matches("[::1]", "http://[::1]:8080/"));
        assert!(!matches("localhost", "http://127.0.0.1/"));
    }

    #[test]
    fn a_one_label_website_matches_only_itself() {
        assert!(matches("intranet", "https://intranet/"));
        assert!(!matches("intranet", "https://wiki.intranet/"));
        // A leading "www." stays when nothing with a dot is left.
        assert!(!matches("www.com", "https://evil.com/"));
    }

    #[test]
    fn values_that_are_not_web_addresses_are_skipped() {
        assert_eq!(Website::parse(""), None);
        assert_eq!(Website::parse("android://com.example.app"), None);
        assert_eq!(Website::parse("ftp://files.example.com"), None);
        assert_eq!(Website::parse("user@example.com"), None);
        assert_eq!(Website::parse("not a host"), None);
    }

    #[test]
    fn website_fields_are_named_or_labelled() {
        assert!(is_website_field("website", None));
        assert!(is_website_field("url", None));
        assert!(is_website_field("x_57656273697465", Some("Website")));
        assert!(is_website_field("x_1", Some("Website 2")));
        assert!(is_website_field("x_1", Some("URL")));
        assert!(!is_website_field("service", None));
        assert!(!is_website_field("x_1", Some("Login page")));
        assert!(!is_website_field("username", None));
    }
}
