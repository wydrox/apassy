//! Value-free agent requests, guarded extension delivery, and acknowledgement.
use std::collections::BTreeMap;
use std::sync::{LazyLock, Mutex};
use std::time::{Duration, Instant};

use super::decide::BrokerContext;
use crate::agent::wire::WireResponse;
use crate::browser::site::{Page, Website, is_website_field};
use crate::browser::trust::InstanceIdentity;
#[cfg(any(feature = "desktop", test))]
use crate::browser::wire::Response;
use crate::browser::wire::{BrowserDocument, Data};
use crate::contracts::CredentialKind;
use crate::owner::wire::SecretText;
use crate::vault::{Vault, custom_detail_label};
use serde_json::json;

const OPEN: &str = "Open the login page in the browser first";
const REMOTE: &str = "This browser runs with remote debugging. In Apassy, trust this browser instance first (Settings → Browser).";
const FRESH: Duration = Duration::from_secs(4);
const CHANGED: &str = "The login page changed. Ask again.";

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

struct Target {
    url: String,
    document: Option<BrowserDocument>,
    focused: bool,
    seen: Instant,
    job: Option<Job>,
    remote: bool,
    identity: Option<InstanceIdentity>,
    history: Vec<Job>,
}
#[cfg_attr(not(all(feature = "desktop", feature = "vault")), allow(dead_code))]
struct Job {
    document: BrowserDocument,
    completed: bool,
    id: String,
    origin: String,
    data: Option<Data>,
    result: Option<Vec<String>>,
    created: Instant,
    vault: super::SharedVault,
    epoch: [u8; 32],
    item: u64,
}
static TARGETS: LazyLock<Mutex<BTreeMap<String, Target>>> =
    LazyLock::new(|| Mutex::new(BTreeMap::new()));

pub(super) struct Fill {
    item: u64,
    requested: Page,
    target: String,
    document: BrowserDocument,
    fields: Vec<String>,
    identity: Option<InstanceIdentity>,
    pub agent_can_read_page: bool,
}

/// Only device-local instance trust authorizes an unsafe browser, never owner grants.
pub fn agent_fill_allowed_in(
    remote: bool,
    identity: Option<&InstanceIdentity>,
) -> Result<(), &'static str> {
    if remote && !identity.is_some_and(crate::browser::bypass::authorize_agent_fill) {
        Err(REMOTE)
    } else {
        Ok(())
    }
}

/// Untrusted metadata can only veto a fill, never authorize delivery.
#[cfg(feature = "desktop")]
pub(crate) fn blocked(instance: &str, url: &str) {
    let mut targets = lock(&TARGETS);
    if targets.len() < 16 || targets.contains_key(instance) {
        targets.insert(
            instance.into(),
            Target {
                url: url.into(),
                document: None,
                focused: true,
                seen: Instant::now(),
                job: None,
                remote: true,
                identity: None,
                history: Vec::new(),
            },
        );
    }
}

impl Fill {
    pub(super) fn site_label(&self) -> String {
        self.requested.host()
    }
    pub(super) fn validate_site(&self, vault: &Vault) -> Result<(), String> {
        let targets = lock(&TARGETS);
        let target = targets
            .get(&self.target)
            .filter(|t| t.seen.elapsed() < FRESH)
            .ok_or(CHANGED)?;
        if target.document.as_ref() != Some(&self.document)
            || target.identity != self.identity
            || target.remote != self.agent_can_read_page
        {
            return Err(CHANGED.into());
        }
        agent_fill_allowed_in(target.remote, target.identity.as_ref()).map_err(str::to_owned)?;
        let actual = Page::parse(&target.url).map_err(|_| CHANGED)?;
        if actual.origin() != self.requested.origin() {
            return Err(CHANGED.into());
        }
        let details = vault
            .details(self.item)
            .map_err(|_| "Credential unavailable")?;
        if details.summary.kind != CredentialKind::Login {
            return Err("Choose a login credential".into());
        }
        let websites = details
            .fields
            .iter()
            .filter(|f| {
                !f.secret && is_website_field(&f.name, custom_detail_label(&f.name).as_deref())
            })
            .filter_map(|f| vault.reveal(self.item, &f.name).ok())
            .filter_map(|v| Website::parse(v.expose()))
            .collect::<Vec<_>>();
        site_binding(&websites, &self.requested, &actual).map_err(str::to_owned)
    }

    pub(super) fn deliver(&self, vault: &Vault, shared: &super::SharedVault) -> WireResponse {
        // Approval may bring Apassy forward. Wait for the bound document only;
        // a poll of another tab/document permanently fails this request.
        let start = Instant::now();
        loop {
            let targets = lock(&TARGETS);
            let Some(target) = targets.get(&self.target) else {
                return refused(CHANGED);
            };
            if target.document.as_ref() != Some(&self.document) {
                return refused(CHANGED);
            }
            if let Err(reason) = agent_fill_allowed_in(target.remote, target.identity.as_ref()) {
                return refused(reason);
            }
            if target.focused && target.seen >= start && target.seen.elapsed() < FRESH {
                break;
            }
            drop(targets);
            if start.elapsed() >= Duration::from_secs(60) {
                return refused(CHANGED);
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        if let Err(reason) = self.validate_site(vault) {
            return refused(&reason);
        }
        if let Err(reason) = agent_fill_allowed_in(self.agent_can_read_page, self.identity.as_ref())
        {
            return refused(reason);
        }
        let read = |field: &str| -> Result<SecretText, String> {
            if !self.fields.iter().any(|f| f == field) {
                return Ok(SecretText::new(String::new()));
            }
            if field == "code" {
                let name = vault
                    .code_field(self.item)
                    .map_err(|_| "Code unavailable")?
                    .ok_or("Code unavailable")?;
                let code = vault
                    .totp(self.item, &name)
                    .map_err(|_| "Code unavailable")?
                    .code_now()
                    .0;
                return Ok(SecretText::new(code));
            }
            vault
                .reveal(self.item, field)
                .map(|v| SecretText::new(v.expose().to_owned()))
                .map_err(|_| "Login field unavailable".into())
        };
        let (username, password, code) = match (read("username"), read("password"), read("code")) {
            (Ok(u), Ok(p), Ok(c)) => (u, p, c),
            _ => return refused("Login field unavailable"),
        };
        if !super::operations::start_effect() {
            return refused("Operation cancelled");
        }
        let mut targets = lock(&TARGETS);
        let Some(target) = targets.get_mut(&self.target).filter(|t| {
            t.document.as_ref() == Some(&self.document)
                && t.identity == self.identity
                && t.remote == self.agent_can_read_page
                && agent_fill_allowed_in(t.remote, t.identity.as_ref()).is_ok()
                && t.focused
                && t.seen.elapsed() < FRESH
                && t.job.as_ref().is_none_or(|j| j.completed)
        }) else {
            return refused(OPEN);
        };
        let mut random = [0u8; 16];
        if getrandom::fill(&mut random).is_err() {
            return refused("Could not create browser delivery ticket");
        }
        let id = random
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>();
        let origin = self.requested.origin();
        if let Some(old) = target.job.take() {
            target.history.push(old);
        }
        target.job = Some(Job {
            document: self.document.clone(),
            completed: false,
            id: id.clone(),
            origin: origin.clone(),
            data: Some(Data::AgentFill {
                receipt: id,
                origin,
                document: self.document.clone(),
                username,
                password,
                code,
            }),
            result: None,
            created: Instant::now(),
            vault: shared.clone(),
            epoch: vault.epoch(),
            item: self.item,
        });
        WireResponse::success(json!({"status":"waiting"}))
    }
}

fn refused(reason: &str) -> WireResponse {
    WireResponse::success(json!({"status":"refused", "reason":reason}))
}

fn site_binding(websites: &[Website], requested: &Page, actual: &Page) -> Result<(), &'static str> {
    if websites.is_empty() {
        return Err("Save the website on the credential first");
    }
    if !websites
        .iter()
        .any(|w| w.matches(requested) && w.matches(actual))
    {
        return Err("The page does not match the credential's saved website");
    }
    Ok(())
}

fn select_target(targets: &BTreeMap<String, Target>, origin: &str) -> Result<String, &'static str> {
    let matches = targets
        .iter()
        .filter(|(_, t)| {
            t.focused
                && (t.document.is_some() || t.remote)
                && t.seen.elapsed() < FRESH
                && Page::parse(&t.url).is_ok_and(|p| p.origin() == origin)
        })
        .map(|(id, _)| id.clone())
        .collect::<Vec<_>>();
    match matches.as_slice() {
        [id] => Ok(id.clone()),
        _ => Err(OPEN),
    }
}

#[allow(clippy::too_many_arguments)]
pub(super) fn run(
    ctx: &BrokerContext,
    token: &str,
    item: u64,
    url: &str,
    fields: &[String],
    user_request: &str,
    purpose: &str,
    cwd: &str,
    host_session: Option<&str>,
) -> WireResponse {
    let agent = {
        let mut guard = lock(&ctx.vault);
        let Some(vault) = guard.as_mut().filter(|v| !v.is_locked()) else {
            return super::decide::locked_response();
        };
        match super::decide::authenticate(vault, token, "agent browser fill") {
            Ok(a) => a,
            Err(e) => return e,
        }
    };
    let result = run_inner(
        ctx,
        token,
        item,
        url,
        fields,
        user_request,
        purpose,
        cwd,
        host_session,
    );
    let mut guard = lock(&ctx.vault);
    if let Some(vault) = guard.as_mut().filter(|v| !v.is_locked()) {
        let status = result
            .result
            .as_ref()
            .and_then(|r| r["status"].as_str())
            .unwrap_or("refused");
        let _ = vault.record_activity(&crate::vault::NewActivity {
            agent_id: Some(agent.id),
            agent_name: agent.name,
            item_id: None,
            operation: "agent browser fill".into(),
            decision: if status == "filled" {
                crate::vault::ActivityDecision::Allow
            } else {
                crate::vault::ActivityDecision::Deny
            },
            reason: format!("Browser fill {status}. No credential values returned to the agent."),
        });
    }
    result
}

#[allow(clippy::too_many_arguments)]
fn run_inner(
    ctx: &BrokerContext,
    token: &str,
    item: u64,
    url: &str,
    fields: &[String],
    user_request: &str,
    purpose: &str,
    cwd: &str,
    host_session: Option<&str>,
) -> WireResponse {
    if fields.is_empty()
        || fields.len() > 3
        || fields
            .iter()
            .any(|f| !["username", "password", "code"].contains(&f.as_str()))
        || fields
            .iter()
            .collect::<std::collections::BTreeSet<_>>()
            .len()
            != fields.len()
        || purpose.trim().is_empty()
        || user_request.trim().is_empty()
    {
        return refused("Invalid browser fill arguments");
    }
    let requested = match Page::parse(url) {
        Ok(p) => p,
        Err(e) => return refused(e.message()),
    };
    let target = match select_target(&lock(&TARGETS), &requested.origin()) {
        Ok(t) => t,
        Err(e) => return refused(e),
    };
    let targets = lock(&TARGETS);
    let Some(selected) = targets.get(&target) else {
        return refused(CHANGED);
    };
    let agent_can_read_page = selected.remote;
    let identity = selected.identity.clone();
    if let Err(reason) = agent_fill_allowed_in(agent_can_read_page, identity.as_ref()) {
        return refused(reason);
    }
    let Some(document) = selected.document.clone() else {
        return refused(CHANGED);
    };
    drop(targets);
    let fill = Fill {
        item,
        requested,
        target,
        document,
        fields: fields.to_vec(),
        agent_can_read_page,
        identity,
    };
    let items = if fields.iter().any(|f| f != "code") {
        vec![item]
    } else {
        vec![]
    };
    let codes = if fields.iter().any(|f| f == "code") {
        vec![item]
    } else {
        vec![]
    };
    let command = vec![
        "apassy-browser-fill".into(),
        fill.requested.origin(),
        fields.join(","),
    ];
    let result = super::run::fill_browser(
        ctx,
        token,
        &super::run::RunRequest {
            access_request_id: None,
            items: &items,
            codes: &codes,
            command: &command,
            cwd,
            purpose,
            path: None,
            user_request: Some(user_request),
            host_session,
        },
        &fill,
    );
    if !result.ok || result.result.as_ref().and_then(|r| r["status"].as_str()) != Some("waiting") {
        return result;
    }
    let start = Instant::now();
    loop {
        if start.elapsed() > Duration::from_secs(15) {
            if let Some(target) = lock(&TARGETS).get_mut(&fill.target) {
                target.job = None;
            }
            return refused(
                "Browser fill acknowledgement timed out; inspect the page before retrying",
            );
        }
        {
            let mut targets = lock(&TARGETS);
            let Some(target) = targets.get_mut(&fill.target) else {
                return refused(OPEN);
            };
            if target.document.as_ref() != Some(&fill.document) {
                target.job = None;
                return refused(CHANGED);
            }
            if let Some(job) = &mut target.job {
                if let Some(fields) = job.result.take() {
                    job.completed = true;
                    return WireResponse::success(
                        json!({"status":if fields.is_empty() {"refused"} else {"filled"}, "fields":fields, "reason":if fields.is_empty() {"The page changed or has no matching fields"} else {""}}),
                    );
                }
            } else {
                return refused("Browser delivery was cancelled; inspect the page before retrying");
            }
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// Called only after the native host and socket peer caller guards pass.
#[cfg(any(feature = "desktop", test))]
#[allow(clippy::too_many_arguments)]
pub(crate) fn poll(
    instance: &str,
    identity: Option<InstanceIdentity>,
    url: &str,
    document: Option<BrowserDocument>,
    focused: bool,
    receipt: Option<&str>,
    filled: Vec<String>,
    exposed: bool,
) -> Response {
    let mut targets = lock(&TARGETS);
    targets.retain(|_, t| t.seen.elapsed() < Duration::from_secs(150));
    if targets.len() >= 16 && !targets.contains_key(instance) {
        return Response::error("busy", OPEN);
    }
    let target = targets.entry(instance.into()).or_insert_with(|| Target {
        url: url.into(),
        document: document.clone(),
        focused,
        seen: Instant::now(),
        job: None,
        remote: identity.is_some(),
        identity: identity.clone(),
        history: Vec::new(),
    });
    // Identity is supplied by the socket guard, never by the extension packet.
    // A changed security context invalidates any already approved delivery.
    if target.identity != identity || target.remote != identity.is_some() {
        target.job = None;
    }
    target.remote = identity.is_some();
    target.identity = identity;
    // Losing browser focus must not discard the owner's selected document.
    if !url.is_empty() {
        target.url = url.into();
        target.document = document.clone();
    }
    target.focused = focused && document.is_some();
    target.seen = Instant::now();
    if let Err(reason) = agent_fill_allowed_in(target.remote, target.identity.as_ref()) {
        target.job = None;
        return Response::error("unsafe_browser", reason);
    }
    let old_report = receipt.and_then(|id| target.history.iter_mut().find(|j| j.id == id));
    let active = old_report.is_none();
    if let Some(job) = old_report.or(target.job.as_mut()) {
        if receipt == Some(job.id.as_str()) {
            if !job.completed {
                job.result = Some(filled);
            }
            let Ok(mut guard) = job.vault.try_lock() else {
                return Response::ok("Waiting", Data::None);
            };
            if let Some(vault) = guard
                .as_mut()
                .filter(|v| !v.is_locked() && v.epoch() == job.epoch)
            {
                if !exposed && job.result.as_ref().is_some_and(|f| !f.is_empty()) {
                    let _ = vault.record_fill(job.item, &job.origin);
                }
                let _ = vault.record_activity(&crate::vault::NewActivity {
                    agent_id: None,
                    agent_name: "Browser extension".into(),
                    item_id: Some(job.item),
                    operation: "agent browser fill".into(),
                    decision: if exposed {
                        crate::vault::ActivityDecision::Deny
                    } else {
                        crate::vault::ActivityDecision::Allow
                    },
                    reason: if exposed {
                        "The filled password field became visible. Apassy cleared it."
                    } else {
                        "The extension acknowledged the browser fill."
                    }
                    .into(),
                });
            }
        }
        if job.created.elapsed() > Duration::from_secs(140) {
            job.data = None;
        } else if active
            && focused
            && document.as_ref() == Some(&job.document)
            && Page::parse(url).is_ok_and(|p| p.origin() == job.origin)
            && job.created.elapsed() < Duration::from_secs(10)
        {
            // Do not retain delivery across a lock or vault replacement.
            let Ok(guard) = job.vault.try_lock() else {
                return Response::ok("Waiting", Data::None);
            };
            if guard
                .as_ref()
                .is_some_and(|v| !v.is_locked() && v.epoch() == job.epoch)
            {
                if let Some(data) = job.data.take() {
                    return Response::ok("Fill this tab", data);
                }
            } else {
                job.data = None;
            }
        }
    }
    Response::ok("Waiting for an agent fill", Data::None)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn extension_cannot_supply_guard_identity_or_remote_flag() {
        let packet = json!({
            "v": 1, "cmd": "agent_poll",
            "instance": "0123456789abcdef0123456789abcdef",
            "url": "https://example.com", "document": null
        });
        assert!(
            crate::browser::wire::Request::parse(&serde_json::to_vec(&packet).unwrap()).is_ok()
        );
        for field in ["identity", "remote", "agent_can_read_page"] {
            let mut forged = packet.clone();
            forged[field] = json!(false);
            assert!(
                crate::browser::wire::Request::parse(&serde_json::to_vec(&forged).unwrap())
                    .is_err()
            );
        }
    }
    #[test]
    fn owner_bypass_does_not_authorize_agent_poll_or_clear_remote_identity() {
        use crate::browser::bypass::{BypassScope, OwnerPasskeyCodeBypass, consume};
        // Invalid identity fails trust before any native-helper access. No owner
        // vault, keychain, or installed browser is needed by this regression.
        let identity = InstanceIdentity {
            bundle_id: String::new(),
            team_id: String::new(),
            user_data_root: String::new(),
            debugging: "9223".into(),
            unsafe_switches: vec!["remote-debugging-port".into()],
        };
        let now = Instant::now();
        let mut grant = Some(OwnerPasskeyCodeBypass::approved(
            identity.clone(),
            BypassScope::FiveMinutes,
            now,
        ));
        assert!(grant.as_ref().unwrap().remaining(&identity, now).is_some());
        let command = crate::browser::wire::Command::AgentPoll {
            instance: "remote-bypass-regression".into(),
            url: "https://example.com/login".into(),
            document: None,
            focused: false,
            receipt: None,
            filled: vec![],
            exposed: false,
        };
        assert!(!consume(&mut grant, &identity, now, &command, None));
        assert_eq!(agent_fill_allowed_in(true, Some(&identity)), Err(REMOTE));
        for _ in 0..2 {
            let response = poll(
                "remote-bypass-regression",
                Some(identity.clone()),
                "https://example.com/login",
                None,
                false,
                None,
                vec![],
                false,
            );
            assert!(!response.ok);
            assert_eq!(response.message, REMOTE);
            let targets = lock(&TARGETS);
            let target = targets.get("remote-bypass-regression").unwrap();
            assert!(target.remote);
            assert_eq!(target.identity.as_ref(), Some(&identity));
            assert!(target.job.is_none());
        }
        assert!(grant.is_some());
        lock(&TARGETS).remove("remote-bypass-regression");
    }
    #[test]
    fn unfocused_poll_preserves_binding_and_navigation_replaces_it() {
        let instance = "binding-test";
        let document = BrowserDocument {
            window_id: 1,
            tab_id: 2,
            frame_id: 0,
            document_id: "first-document".into(),
            generation: "first-activation".into(),
        };
        poll(
            instance,
            None,
            "https://example.com/login",
            Some(document.clone()),
            true,
            None,
            vec![],
            false,
        );
        poll(instance, None, "", None, false, None, vec![], false);
        {
            let targets = lock(&TARGETS);
            let target = targets.get(instance).unwrap();
            assert_eq!(target.document.as_ref(), Some(&document));
            assert_eq!(target.url, "https://example.com/login");
            assert!(!target.focused);
        }
        let mut next = document.clone();
        next.document_id = "second-document".into();
        poll(
            instance,
            None,
            "https://example.com/login",
            Some(next.clone()),
            true,
            None,
            vec![],
            false,
        );
        let mut targets = lock(&TARGETS);
        assert_eq!(
            targets.get(instance).unwrap().document.as_ref(),
            Some(&next)
        );
        assert_ne!(next, document);
        targets.remove(instance);
    }
    #[test]
    fn binding_and_debugging() {
        let page = Page::parse("https://example.com/login").unwrap();
        let evil = Page::parse("https://example.com.evil.com").unwrap();
        let sites = vec![Website::parse("example.com").unwrap()];
        assert!(site_binding(&sites, &page, &page).is_ok());
        assert!(site_binding(&sites, &evil, &page).is_err());
        assert!(site_binding(&sites, &page, &evil).is_err());
        assert_eq!(
            site_binding(&[], &page, &page),
            Err("Save the website on the credential first")
        );
        assert_eq!(agent_fill_allowed_in(true, None), Err(REMOTE));
        assert!(agent_fill_allowed_in(false, None).is_ok());
    }
    #[test]
    fn none_one_several_targets() {
        let mut targets = BTreeMap::new();
        assert!(select_target(&targets, "https://example.com").is_err());
        for id in ["a", "b"] {
            targets.insert(
                id.into(),
                Target {
                    url: "https://example.com/login".into(),
                    document: Some(BrowserDocument {
                        window_id: 1,
                        tab_id: 1,
                        frame_id: 0,
                        document_id: "doc".into(),
                        generation: "generation".into(),
                    }),
                    focused: true,
                    seen: Instant::now(),
                    job: None,
                    remote: false,
                    identity: None,
                    history: Vec::new(),
                },
            );
            assert_eq!(
                select_target(&targets, "https://example.com").is_ok(),
                id == "a"
            );
        }
    }
}
