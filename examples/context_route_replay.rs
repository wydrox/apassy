//! Isolated sdc-baseline-replay-v1. One bounded JSON request and one JSON reply.
//! prepare: {op:"prepare",views:[view,...]}; decide additionally supplies bodies.
//! Inputs must already be sanitized synthetic views. Never reads a vault/profile.
use apassy::broker::{
    bouncer::{self, BouncerRequest, DecisionContext, Learned, Thresholds},
    shell_risk,
};
use apassy::vault::{Declaration, Environment, Reversibility, RiskLevel, Scope};
use serde::Deserialize;
use serde_json::{Value, json};
use std::io::{Read, Write};

const LIMIT: u64 = 8 * 1024 * 1024;
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    user_request: String,
    command: String,
    purpose: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct View {
    request: Request,
    action: String,
    secrets: Vec<Value>,
    local_rule: Option<String>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Input {
    op: String,
    views: Vec<View>,
    #[serde(default)]
    bodies: Vec<Value>,
}

fn declarations(v: &View) -> Result<Vec<Option<Declaration>>, &'static str> {
    let c: Value = serde_json::from_str(include_str!(
        "../tools/basemodel/contracts/secret-decision-context-v1.json"
    ))
    .map_err(|_| "contract")?;
    if !(1..=3).contains(&v.secrets.len())
        || !["read", "change", "deploy", "delete"].contains(&v.action.as_str())
    {
        return Err("row_incoherent");
    }
    let mut out = Vec::new();
    for s in &v.secrets {
        let obj = s.as_object().ok_or("row_incoherent")?;
        let fields = c["secret_facts"].as_array().ok_or("contract")?;
        if obj.len() != fields.len() {
            return Err("row_incoherent");
        }
        for f in fields {
            let key = f[0].as_str().ok_or("contract")?;
            let val = obj
                .get(key)
                .and_then(Value::as_str)
                .ok_or("row_incoherent")?;
            let valid = f[1]
                .as_array()
                .ok_or("contract")?
                .iter()
                .any(|x| x.as_str() == Some(val))
                || (key == "provider"
                    && c["providers"]
                        .as_array()
                        .ok_or("contract")?
                        .iter()
                        .any(|x| x.as_str() == Some(val)));
            if !valid || val == "<listed>" {
                return Err("row_incoherent");
            }
        }
        let absent = s["env_from"] == "none";
        if absent {
            if s["env"] != "unknown"
                || s["scope"] != "unknown"
                || s["scope_from"] != "none"
                || s["sensitive"] != "unknown"
                || s["project"] != "undeclared"
            {
                return Err("row_incoherent");
            }
            out.push(None);
        } else {
            if s["scope_from"] == "none"
                || s["env"] == "unknown"
                || s["scope"] == "unknown"
                || s["sensitive"] == "unknown"
                || (s["env"] == "production" && s["sensitive"] != "yes")
            {
                return Err("row_incoherent");
            }
            out.push(Some(Declaration {
                project: String::new(),
                environment: Environment::parse(s["env"].as_str().ok_or("row_incoherent")?)
                    .map_err(|_| "row_incoherent")?,
                scope: Scope::parse(
                    &s["scope"]
                        .as_str()
                        .ok_or("row_incoherent")?
                        .replace('_', "-"),
                )
                .map_err(|_| "row_incoherent")?,
                risk: if s["sensitive"] == "yes" && s["env"] != "production" {
                    RiskLevel::High
                } else {
                    RiskLevel::Low
                },
                reversibility: Reversibility::Reversible,
            }));
        }
    }
    Ok(out)
}
// A1: bound names are not present in the view. Recognize $NAME/${NAME}, else
// SECRET_1..n. No expansion, process execution, environment or owner file reads.
fn env_names(command: &str, n: usize) -> Vec<String> {
    let bytes = command.as_bytes();
    let mut out = Vec::new();
    for i in 0..bytes.len() {
        if bytes[i] != b'$' {
            continue;
        }
        let start = i + 1 + usize::from(bytes.get(i + 1) == Some(&b'{'));
        let mut end = start;
        while bytes
            .get(end)
            .is_some_and(|b| b.is_ascii_alphanumeric() || *b == b'_')
        {
            end += 1;
        }
        if end > start && (bytes[start].is_ascii_alphabetic() || bytes[start] == b'_') {
            let name = command[start..end].to_owned();
            if !out.contains(&name) {
                out.push(name);
            }
        }
    }
    if out.is_empty() {
        out = (1..=n).map(|i| format!("SECRET_{i}")).collect();
    }
    out
}
fn replay(v: &View, body: Option<&Value>) -> Result<Value, &'static str> {
    let declarations = declarations(v)?;
    let names = env_names(&v.request.command, v.secrets.len());
    let argv = shell_risk::command_line_to_argv(&v.request.command);
    // Actual run.rs:1099 analyze_run(argv, purpose, env_names, provider_hosts).
    // Host strings are absent. For hosts=known reconstruct per-item covering
    // destinations from command_hosts; hosts=unknown is an explicit route ask.
    let hosts = shell_risk::command_hosts(&argv);
    let providers: Vec<_> = names
        .iter()
        .map(|name| shell_risk::ProviderHosts {
            env_name: name.clone(),
            hosts: hosts.clone(),
        })
        .collect();
    let analysis = shell_risk::analyze_run(&argv, &v.request.purpose, &names, &providers);
    let ctx = DecisionContext {
        analysis: &analysis,
        declarations: &declarations,
        has_user_request: !v.request.user_request.trim().is_empty(),
    };
    let pre = bouncer::before_model(&ctx);
    let reason = if pre.is_some() {
        Some("before_model")
    } else if v.local_rule.is_some() {
        Some("local_rule")
    } else if v.secrets.iter().any(|s| s["hosts"] == "unknown") {
        Some("ForeignHost")
    } else if v.secrets.iter().any(|s| s["project"] == "other") {
        Some("ForeignProject")
    } else {
        None
    };
    let request = BouncerRequest {
        user_request: v.request.user_request.clone(),
        command: v.request.command.clone(),
        purpose: v.request.purpose.clone(),
        relative_dir: ".".into(),
        env_names: names,
        instruction: String::new(),
        task_provenance: String::new(),
    };
    let systemone = bouncer::request_body(&request);
    let mut result =
        json!({"pre_ask":reason.is_some(), "pre_reason":reason, "systemone_body":systemone});
    if let Some(body) = body {
        let asked = bouncer::questions();
        let asked: Vec<_> = asked
            .into_iter()
            .filter(|(id, _)| *id != "rule_break")
            .collect();
        let verdict =
            bouncer::parse_answers(&serde_json::to_vec(body).map_err(|_| "bad_answer")?, &asked);
        let weak = v.secrets.iter().any(|s| s["env_from"] == "default");
        let learned = Learned {
            thresholds: if weak {
                Thresholds {
                    task_match: bouncer::MIN_CONFIDENCE,
                }
            } else {
                Thresholds::default()
            },
            pattern: None,
        };
        let decision = bouncer::decide_learned(&verdict, &ctx, &learned);
        // A3: decide_routed's extra default-source check is private; public
        // decide_learned can allow weak known-safe reads. Favors the baseline.
        result["ask"] = json!(reason.is_some() || decision.ask_owner);
    }
    Ok(result)
}
fn execute() -> Result<Value, &'static str> {
    let mut data = Vec::new();
    std::io::stdin()
        .take(LIMIT + 1)
        .read_to_end(&mut data)
        .map_err(|_| "input_io")?;
    if data.len() as u64 > LIMIT {
        return Err("input_too_large");
    }
    let input: Input = serde_json::from_slice(&data).map_err(|_| "invalid_input")?;
    if input.views.len() > 4096
        || !["prepare", "decide"].contains(&input.op.as_str())
        || (input.op == "decide" && input.bodies.len() != input.views.len())
        || (input.op == "prepare" && !input.bodies.is_empty())
    {
        return Err("invalid_input");
    }
    let rows: Result<Vec<_>, _> = input
        .views
        .iter()
        .enumerate()
        .map(|(i, v)| {
            replay(
                v,
                if input.op == "decide" {
                    input.bodies.get(i)
                } else {
                    None
                },
            )
        })
        .collect();
    Ok(json!({"contract":"sdc-baseline-replay-v1", "rows":rows?}))
}
fn main() {
    std::panic::set_hook(Box::new(|_| {}));
    let result = std::panic::catch_unwind(execute).unwrap_or(Err("internal_error"));
    let (out, code) = match result {
        Ok(v) => (v, 0),
        Err(e) => (json!({"status":"UNSUPPORTED","reason":e}), 2),
    };
    if writeln!(std::io::stdout().lock(), "{out}").is_err() {
        std::process::exit(2);
    }
    std::process::exit(code);
}
