//! Connector profiles. A profile names the operations that an agent can request.
//!
//! `reporting-api-v0` follows candidate A in `docs/contracts/p0-candidates.md`.
//! It is synthetic. No real provider is verified.

use std::collections::BTreeMap;

use serde_json::{Value, json};

use crate::contracts::CredentialKind;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParamKind {
    /// 1 to 64 bytes of lowercase ASCII letters, digits, `-`, or `_`.
    Slug,
    /// A calendar date in `YYYY-MM-DD` form.
    Date,
}

impl ParamKind {
    fn format(self) -> &'static str {
        match self {
            Self::Slug => "1 to 64 characters: a-z, 0-9, - or _",
            Self::Date => "YYYY-MM-DD",
        }
    }
}

#[derive(Debug)]
pub struct ParamSpec {
    pub name: &'static str,
    pub kind: ParamKind,
    pub description: &'static str,
}

#[derive(Debug)]
pub struct OperationSpec {
    pub name: &'static str,
    pub description: &'static str,
    pub params: &'static [ParamSpec],
    /// Permitted output fields. The broker drops every other field.
    pub output_fields: &'static [&'static str],
    path: fn(&BTreeMap<String, String>) -> String,
    check: fn(&BTreeMap<String, String>) -> Result<(), String>,
}

impl OperationSpec {
    /// Check the parameter set and each value. The message names the parameter, not its value.
    pub fn validate(&self, params: &BTreeMap<String, String>) -> Result<(), String> {
        for name in params.keys() {
            if !self.params.iter().any(|spec| spec.name == name) {
                return Err(format!("The parameter \"{name}\" is not permitted."));
            }
        }
        for spec in self.params {
            let value = params
                .get(spec.name)
                .ok_or_else(|| format!("The parameter \"{}\" is required.", spec.name))?;
            let valid = match spec.kind {
                ParamKind::Slug => is_slug(value),
                ParamKind::Date => is_date(value),
            };
            if !valid {
                return Err(format!(
                    "The parameter \"{}\" must have this format: {}.",
                    spec.name,
                    spec.kind.format()
                ));
            }
        }
        (self.check)(params)
    }

    /// Request path and query. Call only after `validate`. Valid values need no escape.
    pub fn path(&self, params: &BTreeMap<String, String>) -> String {
        (self.path)(params)
    }

    pub fn describe(&self) -> Value {
        let params: Vec<Value> = self
            .params
            .iter()
            .map(|spec| {
                json!({
                    "name": spec.name,
                    "format": spec.kind.format(),
                    "description": spec.description,
                })
            })
            .collect();
        json!({
            "name": self.name,
            "description": self.description,
            "params": params,
            "output_fields": self.output_fields,
        })
    }
}

#[derive(Debug)]
pub struct Profile {
    pub id: &'static str,
    pub label: &'static str,
    pub credential_kind: CredentialKind,
    /// The item field that holds the secret.
    pub secret_field: &'static str,
    pub operations: &'static [OperationSpec],
}

impl Profile {
    pub fn operation(&self, name: &str) -> Option<&'static OperationSpec> {
        self.operations.iter().find(|op| op.name == name)
    }
}

pub const REPORTING_API_V0: Profile = Profile {
    id: "reporting-api-v0",
    label: "Synthetic reporting API (candidate A)",
    credential_kind: CredentialKind::ApiKey,
    secret_field: "token",
    operations: &[
        OperationSpec {
            name: "get_sales_summary",
            description: "Read one sales summary for one project and one date range.",
            params: &[
                ParamSpec {
                    name: "project_id",
                    kind: ParamKind::Slug,
                    description: "Project ID.",
                },
                ParamSpec {
                    name: "period_start",
                    kind: ParamKind::Date,
                    description: "First day of the range.",
                },
                ParamSpec {
                    name: "period_end",
                    kind: ParamKind::Date,
                    description: "Last day of the range. It cannot be before period_start.",
                },
            ],
            output_fields: &[
                "project_id",
                "period_start",
                "period_end",
                "currency",
                "total_amount",
                "order_count",
            ],
            path: sales_summary_path,
            check: check_period,
        },
        OperationSpec {
            name: "get_report_job_status",
            description: "Read the state of one report job.",
            params: &[ParamSpec {
                name: "job_id",
                kind: ParamKind::Slug,
                description: "Report job ID.",
            }],
            output_fields: &["job_id", "state", "completed_at"],
            path: job_status_path,
            check: no_extra_check,
        },
    ],
};

pub const PROFILES: &[Profile] = &[REPORTING_API_V0];

pub fn find(id: &str) -> Option<&'static Profile> {
    PROFILES.iter().find(|profile| profile.id == id)
}

fn sales_summary_path(params: &BTreeMap<String, String>) -> String {
    format!(
        "/v1/projects/{}/sales-summary?period_start={}&period_end={}",
        param(params, "project_id"),
        param(params, "period_start"),
        param(params, "period_end"),
    )
}

fn job_status_path(params: &BTreeMap<String, String>) -> String {
    format!("/v1/report-jobs/{}", param(params, "job_id"))
}

fn param<'a>(params: &'a BTreeMap<String, String>, name: &str) -> &'a str {
    params.get(name).map_or("", String::as_str)
}

fn check_period(params: &BTreeMap<String, String>) -> Result<(), String> {
    // Valid ISO dates compare correctly as text.
    if param(params, "period_start") > param(params, "period_end") {
        Err("The period_end parameter cannot be before period_start.".to_owned())
    } else {
        Ok(())
    }
}

fn no_extra_check(_params: &BTreeMap<String, String>) -> Result<(), String> {
    Ok(())
}

fn is_slug(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_')
}

fn is_date(value: &str) -> bool {
    let bytes = value.as_bytes();
    if bytes.len() != 10 || bytes[4] != b'-' || bytes[7] != b'-' {
        return false;
    }
    let digits = |range: std::ops::Range<usize>| -> Option<u32> {
        let text = value.get(range)?;
        if text.bytes().all(|b| b.is_ascii_digit()) {
            text.parse().ok()
        } else {
            None
        }
    };
    let (Some(year), Some(month), Some(day)) = (digits(0..4), digits(5..7), digits(8..10)) else {
        return false;
    };
    let leap = (year % 4 == 0 && year % 100 != 0) || year % 400 == 0;
    let max_day = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap => 29,
        2 => 28,
        _ => return false,
    };
    (1900..=2999).contains(&year) && (1..=max_day).contains(&day)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn params(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect()
    }

    #[test]
    fn sales_summary_validation() {
        let op = REPORTING_API_V0
            .operation("get_sales_summary")
            .expect("operation");
        let good = params(&[
            ("project_id", "project-a-synthetic"),
            ("period_start", "2026-09-01"),
            ("period_end", "2026-09-30"),
        ]);
        assert!(op.validate(&good).is_ok());
        assert_eq!(
            op.path(&good),
            "/v1/projects/project-a-synthetic/sales-summary?period_start=2026-09-01&period_end=2026-09-30"
        );
        let mut reversed = good.clone();
        reversed.insert("period_start".into(), "2026-10-01".into());
        assert!(op.validate(&reversed).is_err());
        let mut injected = good.clone();
        injected.insert("project_id".into(), "../admin?x=1".into());
        assert!(op.validate(&injected).is_err());
        let mut extra = good.clone();
        extra.insert("url".into(), "http://evil.invalid".into());
        assert!(op.validate(&extra).is_err());
        let mut bad_date = good;
        bad_date.insert("period_end".into(), "2026-02-30".into());
        assert!(op.validate(&bad_date).is_err());
    }

    #[test]
    fn dates() {
        assert!(is_date("2024-02-29"));
        assert!(!is_date("2023-02-29"));
        assert!(!is_date("2026-13-01"));
        assert!(!is_date("2026-1-01"));
        assert!(!is_date("２０２６-01-01"));
    }
}
