//! Code metadata and parsing shared by owner CLI and agent execution (ADR 0034).
use super::types::err;
use super::{Vault, VaultErrorKind, VaultResult};

pub fn code_env_name(item: u64) -> String {
    format!("APASSY_ITEM_{item}_OTP")
}

impl Vault {
    /// Exactly one OTP detail, including legacy labels and explicit TOTP URIs.
    /// Multiple settings are ambiguous and fail closed.
    pub fn code_field(&self, item: u64) -> VaultResult<Option<String>> {
        let details = self.details(item)?;
        let mut found = None;
        for field in details.fields {
            if super::types::is_passkey_field(&field.name) {
                continue;
            }
            let value = self.reveal(item, &field.name)?;
            if super::access::is_setup_key_field(&field.name, value.expose()) {
                if found.is_some() {
                    return Err(err(VaultErrorKind::InvalidInput));
                }
                found = Some(field.name);
            }
        }
        Ok(found)
    }

    pub(crate) fn totp(&self, item: u64, field: &str) -> VaultResult<crate::otp::Totp> {
        if self.code_field(item)?.as_deref() != Some(field) {
            return Err(err(VaultErrorKind::InvalidInput));
        }
        let seed = self.reveal(item, field)?;
        crate::otp::Totp::parse(seed.expose()).map_err(|_| err(VaultErrorKind::InvalidInput))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::contracts::CredentialKind;
    use crate::vault::{Field, ItemDraft, SecretValue};
    const SEED: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
    fn draft(fields: Vec<Field>) -> ItemDraft {
        ItemDraft {
            title: "Synthetic OTP".into(),
            kind: CredentialKind::Custom,
            notes: String::new(),
            tags: vec![],
            fields,
        }
    }
    fn field(label: &str, value: &str) -> Field {
        Field {
            name: format!(
                "x_{}",
                label
                    .bytes()
                    .map(|b| format!("{b:02x}"))
                    .collect::<String>()
            ),
            value: SecretValue::new(value.into()),
            secret: true,
        }
    }
    #[test]
    fn discovery_handles_missing_legacy_ambiguous_and_invalid_settings_without_seeds() {
        let dir = tempfile::tempdir().unwrap();
        let pass = "synthetic-mfa-test";
        let mut v = Vault::create(&dir.path().join("mfa.db"), pass).unwrap();
        v.unlock(pass).unwrap();
        let missing = v
            .add(draft(vec![field("Recovery", "unrelated-secret")]))
            .unwrap()
            .id;
        assert!(v.code_field(missing).unwrap().is_none());
        let legacy = v.add(draft(vec![field("One-time code", SEED)])).unwrap().id;
        let setting = v.code_field(legacy).unwrap().unwrap();
        assert_eq!(v.totp(legacy, &setting).unwrap().code_at(59).0, "287082");
        v.set_env_binding(legacy, "LEGACY_SEED", &setting).unwrap();
        assert!(
            v.process_binding(legacy).unwrap().is_none(),
            "even explicit old seed bindings cannot reach agents"
        );
        let ambiguous = v
            .add(draft(vec![field("OTP", SEED), field("TOTP", SEED)]))
            .unwrap()
            .id;
        assert_eq!(
            v.code_field(ambiguous).unwrap_err().kind(),
            VaultErrorKind::InvalidInput
        );
        let bad = v
            .add(draft(vec![field("OTP", "not-a-valid-seed")]))
            .unwrap()
            .id;
        let setting = v.code_field(bad).unwrap().unwrap();
        assert!(v.totp(bad, &setting).is_err());
        assert_eq!(code_env_name(legacy), format!("APASSY_ITEM_{legacy}_OTP"));
    }
}
