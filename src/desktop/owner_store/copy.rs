//! Explicit, freshly authenticated desktop clipboard disclosure. No socket or agent
//! API calls this adapter, and no secret value enters the request or proof.

use zeroize::Zeroizing;

use super::{OwnerSession, fail, map_err};
use crate::broker::approvals::{OwnerAction, OwnerProof};
use crate::desktop::model::ModelResult;
use crate::vault::{Vault, is_passkey_field, is_setup_key_field};

/// Validate the approved snapshot again while holding the same vault lock as the read.
fn copyable(vault: &Vault, id: u64, field: &str, revision: u64) -> ModelResult<bool> {
    // Reserved passkey material never becomes an ordinary field, even if corrupt
    // metadata marks it as a visible or ordinary secret field.
    if is_passkey_field(field) {
        return Ok(false);
    }
    let meta = vault.details(id).map_err(|_| stale())?;
    if meta.summary.revision != revision {
        return Err(stale());
    }
    let Some(summary) = meta.fields.iter().find(|candidate| candidate.name == field) else {
        return Err(stale());
    };
    if !summary.secret {
        return Ok(false);
    }
    // The canonical predicate applies to every candidate, including ordinary token
    // and password fields. A value read failure cannot make a setup key copyable.
    let value = vault.reveal(id, field).map_err(map_err)?;
    Ok(!is_setup_key_field(field, value.expose()))
}

fn stale() -> crate::desktop::model::ModelError {
    fail(
        "stale_item",
        "The item changed or is gone. Review it and copy again. Nothing was copied.",
    )
}

impl OwnerSession {
    /// Whether an exact displayed field can offer Copy. No value reaches the view.
    /// TOTP setup keys retain their existing Copy Code action.
    pub fn can_copy_field(&self, id: u64, field: &str, revision: u64) -> bool {
        self.unlocked()
            .and_then(|vault| copyable(&vault, id, field, revision))
            .unwrap_or(false)
    }

    /// Release one ordinary secret to the trusted desktop clipboard adapter. A reveal,
    /// code, fill, another field, or another revision proof cannot authorize this read.
    /// The proof is consumed on every outcome; no revealed-state cache is populated.
    pub fn copy_field(
        &mut self,
        id: u64,
        field: &str,
        revision: u64,
        proof: OwnerProof,
    ) -> ModelResult<Zeroizing<String>> {
        let action = OwnerAction::CopyField {
            item_id: id,
            field: field.to_owned(),
            revision,
        };
        let mut vault = self.unlocked_for(proof, &action)?;
        if !copyable(&vault, id, field, revision)? {
            return Err(fail(
                "unsupported_field",
                "This field cannot be copied. Nothing was copied.",
            ));
        }
        let value = vault
            .reveal(id, field)
            .map_err(|_| stale())?
            .into_zeroizing();
        vault.record_reveal(id).map_err(map_err)?;
        Ok(value)
    }
}
