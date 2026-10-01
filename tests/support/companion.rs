//! Helpers for the companion tests: a vault with an owner gate, and phone keys made by
//! ring. All values are synthetic.

#![allow(dead_code)]

use std::sync::{Arc, Mutex};

use apassy::broker::SharedVault;
use apassy::broker::approvals::{OwnerAction, OwnerCheck, OwnerGate, PendingRun};
use apassy::vault::{AddDeviceError, CompanionDevice, Vault};
use ring::rand::SystemRandom;
use ring::signature::{ECDSA_P256_SHA256_ASN1_SIGNING, EcdsaKeyPair, KeyPair};
use tempfile::TempDir;

pub const PASS: &str = "companion-test-passphrase";
pub const DEVICE: &str = "0123456789abcdef0123456789abcdef";

/// A device key as the phone would hold one.
pub struct PhoneKey {
    pair: EcdsaKeyPair,
    rng: SystemRandom,
}

impl PhoneKey {
    pub fn generate() -> Self {
        let rng = SystemRandom::new();
        let algorithm = &ECDSA_P256_SHA256_ASN1_SIGNING;
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(algorithm, &rng).expect("generate");
        let pair = EcdsaKeyPair::from_pkcs8(algorithm, pkcs8.as_ref(), &rng).expect("parse");
        Self { pair, rng }
    }

    /// The public key in X9.63 form.
    pub fn public(&self) -> Vec<u8> {
        self.pair.public_key().as_ref().to_vec()
    }

    /// A DER signature over the UTF-8 bytes of `text`.
    pub fn sign(&self, text: &str) -> Vec<u8> {
        self.pair
            .sign(&self.rng, text.as_bytes())
            .expect("sign")
            .as_ref()
            .to_vec()
    }
}

/// An unlocked vault behind the shared handle, and the gate on it.
pub struct Fixture {
    pub dir: TempDir,
    pub shared: SharedVault,
    pub gate: OwnerGate,
}

pub fn fixture() -> Fixture {
    let dir = TempDir::new().expect("temp dir");
    let mut vault = Vault::create(&dir.path().join("companion.db"), PASS).expect("create");
    vault.unlock(PASS).expect("unlock");
    let shared: SharedVault = Arc::new(Mutex::new(Some(vault)));
    let gate = OwnerGate::new(Arc::clone(&shared), None);
    Fixture { dir, shared, gate }
}

impl Fixture {
    /// Run `f` with the vault locked by the mutex.
    pub fn with<T>(&self, f: impl FnOnce(&mut Vault) -> T) -> T {
        let mut guard = self.shared.lock().expect("vault mutex");
        f(guard.as_mut().expect("vault"))
    }

    /// A proof for `PairCompanion` with these values, from a passphrase check.
    pub fn pair_proof(
        &self,
        device_id: &str,
        name: &str,
        request_key: &[u8],
        approval_key: &[u8],
    ) -> apassy::broker::approvals::OwnerProof {
        self.gate
            .authorize(
                OwnerAction::PairCompanion {
                    device_id: device_id.to_owned(),
                    device_name: name.to_owned(),
                    request_key: request_key.to_vec(),
                    approval_key: approval_key.to_vec(),
                },
                OwnerCheck::passphrase(PASS),
            )
            .expect("the passphrase confirms the pairing")
    }

    /// Pair a device with a proof for exactly these values.
    pub fn pair(
        &self,
        device_id: &str,
        name: &str,
        request_key: &[u8],
        approval_key: &[u8],
    ) -> Result<CompanionDevice, AddDeviceError> {
        let proof = self.pair_proof(device_id, name, request_key, approval_key);
        self.with(|vault| {
            vault.add_companion_device(proof, device_id, name, request_key, approval_key)
        })
    }
}

/// A waiting run with a remember offer or without.
pub fn run(remember: bool) -> PendingRun {
    PendingRun {
        id: 0,
        agent: "Companion agent".to_owned(),
        command: vec!["npm".to_owned(), "run".to_owned(), "migrate".to_owned()],
        cwd: "/tmp/synthetic-shop".to_owned(),
        env_names: vec!["DATABASE_URL".to_owned()],
        purpose: "Apply the migration.".to_owned(),
        risk: "asks the owner".to_owned(),
        user_request: "Deploy the schema.".to_owned(),
        request_source: "from the host hook".to_owned(),
        agent_request: String::new(),
        remember: remember.then(|| apassy::broker::approvals::RememberOffer {
            pattern: "npm run migrate".to_owned(),
            approvals: 1,
            needed: 3,
        }),
    }
}
