//! Device sign-in. The configured origin binds every signature.
use std::time::{Duration, Instant};

use crate::api::{AccessGranted, Challenge, ChallengeRequest, TokenRequest};
use crate::cli::client::{CALL_TIMEOUT, CallError, Client, Method};
use crate::device::{DeviceKey, sign_in_message};
use crate::hostkeys::encode_b64;
use crate::ids::TeamId;

pub fn challenge(client: &Client, team: &TeamId, key: &DeviceKey) -> Result<Challenge, CallError> {
    challenge_before(client, team, key, Instant::now() + CALL_TIMEOUT)
}

fn remaining(deadline: Instant) -> Result<Duration, CallError> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|duration| !duration.is_zero())
        .ok_or_else(|| CallError::Transport("The sign-in call timed out.".into()))
}

fn challenge_before(
    client: &Client,
    team: &TeamId,
    key: &DeviceKey,
    deadline: Instant,
) -> Result<Challenge, CallError> {
    let request = ChallengeRequest {
        team_id: team.clone(),
        public_key: key.public_key_b64(),
    };
    let body = serde_json::to_string(&request)
        .map_err(|_| CallError::Usage("Cannot encode the sign-in request.".into()))?;
    let result: Challenge = client.call(
        Method::Post,
        "/v1/auth/challenge",
        Some(&body),
        remaining(deadline)?,
    )?;
    if result.origin != client.base() {
        return Err(CallError::Usage(format!(
            "The relay calls itself {}; your settings say {}.",
            result.origin,
            client.base()
        )));
    }
    Ok(result)
}

pub fn sign_in_with_challenge(
    client: &Client,
    team: &TeamId,
    key: &DeviceKey,
    challenge: Challenge,
) -> Result<AccessGranted, CallError> {
    token_before(client, team, key, challenge, Instant::now() + CALL_TIMEOUT)
}

fn token_before(
    client: &Client,
    team: &TeamId,
    key: &DeviceKey,
    challenge: Challenge,
    deadline: Instant,
) -> Result<AccessGranted, CallError> {
    if challenge.origin != client.base() {
        return Err(CallError::Usage(format!(
            "The relay calls itself {}; your settings say {}.",
            challenge.origin,
            client.base()
        )));
    }
    let public_key = key.public_key_b64();
    let message = sign_in_message(client.base(), team, &public_key, &challenge.nonce);
    let signature = key
        .sign(&message)
        .map_err(|_| CallError::Usage("Cannot sign with the device key.".into()))?;
    let request = TokenRequest {
        team_id: team.clone(),
        public_key,
        nonce: challenge.nonce,
        signature: encode_b64(&signature),
    };
    let body = zeroize::Zeroizing::new(
        serde_json::to_string(&request)
            .map_err(|_| CallError::Usage("Cannot encode the sign-in request.".into()))?,
    );
    let access: AccessGranted = client.call(
        Method::Post,
        "/v1/auth/token",
        Some(&body),
        remaining(deadline)?,
    )?;
    if access.team_id != *team {
        return Err(CallError::Usage(
            "The sign-in answer has a different team id.".into(),
        ));
    }
    Ok(access)
}

pub fn sign_in(
    client: &Client,
    team: &TeamId,
    key: &DeviceKey,
) -> Result<AccessGranted, CallError> {
    sign_in_timeout(client, team, key, CALL_TIMEOUT)
}

/// Both requests share one deadline, including the time to prepare the signature.
pub fn sign_in_timeout(
    client: &Client,
    team: &TeamId,
    key: &DeviceKey,
    timeout: Duration,
) -> Result<AccessGranted, CallError> {
    let deadline = Instant::now()
        .checked_add(timeout)
        .ok_or_else(|| CallError::Usage("The sign-in timeout is not valid.".into()))?;
    let nonce = challenge_before(client, team, key, deadline)?;
    let access = token_before(client, team, key, nonce, deadline)?;
    remaining(deadline)?;
    Ok(access)
}
