//! One closed service-diagnostic consumer of Standing's existing act grants.
//!
//! An operator signs enrollment of an exact grant and workload key. The workload
//! signs the exact acquisition request. Only the existing transactional grant
//! transition may admit it. Neither signature nor an old receipt is reusable
//! permission to invoke a provider. Configuration/key custody is deployment-owned.

use chrono::{DateTime, Utc};
use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use standing_grant::{ActorContext, GrantScope, GrantState, Principal};
use standing_receipt::{ReceiptKind, canonical_json};
use uuid::Uuid;

use crate::{Store, TransitionResult};

pub const ENROLLMENT_SCHEMA: &str = "standing.service-diagnostic-enrollment/v1";
pub const REQUEST_SCHEMA: &str = "standing.service-diagnostic-request/v1";
pub const ACTION: &str = "nq.service-diagnostic/v1";

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DiagnosticEnrollment {
    pub schema: String,
    pub operator: String,
    pub genesis_digest: String,
    pub grant_id: Uuid,
    pub workload: String,
    pub workload_public_key: String,
    pub audience: String,
    pub subject: String,
    pub scope: String,
    pub profile: String,
    pub config_digest: String,
    pub valid_until: DateTime<Utc>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DiagnosticRequest {
    pub schema: String,
    pub request_id: Uuid,
    pub grant_id: Uuid,
    pub operator: String,
    pub workload: String,
    pub audience: String,
    pub subject: String,
    pub scope: String,
    pub profile: String,
    pub config_digest: String,
    pub plan_digest: String,
    pub run_id: Uuid,
    pub node_id: String,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Signed<T> {
    pub body: T,
    pub signature: String,
}

/// Exact bytes signed by each independent principal; no incidental JSON formatting.
pub fn signing_bytes<T: Serialize>(schema: &str, body: &T) -> Result<Vec<u8>, String> {
    let value = serde_json::to_value(body).map_err(|e| e.to_string())?;
    let canonical = canonical_json(&value).map_err(|e| e.to_string())?;
    Ok([schema.as_bytes(), b"\0", canonical.as_slice()].concat())
}

pub fn request_digest(request: &DiagnosticRequest) -> Result<String, String> {
    Ok(format!(
        "sha256:{}",
        hex::encode(Sha256::digest(signing_bytes(REQUEST_SCHEMA, request)?))
    ))
}

/// The existing GrantScope target commits BOTH the subject and observation scope.
pub fn target(subject: &str, scope: &str) -> String {
    let bytes = [
        b"standing.service-diagnostic-target/v1\0".as_slice(),
        subject.as_bytes(),
        b"\0",
        scope.as_bytes(),
    ]
    .concat();
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}

fn digest(value: &str) -> bool {
    value.strip_prefix("sha256:").is_some_and(|v| {
        v.len() == 64
            && v.bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    })
}

fn verify<T: Serialize>(signed: &Signed<T>, key: &str, schema: &str) -> Result<(), String> {
    let bytes: [u8; 32] = hex::decode(key)
        .map_err(|_| "invalid public key")?
        .try_into()
        .map_err(|_| "invalid public key length")?;
    let key = VerifyingKey::from_bytes(&bytes).map_err(|_| "invalid public key")?;
    let bytes = hex::decode(&signed.signature).map_err(|_| "invalid signature")?;
    let signature = Signature::from_slice(&bytes).map_err(|_| "invalid signature length")?;
    key.verify_strict(&signing_bytes(schema, &signed.body)?, &signature)
        .map_err(|_| "signature verification refused".into())
}

impl Store {
    /// Consume one existing active act grant before exactly one diagnostic.
    /// The pinned operator key and expected audience are owner startup inputs,
    /// never supplied by the submitted document. Failure leaves the grant unspent.
    /// An already used grant refuses: inspection of its receipt is a separate read.
    pub fn admit_service_diagnostic(
        &mut self,
        enrollment: &Signed<DiagnosticEnrollment>,
        pinned_operator_key: &str,
        expected_audience: &str,
        signed: &Signed<DiagnosticRequest>,
    ) -> Result<TransitionResult, String> {
        verify(enrollment, pinned_operator_key, ENROLLMENT_SCHEMA)?;
        let e = &enrollment.body;
        if e.schema != ENROLLMENT_SCHEMA
            || e.operator.is_empty()
            || e.workload.is_empty()
            || e.operator == e.workload
            || e.workload_public_key == pinned_operator_key
            || e.audience != expected_audience
            || expected_audience.is_empty()
        {
            return Err("enrollment identity/schema/audience refused".into());
        }
        let genesis = self
            .get_genesis()
            .map_err(|e| e.to_string())?
            .ok_or("genesis absent")?;
        if genesis.actor != e.operator || genesis.digest != e.genesis_digest {
            return Err("operator enrollment does not bind the installed genesis".into());
        }
        verify(signed, &e.workload_public_key, REQUEST_SCHEMA)?;
        let r = &signed.body;
        if r.schema != REQUEST_SCHEMA
            || r.grant_id != e.grant_id
            || r.operator != e.operator
            || r.workload != e.workload
            || r.audience != e.audience
            || r.subject != e.subject
            || r.scope != e.scope
            || r.profile != e.profile
            || r.config_digest != e.config_digest
        {
            return Err("request does not match exact enrolled mandate".into());
        }
        if !matches!(
            r.profile.as_str(),
            "nq.systemd_unit/v1" | "nq.http_endpoint/v1"
        ) || ![&r.subject, &r.scope, &r.config_digest, &r.plan_digest]
            .into_iter()
            .all(|v| digest(v))
            || !r.node_id.starts_with("pn_")
            || r.node_id.len() > 66
            || !r
                .node_id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
        {
            return Err("unsupported diagnostic profile or malformed exact binding".into());
        }
        let now = Utc::now();
        if r.issued_at > now
            || r.expires_at <= now
            || r.expires_at <= r.issued_at
            || (r.expires_at - r.issued_at).num_milliseconds() > 300_000
            || e.valid_until <= now
        {
            return Err("diagnostic request or enrollment expired/not yet valid".into());
        }
        let actor = ActorContext::subject(Principal::new(&e.workload, &e.workload));
        let attempted = GrantScope {
            action: ACTION.into(),
            target: target(&r.subject, &r.scope),
        };
        let evidence = serde_json::json!({
            "schema": "standing.service-diagnostic-admission/v1",
            "request_digest": request_digest(r)?,
            "signed_request": signed,
            "signed_enrollment": enrollment,
            "operator_public_key": pinned_operator_key,
            "nonclaims": ["provider_invoked", "diagnostic_succeeded", "service_healthy", "ag_authorization", "permission_to_reacquire"]
        });
        self.transition_inner(
            &r.grant_id.to_string(),
            GrantState::Used,
            ReceiptKind::GrantUsed,
            &actor,
            evidence,
            None,
            Some(&attempted),
            Some(r.expires_at.min(e.valid_until)),
        )
        .map_err(|e| e.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;
    use ed25519_dalek::{Signer, SigningKey};
    use standing_grant::GrantRequest;
    use standing_policy::HardcodedPolicy;

    fn signed<T: Serialize>(schema: &str, body: T, key: &SigningKey) -> Signed<T> {
        let signature = hex::encode(key.sign(&signing_bytes(schema, &body).unwrap()).to_bytes());
        Signed { body, signature }
    }

    fn fixture() -> (
        Store,
        SigningKey,
        SigningKey,
        Signed<DiagnosticEnrollment>,
        DiagnosticRequest,
    ) {
        fixture_from(Store::open(":memory:").unwrap())
    }

    fn fixture_from(
        mut store: Store,
    ) -> (
        Store,
        SigningKey,
        SigningKey,
        Signed<DiagnosticEnrollment>,
        DiagnosticRequest,
    ) {
        let operator = SigningKey::from_bytes(&[41; 32]);
        let worker = SigningKey::from_bytes(&[42; 32]);
        let genesis = store
            .install_genesis("operator:fixture", "exact-service-diagnostic-v1")
            .unwrap();
        let subject = format!("sha256:{}", "a".repeat(64));
        let scope = format!("sha256:{}", "b".repeat(64));
        let grant = store
            .create_grant(
                &GrantRequest {
                    subject: Principal::new("workload:fixture", "fixture"),
                    scope: GrantScope {
                        action: ACTION.into(),
                        target: target(&subject, &scope),
                    },
                    duration_secs: 300,
                    not_before: None,
                    context: serde_json::json!({"fixture": "operational-ecad"}),
                },
                &HardcodedPolicy,
            )
            .unwrap();
        store
            .transition(
                &grant.grant_id.to_string(),
                GrantState::Active,
                ReceiptKind::GrantActivated,
                &ActorContext::subject(Principal::new("workload:fixture", "fixture")),
                serde_json::json!({}),
                None,
            )
            .unwrap();
        let now = Utc::now();
        let e = DiagnosticEnrollment {
            schema: ENROLLMENT_SCHEMA.into(),
            operator: "operator:fixture".into(),
            genesis_digest: genesis.digest,
            grant_id: grant.grant_id,
            workload: "workload:fixture".into(),
            workload_public_key: hex::encode(worker.verifying_key().to_bytes()),
            audience: "nq:fixture".into(),
            subject: subject.clone(),
            scope: scope.clone(),
            profile: "nq.systemd_unit/v1".into(),
            config_digest: format!("sha256:{}", "c".repeat(64)),
            valid_until: now + Duration::seconds(200),
        };
        let r = DiagnosticRequest {
            schema: REQUEST_SCHEMA.into(),
            request_id: Uuid::new_v4(),
            grant_id: grant.grant_id,
            operator: e.operator.clone(),
            workload: e.workload.clone(),
            audience: e.audience.clone(),
            subject,
            scope,
            profile: e.profile.clone(),
            config_digest: e.config_digest.clone(),
            plan_digest: format!("sha256:{}", "d".repeat(64)),
            run_id: Uuid::new_v4(),
            node_id: "pn_systemd".into(),
            issued_at: now,
            expires_at: now + Duration::seconds(100),
        };
        (
            store,
            operator.clone(),
            worker,
            signed(ENROLLMENT_SCHEMA, e, &operator),
            r,
        )
    }

    #[test]
    fn actual_grant_spend_binds_both_signatures_and_exact_request() {
        let (mut store, op, worker, enrollment, request) = fixture();
        let signed = signed(REQUEST_SCHEMA, request.clone(), &worker);
        let key = hex::encode(op.verifying_key().to_bytes());
        let result = store
            .admit_service_diagnostic(&enrollment, &key, "nq:fixture", &signed)
            .unwrap();
        assert_eq!(result.to_state, GrantState::Used);
        assert_eq!(
            result.receipt.evidence["detail"]["request_digest"],
            request_digest(&request).unwrap()
        );
        assert_eq!(
            store
                .get_grant(&request.grant_id.to_string())
                .unwrap()
                .unwrap()
                .state,
            "used"
        );
        // Replay is historical custody, never a second invocation permission.
        assert!(
            store
                .admit_service_diagnostic(&enrollment, &key, "nq:fixture", &signed)
                .is_err()
        );
    }

    #[test]
    fn concurrent_writers_receive_exactly_one_acquisition_admission() {
        let path = std::env::temp_dir().join(format!(
            "standing-service-diagnostic-{}.sqlite",
            Uuid::new_v4()
        ));
        let (store, op, worker, enrollment, request) =
            fixture_from(Store::open(path.to_str().unwrap()).unwrap());
        drop(store);
        let signed_request = signed(REQUEST_SCHEMA, request, &worker);
        let key = hex::encode(op.verifying_key().to_bytes());
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
        let mut joins = Vec::new();
        for _ in 0..2 {
            let path = path.clone();
            let enrollment = enrollment.clone();
            let signed_request = signed_request.clone();
            let key = key.clone();
            let barrier = barrier.clone();
            joins.push(std::thread::spawn(move || {
                let mut store = Store::open(path.to_str().unwrap()).unwrap();
                barrier.wait();
                store
                    .admit_service_diagnostic(&enrollment, &key, "nq:fixture", &signed_request)
                    .is_ok()
            }));
        }
        let successes = joins
            .into_iter()
            .map(|join| join.join().unwrap())
            .filter(|success| *success)
            .count();
        assert_eq!(successes, 1);
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn signed_wrong_subject_scope_principal_profile_or_configuration_cannot_spend() {
        for field in [
            "subject", "scope", "workload", "operator", "profile", "config", "audience",
        ] {
            let (mut store, op, worker, e, mut r) = fixture();
            match field {
                "subject" => r.subject = format!("sha256:{}", "e".repeat(64)),
                "scope" => r.scope = format!("sha256:{}", "e".repeat(64)),
                "workload" => r.workload = "other".into(),
                "operator" => r.operator = "other".into(),
                "profile" => r.profile = "nq.http_endpoint/v1".into(),
                "config" => r.config_digest = format!("sha256:{}", "e".repeat(64)),
                _ => r.audience = "other".into(),
            }
            let id = r.grant_id.to_string();
            assert!(
                store
                    .admit_service_diagnostic(
                        &e,
                        &hex::encode(op.verifying_key().to_bytes()),
                        "nq:fixture",
                        &signed(REQUEST_SCHEMA, r, &worker)
                    )
                    .is_err(),
                "{field}"
            );
            assert_eq!(
                store.get_grant(&id).unwrap().unwrap().state,
                "active",
                "{field}"
            );
        }
    }

    #[test]
    fn operator_and_workload_keys_are_independent_and_pinned() {
        let (mut store, op, worker, e, r) = fixture();
        let other = SigningKey::from_bytes(&[9; 32]);
        let key = hex::encode(op.verifying_key().to_bytes());
        assert!(
            store
                .admit_service_diagnostic(
                    &e,
                    &key,
                    "nq:fixture",
                    &signed(REQUEST_SCHEMA, r.clone(), &other)
                )
                .is_err()
        );
        assert!(
            store
                .admit_service_diagnostic(
                    &signed(ENROLLMENT_SCHEMA, e.body.clone(), &other),
                    &key,
                    "nq:fixture",
                    &signed(REQUEST_SCHEMA, r.clone(), &worker)
                )
                .is_err()
        );
        let mut changed = signed(REQUEST_SCHEMA, r, &worker);
        changed.body.plan_digest = format!("sha256:{}", "0".repeat(64));
        assert!(
            store
                .admit_service_diagnostic(&e, &key, "nq:fixture", &changed)
                .is_err()
        );
    }

    #[test]
    fn revoked_and_expired_grants_refuse_even_with_valid_signatures() {
        for state in ["revoked", "expired"] {
            let (mut store, op, worker, e, r) = fixture();
            let id = r.grant_id.to_string();
            if state == "revoked" {
                store
                    .transition(
                        &id,
                        GrantState::Revoked,
                        ReceiptKind::GrantRevoked,
                        &ActorContext::subject(Principal::new("workload:fixture", "fixture")),
                        serde_json::json!({}),
                        None,
                    )
                    .unwrap();
            } else {
                // Exact boundary control, including the generic grant's skew window.
                store
                    .conn
                    .execute(
                        "UPDATE grants SET expires_at = ?1 WHERE id = ?2",
                        rusqlite::params![Utc::now().to_rfc3339(), id],
                    )
                    .unwrap();
            }
            assert!(
                store
                    .admit_service_diagnostic(
                        &e,
                        &hex::encode(op.verifying_key().to_bytes()),
                        "nq:fixture",
                        &signed(REQUEST_SCHEMA, r, &worker)
                    )
                    .is_err()
            );
            assert_ne!(store.get_grant(&id).unwrap().unwrap().state, "used");
        }
    }

    #[test]
    fn expiry_and_genesis_substitution_are_not_permission() {
        for field in ["request_expiry", "enrollment_expiry", "genesis"] {
            let (mut store, op, worker, mut e, mut r) = fixture();
            match field {
                "request_expiry" => r.expires_at = r.issued_at,
                "enrollment_expiry" => e.body.valid_until = r.issued_at,
                _ => e.body.genesis_digest = "other-instance".into(),
            }
            e = signed(ENROLLMENT_SCHEMA, e.body, &op);
            assert!(
                store
                    .admit_service_diagnostic(
                        &e,
                        &hex::encode(op.verifying_key().to_bytes()),
                        "nq:fixture",
                        &signed(REQUEST_SCHEMA, r, &worker)
                    )
                    .is_err()
            );
        }
    }
}
