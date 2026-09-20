//! Receipt kernel for standing.
//!
//! A receipt is a content-addressed, immutable witness to something that happened:
//! a grant issued, a policy decision made, a grant used, revoked, or expired.
//!
//! Receipts form chains: each receipt optionally references a parent, creating
//! a verifiable sequence of events for a given grant lifecycle.
//!
//! Format: canonical JSON (keys sorted) + SHA-256 digest. This format is
//! standing's own and is held to no external protocol. It previously claimed
//! WLP compatibility; WLP is retired from this integration with no named
//! consumer and the claim is withdrawn.
//! No signatures yet — hash is mandatory, signatures are future work.

mod canonical;
mod chain;
mod error;
mod receipt;

pub use canonical::canonical_json;
pub use chain::ReceiptChain;
pub use error::ReceiptError;
pub use receipt::{Receipt, ReceiptBuilder, ReceiptKind, SCHEMA_VERSION};
