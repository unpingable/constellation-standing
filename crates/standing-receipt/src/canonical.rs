//! Deterministic JSON serialization for receipt content-addressing.
//!
//! What this provides: sorted keys at every level, no trailing commas, no
//! whitespace, no BOM. That is sufficient for the types this crate hashes.
//!
//! What this is NOT: RFC 8785 (JCS). An earlier comment described it as a
//! "JCS subset" to justify a WLP compatibility claim. WLP is retired and the
//! claim is withdrawn, so the accurate description stands on its own: number
//! formatting and string escaping follow serde_json, not ECMAScript, so output
//! diverges from JCS for floats. Receipts here hold no floats today.
//!
//! Fragility worth knowing: `sort_keys` below is correct only while
//! `serde_json::Map` is a `BTreeMap`. If any crate in the dependency graph
//! enables `serde_json/preserve_order`, Cargo feature unification makes this
//! function a silent no-op. `preserve_order` is not enabled today. Adopting
//! `serde_jcs` would remove both this hazard and the JCS divergence, at the
//! cost of rebasing every stored receipt digest.

use serde::Serialize;
use serde_json::Value;

/// Serialize a value to canonical JSON bytes.
///
/// Keys are sorted lexicographically at every nesting level.
/// Output is compact (no whitespace).
pub fn canonical_json<T: Serialize>(value: &T) -> Result<Vec<u8>, serde_json::Error> {
    let v = serde_json::to_value(value)?;
    let sorted = sort_keys(&v);
    serde_json::to_vec(&sorted)
}

fn sort_keys(v: &Value) -> Value {
    match v {
        Value::Object(map) => {
            let sorted: serde_json::Map<String, Value> =
                map.iter().map(|(k, v)| (k.clone(), sort_keys(v))).collect();
            Value::Object(sorted)
        }
        Value::Array(arr) => Value::Array(arr.iter().map(sort_keys).collect()),
        other => other.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    #[test]
    fn keys_are_sorted() {
        let mut map = BTreeMap::new();
        map.insert("zebra", 1);
        map.insert("alpha", 2);
        let bytes = canonical_json(&map).unwrap();
        let s = String::from_utf8(bytes).unwrap();
        assert_eq!(s, r#"{"alpha":2,"zebra":1}"#);
    }

    #[test]
    fn nested_keys_sorted() {
        let mut inner = BTreeMap::new();
        inner.insert("z", 1);
        inner.insert("a", 2);
        let mut outer = BTreeMap::new();
        outer.insert("nested", inner);
        let bytes = canonical_json(&outer).unwrap();
        let s = String::from_utf8(bytes).unwrap();
        assert_eq!(s, r#"{"nested":{"a":2,"z":1}}"#);
    }
}
