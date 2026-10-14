//! What the vault keeps to recognize the master password of an account.
//!
//! A client never sends the master password, but a hash that it derives from it. Like a server,
//! the vault does not store that hash either, but a salted hash of it:
//!
//! ```text
//! hash = PBKDF2-HMAC-SHA256(<the hash of the client as ASCII>, salt, iterations, 32 bytes)
//! ```

use serde_json::{Value, json};
use sha2::Sha256;
use subtle::ConstantTimeEq;

use crate::json::{JsonObject, base64_decode, base64_encode, int, string};
use crate::platform::Platform;

const ALGORITHM: &str = "PBKDF2-SHA256";
const ITERATIONS: u32 = 100_000;
const SALT_SIZE_BYTES: usize = 16;
const HASH_SIZE_BYTES: usize = 32;

/// Creates the verifier for the hash of a master password, with a new salt.
pub(crate) fn create_verifier(platform: &impl Platform, password_hash: &str) -> Value {
    let mut salt = [0u8; SALT_SIZE_BYTES];
    platform.random_bytes(&mut salt);
    let hash = derive(password_hash, &salt, ITERATIONS);
    json!({
        "algorithm": ALGORITHM,
        "iterations": ITERATIONS,
        "salt": base64_encode(&salt),
        "hash": base64_encode(&hash),
    })
}

/// Returns `true` if the hash of a master password is the one that the verifier was created
/// for.
pub(crate) fn matches_verifier(verifier: Option<&JsonObject>, password_hash: &str) -> bool {
    let Some(verifier) = verifier else {
        return false;
    };
    if string(verifier, "algorithm") != Some(ALGORITHM) {
        return false;
    }
    let iterations = int(verifier, "iterations")
        .and_then(|iterations| u32::try_from(iterations).ok())
        .filter(|iterations| *iterations > 0);
    let salt = decode_non_empty(string(verifier, "salt"));
    let expected_hash = decode_non_empty(string(verifier, "hash"));
    let (Some(iterations), Some(salt), Some(expected_hash)) = (iterations, salt, expected_hash)
    else {
        return false;
    };
    let hash = derive(password_hash, &salt, iterations);
    // In a time that does not depend on where the two differ. Hashes of other lengths differ.
    bool::from(expected_hash.as_slice().ct_eq(&hash))
}

fn derive(password_hash: &str, salt: &[u8], iterations: u32) -> [u8; HASH_SIZE_BYTES] {
    let mut hash = [0u8; HASH_SIZE_BYTES];
    pbkdf2::pbkdf2_hmac::<Sha256>(password_hash.as_bytes(), salt, iterations, &mut hash);
    hash
}

fn decode_non_empty(text: Option<&str>) -> Option<Vec<u8>> {
    text.and_then(base64_decode)
        .filter(|bytes| !bytes.is_empty())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::platform::LogLevel;
    use std::cell::Cell;

    const PASSWORD_HASH: &str = "cGFzc3dvcmQtaGFzaA==";

    /// A verifier of [`PASSWORD_HASH`] that another implementation of PBKDF2 derived.
    fn known_verifier() -> JsonObject {
        json!({
            "algorithm": "PBKDF2-SHA256",
            "iterations": 1000,
            "salt": "AAECAwQFBgcICQoLDA0ODw==",
            "hash": "P4IEzEay0g6Vm+cSyuqoihll00E0FvAo+DlgSpr+xCs=",
        })
        .as_object()
        .cloned()
        .unwrap()
    }

    struct CountingPlatform {
        next: Cell<u8>,
    }

    impl Platform for CountingPlatform {
        fn now_millis(&self) -> i64 {
            0
        }

        fn random_bytes(&self, buffer: &mut [u8]) {
            for byte in buffer {
                *byte = self.next.get();
                self.next.set(self.next.get().wrapping_add(1));
            }
        }

        fn log(&self, _level: LogLevel, _message: &str) {}
    }

    #[test]
    fn a_verifier_recognizes_the_hash_that_it_was_created_for_and_no_other() {
        let platform = CountingPlatform { next: Cell::new(0) };

        let first = create_verifier(&platform, PASSWORD_HASH);
        let second = create_verifier(&platform, PASSWORD_HASH);
        let first = first.as_object().unwrap();

        assert_eq!(string(first, "algorithm"), Some("PBKDF2-SHA256"));
        assert_eq!(int(first, "iterations"), Some(100_000));
        let salt = base64_decode(string(first, "salt").unwrap()).unwrap();
        let hash = base64_decode(string(first, "hash").unwrap()).unwrap();

        assert_eq!(salt.len(), 16);
        assert_eq!(hash.len(), 32);
        assert!(matches_verifier(Some(first), PASSWORD_HASH));
        assert!(!matches_verifier(Some(first), "d3Jvbmc="));
        // Every verifier is salted differently.
        assert_ne!(Value::Object(first.clone()), second);
    }

    #[test]
    fn the_hash_is_derived_the_way_the_format_of_the_vault_defines_it() {
        let verifier = known_verifier();

        let other_hash = PASSWORD_HASH.to_lowercase();

        assert!(matches_verifier(Some(&verifier), PASSWORD_HASH));
        assert!(!matches_verifier(Some(&verifier), &other_hash));
    }

    #[test]
    fn a_verifier_that_is_not_complete_recognizes_nothing() {
        let cases = [
            ("algorithm", json!("SHA-256")),
            ("iterations", json!(0)),
            ("iterations", json!(-1)),
            ("iterations", json!("1000")),
            ("salt", json!("***")),
            ("salt", json!("")),
            ("hash", json!("")),
            ("hash", json!("P4IEzEay0g6Vm+cSyuqoig==")),
        ];

        assert!(!matches_verifier(None, PASSWORD_HASH));
        for (key, value) in cases {
            let mut verifier = known_verifier();
            verifier.insert(key.to_owned(), value);
            assert!(!matches_verifier(Some(&verifier), PASSWORD_HASH), "{key}");
        }
    }
}
