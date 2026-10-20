//! The settings that the master key of an account is derived with, which the vault keeps in the
//! `kdf` of its unlock data: `kdfType`, `iterations`, and for Argon2id `memory`, in MiB, and
//! `parallelism`.
//!
//! The vault only takes settings in the ranges that the Bitwarden server takes them in
//! (`KdfConstants`), and checks them where the server does (`KdfSettingsValidator`): when an
//! account is registered, and when its settings change. Settings with less work would make the
//! master password easier to guess from the vault folder, and settings with more work, or of a
//! KDF that no client knows, can leave the account impossible to unlock. The settings that an
//! account has are not checked again, as the server does not check them again either: an account
//! that an earlier version took other settings for can still log in.

use std::ops::RangeInclusive;

use crate::json::{JsonObject, int};

/// The `kdfType` of PBKDF2-SHA256.
pub(crate) const KDF_TYPE_PBKDF2: i64 = 0;
/// The `kdfType` of Argon2id.
const KDF_TYPE_ARGON2ID: i64 = 1;

const PBKDF2_ITERATIONS: RangeInclusive<i64> = 600_000..=2_000_000;
const ARGON2_ITERATIONS: RangeInclusive<i64> = 2..=10;
const ARGON2_MEMORY_MIB: RangeInclusive<i64> = 15..=1024;
const ARGON2_PARALLELISM: RangeInclusive<i64> = 1..=16;

const UNKNOWN_KDF_TYPE_MESSAGE: &str = "KDF type must be 0 (PBKDF2-SHA256) or 1 (Argon2id).";

/// Returns why a master key may not be derived with the settings, in the words of the Bitwarden
/// server, or `None` if it may. A parameter that is missing, or that is not an integer, is
/// outside of its range. Settings of another KDF than PBKDF2-SHA256 and Argon2id are refused as
/// well, which the server does not check, as no client derives a master key with them.
pub(crate) fn kdf_error(kdf: &JsonObject) -> Option<String> {
    match int(kdf, "kdfType") {
        Some(KDF_TYPE_PBKDF2) if is_outside(kdf, "iterations", PBKDF2_ITERATIONS) => {
            Some(out_of_range("KDF iterations", PBKDF2_ITERATIONS, ""))
        }
        Some(KDF_TYPE_PBKDF2) => None,
        Some(KDF_TYPE_ARGON2ID) if is_outside(kdf, "iterations", ARGON2_ITERATIONS) => {
            Some(out_of_range("Argon2 iterations", ARGON2_ITERATIONS, ""))
        }
        Some(KDF_TYPE_ARGON2ID) if is_outside(kdf, "memory", ARGON2_MEMORY_MIB) => {
            Some(out_of_range("Argon2 memory", ARGON2_MEMORY_MIB, "mb"))
        }
        Some(KDF_TYPE_ARGON2ID) if is_outside(kdf, "parallelism", ARGON2_PARALLELISM) => {
            Some(out_of_range("Argon2 parallelism", ARGON2_PARALLELISM, ""))
        }
        Some(KDF_TYPE_ARGON2ID) => None,
        _ => Some(UNKNOWN_KDF_TYPE_MESSAGE.to_owned()),
    }
}

/// Returns `true` if both settings derive a master key the same way: with the same KDF, and the
/// same values of its parameters. PBKDF2 has no memory or parallelism, so what the settings say
/// about them makes no difference to it.
pub(crate) fn is_same_kdf(a: &JsonObject, b: &JsonObject) -> bool {
    let kdf_type = int(a, "kdfType");
    let parameters: &[&str] = if kdf_type == Some(KDF_TYPE_PBKDF2) {
        &["iterations"]
    } else {
        &["iterations", "memory", "parallelism"]
    };
    kdf_type == int(b, "kdfType") && parameters.iter().all(|key| int(a, key) == int(b, key))
}

/// Returns `true` if the parameter of the settings is missing, or outside of the range.
fn is_outside(kdf: &JsonObject, key: &str, range: RangeInclusive<i64>) -> bool {
    int(kdf, key).is_none_or(|value| !range.contains(&value))
}

/// The message of the Bitwarden server for a parameter that is outside of its range, which it
/// gives the bounds of in the unit.
fn out_of_range(name: &str, range: RangeInclusive<i64>, unit: &str) -> String {
    let (min, max) = range.into_inner();
    format!("{name} must be between {min}{unit} and {max}{unit}.")
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::json::into_object;

    fn pbkdf2(iterations: i64) -> JsonObject {
        let kdf = json!({"kdfType": 0, "iterations": iterations, "memory": null});
        into_object(kdf)
    }

    fn argon2(iterations: i64, memory: i64, parallelism: i64) -> JsonObject {
        let kdf = json!({
            "kdfType": 1,
            "iterations": iterations,
            "memory": memory,
            "parallelism": parallelism,
        });
        into_object(kdf)
    }

    #[test]
    fn settings_in_the_ranges_of_the_bitwarden_server_are_taken() {
        // Those that the tests of `KdfSettingsValidator` of the server take.
        let taken = [
            pbkdf2(600_000),
            pbkdf2(1_000_000),
            pbkdf2(2_000_000),
            argon2(2, 15, 1),
            argon2(5, 500, 8),
            argon2(10, 1024, 16),
        ];

        for kdf in taken {
            assert_eq!(kdf_error(&kdf), None);
        }
    }

    #[test]
    fn settings_outside_of_the_ranges_are_refused_in_the_words_of_the_bitwarden_server() {
        let iterations = "KDF iterations must be between 600000 and 2000000.";
        let argon2_iterations = "Argon2 iterations must be between 2 and 10.";
        let memory = "Argon2 memory must be between 15mb and 1024mb.";
        let parallelism = "Argon2 parallelism must be between 1 and 16.";
        let refused = [
            (pbkdf2(599_999), iterations),
            (pbkdf2(2_000_001), iterations),
            (argon2(1, 64, 4), argon2_iterations),
            (argon2(11, 64, 4), argon2_iterations),
            (argon2(10, 14, 8), memory),
            (argon2(10, 1025, 8), memory),
            (argon2(10, 512, 0), parallelism),
            (argon2(10, 512, 17), parallelism),
            // Only the first parameter that is outside of its range, as the server tells.
            (argon2(0, 14, 0), argon2_iterations),
        ];

        for (kdf, message) in refused {
            assert_eq!(kdf_error(&kdf).as_deref(), Some(message));
        }
    }

    #[test]
    fn settings_without_a_parameter_or_of_another_kdf_are_refused() {
        let mut no_memory = argon2(3, 64, 4);
        no_memory.remove("memory");
        let mut text = pbkdf2(600_000);
        text.insert("iterations".to_owned(), json!("600000"));
        let mut other_kdf = pbkdf2(600_000);
        other_kdf.insert("kdfType".to_owned(), json!(2));
        let mut no_kdf = pbkdf2(600_000);
        no_kdf.remove("kdfType");

        let memory = "Argon2 memory must be between 15mb and 1024mb.";
        let iterations = "KDF iterations must be between 600000 and 2000000.";
        let unknown = Some(UNKNOWN_KDF_TYPE_MESSAGE);
        assert_eq!(kdf_error(&no_memory).as_deref(), Some(memory));
        assert_eq!(kdf_error(&text).as_deref(), Some(iterations));
        assert_eq!(kdf_error(&other_kdf).as_deref(), unknown);
        assert_eq!(kdf_error(&no_kdf).as_deref(), unknown);
    }

    #[test]
    fn settings_are_the_same_if_they_derive_a_master_key_the_same_way() {
        let mut with_memory = pbkdf2(600_000);
        with_memory.insert("memory".to_owned(), json!(64));

        assert!(is_same_kdf(&pbkdf2(600_000), &with_memory));
        assert!(is_same_kdf(&argon2(3, 64, 4), &argon2(3, 64, 4)));
        assert!(!is_same_kdf(&pbkdf2(600_000), &pbkdf2(700_000)));
        assert!(!is_same_kdf(&pbkdf2(3), &argon2(3, 64, 4)));
        assert!(!is_same_kdf(&argon2(3, 64, 4), &argon2(4, 64, 4)));
        assert!(!is_same_kdf(&argon2(3, 64, 4), &argon2(3, 32, 4)));
        assert!(!is_same_kdf(&argon2(3, 64, 4), &argon2(3, 64, 2)));
    }
}
