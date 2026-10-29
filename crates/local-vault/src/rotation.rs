//! Rotating the user key of an account: the client makes a new user key, encrypts with it again
//! everything that the one before encrypted, and the vault takes it all in place of what it had
//! (`POST accounts/key-management/rotate-user-account-keys`). This is what locks out whoever knows
//! an earlier master password: the user key encrypted with the master key of that password, which
//! the files of the vault folder and their copies can still hold, unlocks the key before, which
//! nothing new is encrypted with.
//!
//! The rotation comes with the master password of the account, which is changed along with it,
//! the private key of the account encrypted with the new key, and every item and folder of the
//! vault encrypted with it. It is refused unless it has each of them, as one that it leaves out
//! would stay encrypted with a key that the vault no longer has, and so is one that leaves out the
//! key of an attachment. The key pair of the account stays the same, which a vault that has no
//! public key of the account cannot tell, as does how the master key is derived. The account gets
//! a new security stamp, and has no recorded ID of its user key until a client records that of the
//! new one.
//!
//! The vault says which rotation made its user key: when and by which device (see
//! [`KeyRotation`]). A device that does not have the rotation yet still writes with the key
//! before, so every version in the file of a device says with which key it was written, and one
//! that was written with a later key is newer than one that was written with an earlier one,
//! whenever either was written (see [`crate::merge::Stamp`]). Such a device changes an item that
//! the rotation encrypted again, and the change is lost, or adds an item, which the new key does
//! not decrypt, but neither takes the place of what the rotation wrote, nor brings the private key
//! encrypted with the key before back. Once the rotation has come to the device, the tokens that
//! were issued before it are refused, so that the client, which still has the key before, does
//! not write with it: it logs the account out, to be logged in to with the new master password.
//!
//! The new key is one of encryption version 1 (AES-CBC with HMAC), as the one before. The clients
//! that share a vault folder keep accounts at that version, and a rotation that comes with keys of
//! version 2, a key pair for signing and the security state of the account, which the vault does
//! not keep, is refused.

use serde_json::{Value, json};

use crate::account::{
    KEY_PASSWORD_VERIFIER, KEY_USER_KEY_ROTATION, is_password_hash, master_password_unlock,
    profile, user_key_rotation,
};
use crate::fs::FileSystem;
use crate::http::{LocalRequest, bad_request, invalid_request_response, ok_empty_response};
use crate::json::{
    JsonObject, int, int_or_null, into_object, obj, string, string_or_null, with_fields,
    without_fields,
};
use crate::kdf::is_same_kdf;
use crate::merge::KeyRotation;
use crate::platform::Platform;
use crate::server::{LocalServer, Outcome};
use crate::store::{KEY_ACCOUNT, KEY_SYNC, ReadVault};
use crate::vault::with_rotated_items;
use crate::verifier::create_verifier;

const INVALID_PASSWORD_MESSAGE: &str = "Invalid master password.";
const UNLOCK_CHANGED_MESSAGE: &str =
    "The master key has to be derived the same way after the rotation as before it.";
const KEY_PAIR_CHANGED_MESSAGE: &str = "The key pair of the account has to stay the same.";
const NO_KEY_PAIR_MESSAGE: &str = "The vault has no key pair of the account to keep.";
const SIGNING_KEYS_MESSAGE: &str =
    "A local vault does not take the keys of encryption version 2, which come with signing keys.";

/// The master password that a rotation comes with (`masterPasswordUnlockData`).
struct MasterPassword<'a> {
    /// The salt and the settings that the master key is derived with, and the new user key
    /// encrypted with that master key, in the form that the vault has them in.
    unlock: JsonObject,
    /// The new user key encrypted with the master key.
    user_key: &'a str,
    /// What the master password is recognized by.
    authentication_hash: &'a str,
    hint: Option<&'a str>,
}

impl<'a> MasterPassword<'a> {
    /// Reads the master password from the unlock data of a rotation, or returns `None` if any of
    /// it is missing.
    fn read(data: &'a JsonObject) -> Option<Self> {
        let user_key = string(data, "masterKeyEncryptedUserKey")?;
        let unlock = json!({
            "salt": string(data, "email")?,
            "kdf": {
                "kdfType": int(data, "kdfType")?,
                "iterations": int(data, "kdfIterations")?,
                "memory": int_or_null(Some(data), "kdfMemory"),
                "parallelism": int_or_null(Some(data), "kdfParallelism"),
            },
            "masterKeyEncryptedUserKey": user_key,
        });
        Some(Self {
            unlock: into_object(unlock),
            user_key,
            authentication_hash: string(data, "masterKeyAuthenticationHash")?,
            hint: string(data, "masterPasswordHint"),
        })
    }

    /// Returns `true` if the master key is derived the way that the unlock data of the vault
    /// says: from the same salt, with the same settings.
    fn is_derived_as(&self, unlock: &JsonObject) -> bool {
        let kdf = obj(&self.unlock, "kdf").zip(obj(unlock, "kdf"));
        let is_same = kdf.is_some_and(|(kdf, other)| is_same_kdf(kdf, other));
        is_same && string(&self.unlock, "salt") == string(unlock, "salt")
    }
}

/// The key pair of the account that a rotation comes with (`accountKeys`): its public key, and its
/// private key encrypted with the new user key.
struct KeyPair<'a> {
    wrapped_private_key: &'a str,
    public_key: &'a str,
}

impl<'a> KeyPair<'a> {
    /// Reads the key pair from the account keys of a rotation, or returns `None` if any of it is
    /// missing. A client sends it twice, in fields that the Bitwarden server reads in turn.
    fn read(keys: &'a JsonObject) -> Option<Self> {
        let pair = obj(keys, "publicKeyEncryptionKeyPair");
        let field = |in_pair, alone| {
            let in_pair = pair.and_then(|pair| string(pair, in_pair));
            in_pair.or_else(|| string(keys, alone))
        };
        Some(Self {
            wrapped_private_key: field("wrappedPrivateKey", "userKeyEncryptedAccountPrivateKey")?,
            public_key: field("publicKey", "accountPublicKey")?,
        })
    }
}

impl<F: FileSystem, P: Platform> LocalServer<F, P> {
    /// Replaces the user key of the account with the one that the client made, along with what the
    /// client encrypted again with it, and the master password that unlocks it (see the
    /// documentation of this module). Every item and folder of the vault gets a new revision date.
    pub(crate) async fn rotate_user_account_keys(
        &self,
        user_id: &str,
        vault: &ReadVault,
        request: &LocalRequest,
    ) -> Outcome {
        let body = request.json_body()?;
        if !is_password_hash(vault, string(&body, "oldMasterKeyAuthenticationHash")) {
            return Ok(bad_request(INVALID_PASSWORD_MESSAGE));
        }
        let unlock_data = obj(&body, "accountUnlockData");
        let unlock_data = unlock_data.and_then(|data| obj(data, "masterPasswordUnlockData"));
        let master_password = unlock_data.and_then(MasterPassword::read);
        let keys = obj(&body, "accountKeys");
        let key_pair = keys.and_then(KeyPair::read);
        let (Some(master_password), Some(keys), Some(key_pair), Some(data)) =
            (master_password, keys, key_pair, obj(&body, "accountData"))
        else {
            return Ok(invalid_request_response());
        };
        let unlock = master_password_unlock(vault);
        if !unlock.is_some_and(|unlock| master_password.is_derived_as(unlock)) {
            return Ok(bad_request(UNLOCK_CHANGED_MESSAGE));
        }
        let has_signing_keys = ["signatureKeyPair", "securityState"]
            .iter()
            .any(|key| keys.get(*key).is_some_and(|value| !value.is_null()));
        if has_signing_keys {
            return Ok(bad_request(SIGNING_KEYS_MESSAGE));
        }
        // The key pair stays the same, which is told by the public key that the vault has.
        let Some(public_key) = public_key_of(vault) else {
            return Ok(bad_request(NO_KEY_PAIR_MESSAGE));
        };
        if public_key != key_pair.public_key {
            return Ok(bad_request(KEY_PAIR_CHANGED_MESSAGE));
        }
        let updated = match with_rotated_items(vault, data, user_id, &self.now()) {
            Ok(updated) => updated,
            Err(refusal) => return Ok(refusal),
        };
        let updated = self.with_new_user_key(&updated, master_password, &key_pair);
        self.save(user_id, vault, &updated).await?;
        Ok(ok_empty_response())
    }

    /// Returns the vault with the new user key: the master password that unlocks it, the private
    /// key encrypted with it, and the rotation that made it, which this device makes now. The
    /// account gets a new security stamp, and loses the ID of its user key, which is that of the
    /// key before.
    fn with_new_user_key(
        &self,
        vault: &JsonObject,
        master_password: MasterPassword<'_>,
        key_pair: &KeyPair<'_>,
    ) -> JsonObject {
        let now_millis = self.platform.now_millis();
        let previous = user_key_rotation(vault);
        let rotation = KeyRotation::next(previous.as_ref(), now_millis, self.store.device_id());
        let verifier = create_verifier(&self.platform, master_password.authentication_hash);
        let account = obj(vault, KEY_ACCOUNT).cloned().unwrap_or_default();
        let account = with_fields(
            &account,
            [
                (KEY_PASSWORD_VERIFIER, verifier),
                (KEY_USER_KEY_ROTATION, rotation.to_json()),
            ],
        );
        let profile = profile(vault);
        // The profile has them, as the rotation is refused for a vault without its public key.
        let account_keys = obj(&profile, "accountKeys").cloned().unwrap_or_default();
        let profile = with_fields(
            &profile,
            [
                ("key", Value::from(master_password.user_key)),
                ("masterPasswordHint", string_or_null(master_password.hint)),
                ("securityStamp", Value::String(self.new_id())),
                ("privateKey", Value::from(key_pair.wrapped_private_key)),
                (
                    "accountKeys",
                    Value::Object(with_key_pair(&account_keys, key_pair)),
                ),
            ],
        );
        let sync = obj(vault, KEY_SYNC).cloned().unwrap_or_default();
        let user_decryption = obj(&sync, "userDecryption").cloned().unwrap_or_default();
        let user_decryption = with_fields(
            &without_fields(&user_decryption, &["userKeyId"]),
            [(
                "masterPasswordUnlock",
                Value::Object(master_password.unlock),
            )],
        );
        let sync = with_fields(
            &sync,
            [
                ("profile", Value::Object(profile)),
                ("userDecryption", Value::Object(user_decryption)),
            ],
        );
        with_fields(
            vault,
            [
                (KEY_ACCOUNT, Value::Object(account)),
                (KEY_SYNC, Value::Object(sync)),
            ],
        )
    }
}

/// The public key of the account, if the vault has one.
fn public_key_of(vault: &JsonObject) -> Option<&str> {
    let profile = obj(obj(vault, KEY_SYNC)?, "profile")?;
    let pair = obj(obj(profile, "accountKeys")?, "publicKeyEncryptionKeyPair")?;
    string(pair, "publicKey")
}

/// Returns the keys of the account, as the profile has them, with the key pair.
fn with_key_pair(account_keys: &JsonObject, key_pair: &KeyPair<'_>) -> JsonObject {
    let pair = obj(account_keys, "publicKeyEncryptionKeyPair").cloned();
    let pair = with_fields(
        &pair.unwrap_or_default(),
        [
            (
                "wrappedPrivateKey",
                Value::from(key_pair.wrapped_private_key),
            ),
            ("publicKey", Value::from(key_pair.public_key)),
        ],
    );
    with_fields(
        account_keys,
        [("publicKeyEncryptionKeyPair", Value::Object(pair))],
    )
}
