//! What the Bitwarden API does for the settings of an account, and what the vault holds about
//! the account.

use serde_json::{Value, json};

use crate::fs::FileSystem;
use crate::http::{
    HTTP_BAD_REQUEST, HTTP_TOO_MANY_REQUESTS, LocalRequest, bad_request, error_response,
    invalid_request_response, ok_empty_response, ok_response,
};
use crate::json::{
    JsonObject, int, int_or_null, into_object, is_blank, obj, string, string_or_null, with_fields,
};
use crate::kdf::{is_same_kdf, kdf_error};
use crate::platform::{LogLevel, Platform};
use crate::server::{ClientKind, LocalServer, Outcome};
use crate::store::{KEY_ACCOUNT, KEY_SYNC, ReadVault};
use crate::verifier::{create_verifier, matches_verifier};

/// The field of the account that holds what the master password is recognized by.
pub(crate) const KEY_PASSWORD_VERIFIER: &str = "masterPasswordVerifier";

const INVALID_PASSWORD_MESSAGE: &str = "Invalid master password.";
const FILES_LEFT_BEHIND_MESSAGE: &str =
    "Files of an account that was deleted could not be deleted from the vault folder.";
const ANOTHER_USER_KEY_MESSAGE: &str = "This is not the ID of the user key of the account.";
const NO_HINT_MESSAGE: &str = "There is no master password hint for this email.";
const KDF_CHANGED_MESSAGE: &str = "The KDF settings cannot be changed with the master password.";

impl<F: FileSystem, P: Platform> LocalServer<F, P> {
    /// A server emails the hint, which cannot be done here. It is the message of an error
    /// instead, which the client shows.
    pub(crate) async fn password_hint(&self, request: &LocalRequest) -> Outcome {
        let body = request.json_body()?;
        let vault = match string(&body, "email") {
            Some(email) => self.first_vault_of(email).await?,
            None => None,
        };
        let hint = vault
            .as_ref()
            .map(profile)
            .and_then(|profile| string(&profile, "masterPasswordHint").map(str::to_owned))
            .filter(|hint| !is_blank(hint));
        let message = match hint {
            Some(hint) => format!("Your master password hint: {hint}"),
            None => NO_HINT_MESSAGE.to_owned(),
        };
        let code = match self.client {
            // The only status that the app shows the message of.
            ClientKind::Android => HTTP_TOO_MANY_REQUESTS,
            // The extension shows a message of its own for that status.
            ClientKind::Browser => HTTP_BAD_REQUEST,
        };
        Ok(error_response(code, &message))
    }

    /// Replaces the master password. A new security stamp signs the account out wherever else
    /// the vault is in use, as the user key there is still unlocked with the old password.
    ///
    /// The new master key has to be derived with the settings that the account has. As with the
    /// Bitwarden server, they only change with [`Self::update_kdf`], which checks them.
    pub(crate) async fn change_password(
        &self,
        user_id: &str,
        vault: &ReadVault,
        request: &LocalRequest,
    ) -> Outcome {
        let body = request.json_body()?;
        if !is_password_hash(vault, string(&body, "masterPasswordHash")) {
            return Ok(bad_request(INVALID_PASSWORD_MESSAGE));
        }
        let Some(updated) = self.with_master_password(vault, &body) else {
            return Ok(invalid_request_response());
        };
        if !has_same_kdf(vault, &updated) {
            return Ok(bad_request(KDF_CHANGED_MESSAGE));
        }
        let hint = string(&body, "masterPasswordHint");
        let profile = with_fields(
            &profile(&updated),
            [
                ("masterPasswordHint", string_or_null(hint)),
                ("securityStamp", Value::String(self.new_id())),
            ],
        );
        let updated = with_profile(&updated, profile);
        self.save(user_id, vault, &updated).await?;
        Ok(ok_empty_response())
    }

    /// Replaces the parameters that the master key is derived with, unless a master key may not
    /// be derived with the new ones (see [`kdf_error`]).
    pub(crate) async fn update_kdf(
        &self,
        user_id: &str,
        vault: &ReadVault,
        request: &LocalRequest,
    ) -> Outcome {
        let body = request.json_body()?;
        if !is_password_hash(vault, string(&body, "masterPasswordHash")) {
            return Ok(bad_request(INVALID_PASSWORD_MESSAGE));
        }
        let Some(updated) = self.with_master_password(vault, &body) else {
            return Ok(invalid_request_response());
        };
        if let Some(message) = kdf_of(&updated).and_then(kdf_error) {
            return Ok(bad_request(&message));
        }
        self.save(user_id, vault, &updated).await?;
        Ok(ok_empty_response())
    }

    /// Records the ID of the user key of the account, which a client then finds when it syncs.
    /// The Bitwarden SDK sends it for an account that has none recorded.
    ///
    /// It is recorded once. Items are checked against it, so a client that has another key must
    /// not get the ID of that key in its place.
    pub(crate) async fn record_user_key_id(
        &self,
        user_id: &str,
        vault: &ReadVault,
        request: &LocalRequest,
    ) -> Outcome {
        let body = request.json_body()?;
        let user_key_id = string(&body, "userKeyId").filter(|id| !is_blank(id));
        let (Some(user_key_id), Some(sync)) = (user_key_id, obj(vault, KEY_SYNC)) else {
            return Ok(invalid_request_response());
        };
        if let Some(recorded) = recorded_user_key_id(vault) {
            return Ok(if recorded.eq_ignore_ascii_case(user_key_id) {
                ok_empty_response()
            } else {
                bad_request(ANOTHER_USER_KEY_MESSAGE)
            });
        }
        let user_decryption = obj(sync, "userDecryption").cloned().unwrap_or_default();
        let user_decryption = with_fields(&user_decryption, [("userKeyId", user_key_id.into())]);
        let sync = with_fields(sync, [("userDecryption", Value::Object(user_decryption))]);
        let updated = with_fields(vault, [(KEY_SYNC, Value::Object(sync))]);
        self.save(user_id, vault, &updated).await?;
        Ok(ok_empty_response())
    }

    /// Deletes the vault of the account, along with its attachments. An account that could not
    /// be deleted is not reported as deleted: the client would sign it out as if it were gone,
    /// while it can still be signed in to. Files of an account that was deleted that could not be
    /// deleted are reported and left behind, as nothing reads them: the client would be told
    /// that the account is still there, and find it gone at its next request.
    pub(crate) async fn delete_account(
        &self,
        user_id: &str,
        vault: &JsonObject,
        request: &LocalRequest,
    ) -> Outcome {
        let body = request.json_body()?;
        if !is_password_hash(vault, string(&body, "MasterPasswordHash")) {
            return Ok(bad_request(INVALID_PASSWORD_MESSAGE));
        }
        if !self.store.delete_account(user_id).await? {
            self.platform
                .log(LogLevel::Warning, FILES_LEFT_BEHIND_MESSAGE);
        }
        Ok(ok_empty_response())
    }

    /// Returns the vault with the master password data of the request body: what the new
    /// password is recognized by, and the user key encrypted with the new master key. Returns
    /// `None` if any of that is missing.
    fn with_master_password(&self, vault: &JsonObject, body: &JsonObject) -> Option<JsonObject> {
        let authentication = obj(body, "authenticationData")?;
        let password_hash = string(authentication, "MasterPasswordAuthenticationHash")?;
        let unlock = to_master_password_unlock(obj(body, "unlockData")?)?;
        let sync = obj(vault, KEY_SYNC)?;
        let user_key = unlock.get("masterKeyEncryptedUserKey").cloned();
        let user_decryption = obj(sync, "userDecryption").cloned().unwrap_or_default();
        let user_decryption = with_fields(
            &user_decryption,
            [("masterPasswordUnlock", Value::Object(unlock))],
        );
        let account = obj(vault, KEY_ACCOUNT).cloned().unwrap_or_default();
        let verifier = create_verifier(&self.platform, password_hash);
        let account = with_fields(&account, [(KEY_PASSWORD_VERIFIER, verifier)]);
        let sync = with_fields(sync, [("userDecryption", Value::Object(user_decryption))]);
        let updated = with_fields(
            vault,
            [
                (KEY_ACCOUNT, Value::Object(account)),
                (KEY_SYNC, Value::Object(sync)),
            ],
        );
        let user_key = user_key.unwrap_or(Value::Null);
        let profile = with_fields(&profile(&updated), [("key", user_key)]);
        Some(with_profile(&updated, profile))
    }
}

/// Tells whether the hash of a request is the one of the master password.
pub(crate) fn verify_password(vault: &JsonObject, request: &LocalRequest) -> Outcome {
    let body = request.json_body()?;
    if !is_password_hash(vault, string(&body, "masterPasswordHash")) {
        return Ok(bad_request(INVALID_PASSWORD_MESSAGE));
    }
    Ok(ok_response(&json!({"object": "masterPasswordPolicy"})))
}

/// Returns `true` if the hash is the one that the master password of the vault is recognized
/// by.
pub(crate) fn is_password_hash(vault: &JsonObject, password_hash: Option<&str>) -> bool {
    password_hash.is_some_and(|hash| matches_verifier(password_verifier(vault), hash))
}

/// What the master password of the account is recognized by.
pub(crate) fn password_verifier(vault: &JsonObject) -> Option<&JsonObject> {
    let account = obj(vault, KEY_ACCOUNT)?;
    obj(account, KEY_PASSWORD_VERIFIER)
}

/// The profile of the account that the vault belongs to.
pub(crate) fn profile(vault: &JsonObject) -> JsonObject {
    let profile = obj(vault, KEY_SYNC).and_then(|sync| obj(sync, "profile"));
    profile.cloned().unwrap_or_default()
}

/// Returns the vault with the profile as the profile of its account.
pub(crate) fn with_profile(vault: &JsonObject, profile: JsonObject) -> JsonObject {
    let sync = obj(vault, KEY_SYNC).cloned().unwrap_or_default();
    let sync = with_fields(&sync, [("profile", Value::Object(profile))]);
    with_fields(vault, [(KEY_SYNC, Value::Object(sync))])
}

/// The data that the user key of the vault is unlocked with: the salt and the parameters that
/// the master key is derived with, and the user key encrypted with that master key.
pub(crate) fn master_password_unlock(vault: &JsonObject) -> Option<&JsonObject> {
    obj(user_decryption(vault)?, "masterPasswordUnlock")
}

/// The settings that the master key of the vault is derived with.
fn kdf_of(vault: &JsonObject) -> Option<&JsonObject> {
    obj(master_password_unlock(vault)?, "kdf")
}

/// Returns `true` if the master keys of both vaults are derived with the same settings.
fn has_same_kdf(vault: &JsonObject, other: &JsonObject) -> bool {
    match (kdf_of(vault), kdf_of(other)) {
        (Some(kdf), Some(other_kdf)) => is_same_kdf(kdf, other_kdf),
        _ => false,
    }
}

/// What the vault has about how its user key is unlocked.
fn user_decryption(vault: &JsonObject) -> Option<&JsonObject> {
    obj(obj(vault, KEY_SYNC)?, "userDecryption")
}

/// Returns the ID of the user key of the account that the vault belongs to, or `None` if no
/// client has had it recorded.
pub(crate) fn recorded_user_key_id(vault: &JsonObject) -> Option<&str> {
    let user_key_id = string(user_decryption(vault)?, "userKeyId");
    user_key_id.filter(|id| !is_blank(id))
}

/// Converts the unlock data of a request to the form that the server returns it in, and that it
/// is stored in. Returns `None` if any of it is missing.
pub(crate) fn to_master_password_unlock(data: &JsonObject) -> Option<JsonObject> {
    let salt = string(data, "salt")?;
    let kdf = obj(data, "kdf")?;
    let kdf_type = int(kdf, "kdfType")?;
    let iterations = int(kdf, "iterations")?;
    let user_key = string(data, "masterKeyWrappedUserKey")
        .or_else(|| string(data, "masterKeyEncryptedUserKey"))?;
    let unlock = json!({
        "salt": salt,
        "kdf": {
            "kdfType": kdf_type,
            "iterations": iterations,
            "memory": int_or_null(Some(kdf), "memory"),
            "parallelism": int_or_null(Some(kdf), "parallelism"),
        },
        "masterKeyEncryptedUserKey": user_key,
    });
    Some(into_object(unlock))
}
