//! Registering, signing in and the settings of an account.

#![allow(clippy::unwrap_used, clippy::indexing_slicing)]

mod common;

use common::*;
use local_vault::{ClientKind, MemoryFileSystem};
use serde_json::{Value, json};

const REGISTER: &str = "accounts/register/finish";
const OTHER_HASH: &str = "b3RoZXItaGFzaA==";
const NEW_HASH: &str = "bmV3LWhhc2g=";
const WRONG_HASH: &str = "d3Jvbmc=";
const USER_KEY_ID: &str = "1b8c188c823891f64b2cb36afc678d21";
const OTHER_KEY_ID: &str = "b16642850e9a7bd0fe6658f98e8dfdf1";

fn browser() -> (Client<MemoryFileSystem>, MemoryFileSystem) {
    Client::in_memory(ClientKind::Browser)
}

/// The body of a request that gives the account of [`EMAIL`] a new master key, derived with the
/// settings: it proves the master password with [`PASSWORD_HASH`], and the master password is
/// known by [`NEW_HASH`] after it.
fn new_master_key(kdf: &Value) -> Value {
    json!({
        "masterPasswordHash": PASSWORD_HASH,
        "authenticationData": {
            "salt": EMAIL,
            "kdf": kdf,
            "masterPasswordAuthenticationHash": NEW_HASH,
        },
        "unlockData": {"salt": EMAIL, "kdf": kdf, "masterKeyWrappedUserKey": "2.newUserKey"},
    })
}

#[test]
fn an_account_is_registered_and_logs_in_with_its_master_password() {
    let (client, fs) = browser();
    let start = json!({"email": " User@Example.com ", "name": "User"});
    let path = "accounts/register/send-verification-email";
    let verification = client.send_anonymous("POST", path, start);
    assert_eq!(verification.code, 200);
    let token = body(&verification);

    let mut registration = registration(EMAIL, PASSWORD_HASH);
    registration["emailVerificationToken"] = token;
    let registered = client.send_anonymous("POST", REGISTER, registration);
    assert_eq!(body(&registered), json!({"object": "register"}));

    let login = client.log_in("USER@example.com", PASSWORD_HASH);
    assert_eq!(login.code, 200);
    let login = body(&login);
    let user_id = user_id_of(login["access_token"].as_str().unwrap());
    assert_eq!(login["token_type"], "Bearer");
    assert_eq!(login["refresh_token"], format!("local-refresh.{user_id}"));
    assert_eq!(login["Key"], USER_KEY);
    assert_eq!(login["PrivateKey"], "2.privateKey");
    assert_eq!(login["Kdf"], 0);
    assert_eq!(login["KdfIterations"], 600_000);
    assert_eq!(login["KdfMemory"], json!(null));
    assert_eq!(login["ForcePasswordReset"], false);
    let unlock = json!({
        "salt": EMAIL,
        "kdf": {"kdfType": 0, "iterations": 600000, "memory": null, "parallelism": null},
        "masterKeyEncryptedUserKey": USER_KEY,
    });
    let options = &login["UserDecryptionOptions"];
    assert_eq!(options["hasMasterPassword"], true);
    assert_eq!(options["masterPasswordUnlock"], unlock);

    let claims = claims_of(login["access_token"].as_str().unwrap());
    assert_eq!(claims["sub"], user_id.as_str());
    assert_eq!(claims["email"], EMAIL);
    assert_eq!(claims["email_verified"], true);
    assert_eq!(claims["name"], "User");
    assert_eq!(claims["premium"], true);
    assert_eq!(claims["client_id"], "browser");
    assert!(claims["exp"].as_i64().unwrap() > NOON / 1000);

    let vault = vault_file(&fs, &user_id);
    assert_eq!(vault["format"], "bitwarden-local-vault");
    assert_eq!(vault["version"], 2);
    assert_eq!(vault["revisionDate"], "2026-10-11T12:00:00.000Z");
    let verifier = &vault["account"]["masterPasswordVerifier"];
    assert_eq!(verifier["algorithm"], "PBKDF2-SHA256");
    assert_eq!(verifier["iterations"], 100_000);
    assert!(!vault.to_string().contains(PASSWORD_HASH));
}

#[test]
fn an_email_that_has_an_account_is_not_registered_again() {
    let (client, fs) = browser();
    client.register();
    let files = fs.paths();

    let path = "accounts/register/send-verification-email";
    let verification = client.send_anonymous("POST", path, json!({"email": EMAIL}));
    let registration = registration(EMAIL, PASSWORD_HASH);
    let registered = client.send_anonymous("POST", REGISTER, registration);

    assert_eq!(verification.code, 400);
    assert_eq!(registered.code, 400);
    let taken = format!("Email '{EMAIL}' is already taken.");
    assert_eq!(message(&registered), taken);
    assert_eq!(fs.paths(), files);
}

#[test]
fn an_account_is_not_registered_without_its_keys() {
    let (client, fs) = browser();
    let mut registration = registration(EMAIL, PASSWORD_HASH);
    let fields = registration.as_object_mut().unwrap();
    fields.remove("masterPasswordUnlock");

    let response = client.send_anonymous("POST", REGISTER, registration);

    assert_eq!(response.code, 400);
    assert_eq!(message(&response), "The registration is not complete.");
    assert!(fs.paths().is_empty());
}

#[test]
fn an_account_is_not_registered_with_kdf_settings_that_the_bitwarden_server_refuses() {
    let (client, fs) = browser();
    let kdf = json!({"kdfType": 1, "iterations": 3, "memory": 14, "parallelism": 4});
    let mut registration = registration(EMAIL, PASSWORD_HASH);
    registration["masterPasswordAuthentication"]["kdf"] = kdf.clone();
    registration["masterPasswordUnlock"]["kdf"] = kdf;

    let response = client.send_anonymous("POST", REGISTER, registration);

    assert_eq!(response.code, 400);
    let refused = "Argon2 memory must be between 15mb and 1024mb.";
    assert_eq!(message(&response), refused);
    assert!(fs.paths().is_empty());
}

#[test]
fn a_wrong_master_password_or_an_unknown_email_does_not_log_in() {
    let (client, _) = browser();
    client.register();

    let wrong_password = client.log_in(EMAIL, WRONG_HASH);
    let unknown_email = client.log_in("nobody@example.com", PASSWORD_HASH);

    for response in [wrong_password, unknown_email] {
        assert_eq!(response.code, 400);
        let body = body(&response);
        assert_eq!(body["error"], "invalid_grant");
        let message = "Username or password is incorrect. Try again.";
        assert_eq!(body["ErrorModel"]["Message"], message);
    }
}

#[test]
fn two_accounts_with_the_same_email_are_told_apart_by_their_master_passwords() {
    let (client, fs) = browser();
    let (_, user_id) = client.register_and_log_in();
    let other = registration("other@example.com", OTHER_HASH);
    client.send_anonymous("POST", REGISTER, other);
    let other_login = body(&client.log_in("other@example.com", OTHER_HASH));
    let other_id = logged_in_id(&other_login);
    // What registering again makes, in a vault folder that the first account is not in yet.
    let mut other_vault = vault_file(&fs, &other_id);
    other_vault["sync"]["profile"]["email"] = json!(EMAIL);
    replace_vault_file(&fs, &other_id, &other_vault);

    let first = body(&client.log_in(EMAIL, PASSWORD_HASH));
    let second = body(&client.log_in(EMAIL, OTHER_HASH));
    let neither = client.log_in(EMAIL, WRONG_HASH);

    assert_eq!(logged_in_id(&first), user_id);
    assert_eq!(logged_in_id(&second), other_id);
    assert_eq!(neither.code, 400);
}

#[test]
fn only_a_master_password_signs_in() {
    let (client, _) = browser();
    let form = [("grant_type", "client_credentials")];

    let response = client.request("POST", "connect/token").form(&form).send();

    assert_eq!(response.code, 400);
    assert_eq!(body(&response)["error"], "invalid_grant");
}

#[test]
fn the_kdf_of_an_account_is_told_before_it_logs_in_and_the_default_for_any_other_email() {
    let (client, _) = browser();
    let mut registration = registration(EMAIL, PASSWORD_HASH);
    let kdf = json!({"kdfType": 1, "iterations": 3, "memory": 64, "parallelism": 4});
    registration["masterPasswordUnlock"]["kdf"] = kdf.clone();
    client.send_anonymous("POST", REGISTER, registration);

    let known = json!({"email": EMAIL});
    let path = "accounts/prelogin/password";
    let known = client.send_anonymous("POST", path, known);
    let unknown = json!({"email": "Nobody@example.com"});
    let unknown = client.send_anonymous("POST", "accounts/prelogin", unknown);

    let known_kdf = json!({
        "kdf": 1,
        "kdfIterations": 3,
        "kdfMemory": 64,
        "kdfParallelism": 4,
        "kdfSettings": kdf,
        "salt": EMAIL,
    });
    let default_kdf = json!({
        "kdf": 0,
        "kdfIterations": 600000,
        "kdfMemory": null,
        "kdfParallelism": null,
        "kdfSettings": {"kdfType": 0, "iterations": 600000, "memory": null, "parallelism": null},
        "salt": "nobody@example.com",
    });
    assert_eq!(body(&known), known_kdf);
    assert_eq!(body(&unknown), default_kdf);
}

#[test]
fn a_refresh_token_renews_the_tokens_of_its_account() {
    let (client, _) = browser();
    let (_, user_id) = client.register_and_log_in();
    let refresh_token = format!("local-refresh.{user_id}");
    let form = [
        ("grant_type", "refresh_token"),
        ("refresh_token", refresh_token.as_str()),
    ];

    let response = client.request("POST", "connect/token").form(&form).send();

    assert_eq!(response.code, 200);
    let tokens = body(&response);
    assert_eq!(logged_in_id(&tokens), user_id);
    assert_eq!(tokens["refresh_token"], refresh_token.as_str());
}

#[test]
fn a_refresh_token_that_was_not_handed_out_is_rejected() {
    let (client, _) = browser();
    client.register_and_log_in();

    for refresh_token in ["local-refresh.unknown", "other", "local-refresh.../x"] {
        let form = [
            ("grant_type", "refresh_token"),
            ("refresh_token", refresh_token),
        ];
        let response = client.request("POST", "connect/token").form(&form).send();

        assert_eq!(response.code, 400);
        assert_eq!(body(&response), json!({"error": "invalid_grant"}));
    }
}

#[test]
fn a_request_without_the_token_of_an_account_is_not_authorized() {
    let (client, _) = browser();
    client.register_and_log_in();
    // A token of the same shape, for an account that the vault folder does not have.
    let stranger = token_for(UNKNOWN_ID);

    assert_eq!(client.request("GET", "sync").send().code, 401);
    for token in ["not-a-token", "not.a.token", stranger.as_str()] {
        assert_eq!(client.get("sync", token).code, 401);
    }
}

#[test]
fn changing_the_master_password_replaces_what_the_account_logs_in_with() {
    let (client, fs) = browser();
    let (token, user_id) = client.register_and_log_in();
    let old_stamp = vault_file(&fs, &user_id)["sync"]["profile"]["securityStamp"].clone();
    let change = json!({
        "masterPasswordHash": PASSWORD_HASH,
        "masterPasswordHint": "new hint",
        "authenticationData": {
            "salt": EMAIL,
            "kdf": {"kdfType": 0, "iterations": 600000},
            "masterPasswordAuthenticationHash": NEW_HASH,
        },
        "unlockData": {
            "salt": EMAIL,
            "kdf": {"kdfType": 0, "iterations": 600000},
            "masterKeyWrappedUserKey": "2.newUserKey",
        },
    });
    let mut wrong = change.clone();
    wrong["masterPasswordHash"] = json!(WRONG_HASH);

    let refused = client.send("POST", "accounts/password", &token, wrong);
    let changed = client.send("POST", "accounts/password", &token, change);

    assert_eq!(refused.code, 400);
    assert_eq!(changed.code, 200);
    assert_eq!(client.log_in(EMAIL, PASSWORD_HASH).code, 400);
    assert_eq!(client.log_in(EMAIL, NEW_HASH).code, 200);
    let sync = &vault_file(&fs, &user_id)["sync"];
    assert_eq!(sync["profile"]["key"], "2.newUserKey");
    assert_eq!(sync["profile"]["masterPasswordHint"], "new hint");
    assert_ne!(sync["profile"]["securityStamp"], old_stamp);
    let unlock = &sync["userDecryption"]["masterPasswordUnlock"];
    assert_eq!(unlock["masterKeyEncryptedUserKey"], "2.newUserKey");
}

#[test]
fn the_master_password_is_not_changed_with_other_kdf_settings() {
    let (client, fs) = browser();
    let (token, user_id) = client.register_and_log_in();
    let vault = vault_file(&fs, &user_id);
    // Settings that a change of the settings takes.
    let kdf = json!({"kdfType": 1, "iterations": 3, "memory": 64, "parallelism": 4});

    let response = client.send("POST", "accounts/password", &token, new_master_key(&kdf));

    assert_eq!(response.code, 400);
    let refused = "The KDF settings cannot be changed with the master password.";
    assert_eq!(message(&response), refused);
    assert_eq!(vault_file(&fs, &user_id), vault);
    assert_eq!(client.log_in(EMAIL, PASSWORD_HASH).code, 200);
}

#[test]
fn changing_the_kdf_replaces_what_the_master_key_is_derived_with() {
    let (client, fs) = browser();
    let (token, user_id) = client.register_and_log_in();
    let stamp = vault_file(&fs, &user_id)["sync"]["profile"]["securityStamp"].clone();
    let kdf = json!({"kdfType": 1, "iterations": 3, "memory": 64, "parallelism": 4});

    let response = client.send("POST", "accounts/kdf", &token, new_master_key(&kdf));

    assert_eq!(response.code, 200);
    let login = body(&client.log_in(EMAIL, NEW_HASH));
    assert_eq!(login["Kdf"], 1);
    assert_eq!(login["KdfIterations"], 3);
    let unlock = &login["UserDecryptionOptions"]["masterPasswordUnlock"];
    assert_eq!(unlock["kdf"], kdf);
    let sync = &vault_file(&fs, &user_id)["sync"];
    assert_eq!(sync["userDecryption"]["masterPasswordUnlock"]["kdf"], kdf);
    assert_eq!(sync["profile"]["securityStamp"], stamp);
}

#[test]
fn the_kdf_is_not_changed_to_settings_that_the_bitwarden_server_refuses() {
    let (client, fs) = browser();
    let (token, user_id) = client.register_and_log_in();
    let vault = vault_file(&fs, &user_id);
    let weak = new_master_key(&json!({"kdfType": 0, "iterations": 100_000}));
    let other_kdf = new_master_key(&json!({"kdfType": 2, "iterations": 600_000}));

    let weak = client.send("POST", "accounts/kdf", &token, weak);
    let other_kdf = client.send("POST", "accounts/kdf", &token, other_kdf);

    assert_eq!(weak.code, 400);
    let too_few = "KDF iterations must be between 600000 and 2000000.";
    assert_eq!(message(&weak), too_few);
    assert_eq!(other_kdf.code, 400);
    let unknown = "KDF type must be 0 (PBKDF2-SHA256) or 1 (Argon2id).";
    assert_eq!(message(&other_kdf), unknown);
    assert_eq!(vault_file(&fs, &user_id), vault);
    assert_eq!(client.log_in(EMAIL, PASSWORD_HASH).code, 200);
}

#[test]
fn the_password_hint_is_the_message_of_an_error_that_the_client_shows() {
    for (kind, code) in [(ClientKind::Browser, 400), (ClientKind::Android, 429)] {
        let (client, _) = Client::in_memory(kind);
        client.register();

        let path = "accounts/password-hint";
        let known = client.send_anonymous("POST", path, json!({"email": EMAIL}));
        let unknown = json!({"email": "nobody@example.com"});
        let unknown = client.send_anonymous("POST", path, unknown);

        assert_eq!(known.code, code);
        assert_eq!(unknown.code, code);
        assert_eq!(message(&known), "Your master password hint: hint");
        let no_hint = "There is no master password hint for this email.";
        assert_eq!(message(&unknown), no_hint);
    }
}

#[test]
fn the_id_of_the_user_key_is_recorded_once_for_the_next_sync() {
    let (client, fs) = browser();
    let (token, user_id) = client.register_and_log_in();
    let record = |user_key_id: &str| {
        let body = json!({"userKeyId": user_key_id});
        let path = "accounts/key-management/user-key-id";
        client.send("POST", path, &token, body)
    };

    let recorded = record(USER_KEY_ID);
    let same = record(&USER_KEY_ID.to_uppercase());
    // A client that has another key than the one of the vault.
    let other = record(OTHER_KEY_ID);
    let invalid = record(" ");

    assert_eq!(recorded.code, 200);
    assert_eq!(same.code, 200);
    assert_eq!(other.code, 400);
    assert_eq!(invalid.code, 400);
    let sync = body(&client.get("sync", &token));
    let decryption = &sync["userDecryption"];
    assert_eq!(decryption["userKeyId"], USER_KEY_ID);
    assert_eq!(decryption["masterPasswordUnlock"]["salt"], EMAIL);
    let stored = vault_file(&fs, &user_id);
    assert_eq!(stored["sync"]["userDecryption"], sync["userDecryption"]);
}

#[test]
fn the_master_password_is_verified() {
    let (client, _) = browser();
    let (token, _) = client.register_and_log_in();
    let verify = |hash: &str| {
        let body = json!({"masterPasswordHash": hash});
        let path = "accounts/verify-password";
        client.send("POST", path, &token, body)
    };

    assert_eq!(verify(PASSWORD_HASH).code, 200);
    assert_eq!(verify(WRONG_HASH).code, 400);
}

#[test]
fn deleting_the_account_removes_its_vault_and_attachments() {
    let (client, fs) = browser();
    let (token, user_id) = client.register_and_log_in();
    let cipher = body(&client.send("POST", "ciphers", &token, json!({})));
    let path = format!("ciphers/{}/attachment/v2", cipher["id"].as_str().unwrap());
    let upload = body(&client.send("POST", &path, &token, json!({})));
    let content_path = path_of(upload["url"].as_str().unwrap());
    client.request("PUT", &content_path).bytes(&[1]).send();
    // The copy that a tool that syncs the folder keeps of a `vault.json` that it had two versions
    // of, with the whole vault in it.
    let vault = vault_file(&fs, &user_id).to_string();
    let conflict = "vault.sync-conflict-20261016-143107-ABCDEFG.json";
    fs.put(&[user_id.as_str(), conflict], vault);
    let delete = |hash: &str| {
        let body = json!({"MasterPasswordHash": hash});
        client.send("DELETE", "accounts", &token, body)
    };

    assert_eq!(delete(WRONG_HASH).code, 400);
    assert!(fs.paths().iter().any(|path| path[0] == user_id));
    assert_eq!(delete(PASSWORD_HASH).code, 200);

    // Only that the account was deleted is left of it.
    let root = [user_id.as_str(), "vault.json"];
    assert_eq!(fs.paths(), [root]);
    assert_eq!(fs.directories(), [[user_id.as_str()]]);
    assert!(client.platform.logs().is_empty());
    let deleted = json!({"format": "bitwarden-local-vault-deleted"});
    assert_eq!(read_json(&fs, &root), deleted);
    assert_eq!(client.get("sync", &token).code, 401);
    assert_eq!(client.log_in(EMAIL, PASSWORD_HASH).code, 400);
    client.register();
}
