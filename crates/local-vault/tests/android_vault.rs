//! A vault as the Android app wrote it before the local vault was shared, in the file of the
//! device that took it over: the fixture is what the local vault wrote when it took over a vault
//! with the structure of one that the app created, with every value replaced. The vaults that the
//! earlier implementations wrote are in such files now, which these tests keep readable.
//!
//! The app that created it stored `encryptedFor` with an item, which the app has stopped since.
//! The items of the fixture are without it, as the app writes them now.

#![allow(clippy::unwrap_used, clippy::indexing_slicing)]

mod common;

use common::*;
use local_vault::{ClientKind, MemoryFileSystem};
use serde_json::{Value, json};

const FIXTURE: &str = include_str!("fixtures/android-vault.json");
const USER_ID: &str = "11111111-2222-4333-8444-555555555555";
const ANDROID_EMAIL: &str = "android@example.com";
const ANDROID_HASH: &str = "YW5kcm9pZC1oYXNo";

fn fixture() -> Value {
    serde_json::from_str(FIXTURE).unwrap()
}

/// A client whose device has the file, as the device that took the vault over has.
fn client_with(file: &str) -> (Client<MemoryFileSystem>, MemoryFileSystem) {
    let (client, fs) = Client::in_memory(ClientKind::Browser);
    let marker = json!({"format": "bitwarden-local-vault", "version": 2});
    fs.put(&[USER_ID, "vault.json"], marker.to_string());
    fs.put(&device_file(USER_ID, DEVICE), file);
    (client, fs)
}

fn log_in(client: &Client<MemoryFileSystem>) -> String {
    let response = client.log_in(ANDROID_EMAIL, ANDROID_HASH);
    assert_eq!(response.code, 200);
    body(&response)["access_token"].as_str().unwrap().to_owned()
}

#[test]
fn the_master_password_is_checked_against_the_verifier_of_the_app() {
    let (client, _) = client_with(FIXTURE);

    let right = client.log_in("Android@Example.com", ANDROID_HASH);
    let wrong = client.log_in(ANDROID_EMAIL, &format!("{ANDROID_HASH}="));

    assert_eq!(right.code, 200);
    assert_eq!(wrong.code, 400);
}

#[test]
fn the_account_logs_in_with_what_is_in_the_vault() {
    let (client, _) = client_with(FIXTURE);
    let fixture = fixture();
    let profile = &fixture["sync"]["profile"];

    let login = body(&client.log_in(ANDROID_EMAIL, ANDROID_HASH));

    assert_eq!(logged_in_id(&login), USER_ID);
    assert_eq!(login["Key"], profile["key"]);
    assert_eq!(login["PrivateKey"], profile["privateKey"]);
    assert_eq!(login["AccountKeys"], profile["accountKeys"]);
    assert_eq!(login["Kdf"], 0);
    assert_eq!(login["KdfIterations"], 600_000);
    let unlock = &fixture["sync"]["userDecryption"]["masterPasswordUnlock"];
    let options = &login["UserDecryptionOptions"];
    assert_eq!(&options["masterPasswordUnlock"], unlock);
}

#[test]
fn the_vault_is_returned_as_it_is_when_it_syncs() {
    let (client, _) = client_with(FIXTURE);
    let token = log_in(&client);

    let sync = body(&client.get("sync", &token));

    assert_eq!(sync, fixture()["sync"]);
}

#[test]
fn nothing_changes_but_what_a_request_is_about() {
    let (client, fs) = client_with(FIXTURE);
    let fixture = fixture();
    let token = log_in(&client);
    let note = &fixture["sync"]["ciphers"][1];
    let update = json!({
        "type": 2,
        "name": "2.renamed",
        "notes": note["notes"],
        "secureNote": {"type": 0},
        "fields": [],
        "favorite": true,
        "reprompt": 0,
        "key": note["key"],
        "encryptedFor": USER_ID,
        "lastKnownRevisionDate": note["revisionDate"],
    });
    let path = format!("ciphers/{}", note["id"].as_str().unwrap());

    let updated = client.send("PUT", &path, &token, update);

    assert_eq!(updated.code, 200);
    // The file of the device has a new version of the item, and is otherwise as it was: what the
    // device took over keeps the stamps that it was taken over with. Only `since`, which earlier
    // clients wrote, is left out.
    let mut renamed = note.clone();
    renamed["name"] = json!("2.renamed");
    renamed["favorite"] = json!(true);
    renamed["revisionDate"] = json!("2026-10-11T12:00:00.000Z");
    let mut expected = fixture.clone();
    expected["revisionDate"] = json!("2026-10-11T12:00:00.000Z");
    expected["sync"]["ciphers"][1] = renamed;
    let key = format!("cipher:{}", note["id"].as_str().unwrap().to_lowercase());
    expected["records"][&key] = json!({"at": NOON, "by": DEVICE});
    expected.as_object_mut().unwrap().shift_remove("since");
    assert_eq!(read_json(&fs, &device_file(USER_ID, DEVICE)), expected);
}

#[test]
fn a_new_item_is_stored_with_the_fields_that_the_app_stores_an_item_with() {
    let (client, fs) = client_with(FIXTURE);
    let fixture = fixture();
    let token = log_in(&client);
    let login = fixture["sync"]["ciphers"][0].as_object().unwrap();
    // What the extension sends for the same item, which is more than the app sends.
    let cipher = json!({
        "type": 1,
        "encryptedFor": USER_ID,
        "folderId": null,
        "organizationId": null,
        "name": login["name"],
        "notes": null,
        "favorite": false,
        "lastKnownRevisionDate": null,
        "archivedDate": null,
        "reprompt": 0,
        "key": login["key"],
        "login": login["login"],
        "fields": [],
        "passwordHistory": null,
    });
    let request = json!({"cipher": cipher, "collectionIds": []});

    let created = body(&client.send("POST", "ciphers/create", &token, request));

    let created = created.as_object().unwrap();
    for (key, value) in login {
        // Every field that both have holds the same kind of value.
        let created_value = created.get(key).unwrap();
        assert_eq!(kind(created_value), kind(value), "{key}");
    }
    assert_eq!(created["organizationId"], json!(null));
    assert_eq!(created["collectionIds"], json!([]));
    let permissions = json!({"delete": true, "restore": true});
    assert_eq!(created["permissions"], permissions);
    assert_eq!(created["attachments"], json!(null));
    assert_eq!(created["object"], "cipherDetails");
    assert_eq!(created.get("lastKnownRevisionDate"), None);
    assert_eq!(created.get("encryptedFor"), None);
    let ciphers = &read_json(&fs, &device_file(USER_ID, DEVICE))["sync"]["ciphers"];
    assert_eq!(ciphers.as_array().unwrap().len(), 3);
}

#[test]
fn the_encrypted_for_of_an_earlier_vault_is_kept_until_its_item_is_updated() {
    // Both clients stored it with an item before, and nothing reads it there.
    let fixture = fixture();
    let mut earlier = fixture.clone();
    for cipher in earlier["sync"]["ciphers"].as_array_mut().unwrap() {
        cipher["encryptedFor"] = json!(USER_ID);
    }
    let (client, fs) = client_with(&earlier.to_string());
    let token = log_in(&client);
    let note = &earlier["sync"]["ciphers"][1];
    let update = json!({
        "type": 2,
        "name": note["name"],
        "notes": note["notes"],
        "secureNote": {"type": 0},
        "fields": [],
        "favorite": false,
        "reprompt": 0,
        "key": note["key"],
        "encryptedFor": USER_ID,
        "lastKnownRevisionDate": note["revisionDate"],
    });
    let path = format!("ciphers/{}", note["id"].as_str().unwrap());

    let sync = body(&client.get("sync", &token));
    let updated = client.send("PUT", &path, &token, update);

    assert_eq!(sync, earlier["sync"]);
    assert_eq!(updated.code, 200);
    let written = read_json(&fs, &device_file(USER_ID, DEVICE));
    let ciphers = &written["sync"]["ciphers"];
    assert_eq!(ciphers[0], earlier["sync"]["ciphers"][0]);
    let mut expected = fixture["sync"]["ciphers"][1].clone();
    expected["revisionDate"] = json!("2026-10-11T12:00:00.000Z");
    assert_eq!(ciphers[1], expected);
}

#[test]
fn kdf_settings_that_would_be_refused_now_still_log_in_and_change_the_master_password() {
    // The earlier implementations took any settings.
    let mut earlier = fixture();
    let kdf = json!({"kdfType": 0, "iterations": 5000, "memory": null, "parallelism": null});
    earlier["sync"]["userDecryption"]["masterPasswordUnlock"]["kdf"] = kdf.clone();
    let (client, _) = client_with(&earlier.to_string());
    let email = json!({"email": ANDROID_EMAIL});
    let new_hash = "bmV3LWhhc2g=";
    let change = json!({
        "masterPasswordHash": ANDROID_HASH,
        "authenticationData": {
            "salt": ANDROID_EMAIL,
            "kdf": kdf,
            "masterPasswordAuthenticationHash": new_hash,
        },
        "unlockData": {
            "salt": ANDROID_EMAIL,
            "kdf": kdf,
            "masterKeyWrappedUserKey": "2.newUserKey",
        },
    });

    let prelogin = client.send_anonymous("POST", "accounts/prelogin", email);
    let token = log_in(&client);
    let changed = client.send("POST", "accounts/password", &token, change);

    assert_eq!(body(&prelogin)["kdfSettings"], kdf);
    assert_eq!(changed.code, 200);
    let login = body(&client.log_in(ANDROID_EMAIL, new_hash));
    assert_eq!(login["KdfIterations"], 5000);
}

/// What kind of value a JSON value is.
fn kind(value: &Value) -> &'static str {
    match value {
        Value::Null => "null",
        Value::Bool(_) => "boolean",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}
