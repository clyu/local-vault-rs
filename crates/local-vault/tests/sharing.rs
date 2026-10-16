//! Sharing a vault folder with other devices and other clients.

#![allow(clippy::unwrap_used, clippy::indexing_slicing)]

mod common;

use common::*;
use local_vault::{ClientKind, MemoryFileSystem};
use serde_json::{Value, json};

fn browser() -> (Client<MemoryFileSystem>, MemoryFileSystem) {
    Client::in_memory(ClientKind::Browser)
}

fn revision_date(client: &Client<MemoryFileSystem>, token: &str) -> Value {
    body(&client.get("accounts/revision-date", token))
}

#[test]
fn the_revision_date_is_now_until_the_vault_that_is_on_disk_has_been_synced() {
    let (client, fs) = browser();
    let (token, user_id) = client.register_and_log_in();
    let two_hours_later = NOON + 120 * MINUTE;
    client.platform.set_now(two_hours_later);

    let before_sync = revision_date(&client, &token);
    client.get("sync", &token);
    let after_sync = revision_date(&client, &token);

    assert_eq!(before_sync, two_hours_later);
    assert_eq!(after_sync, NOON);

    // Another device replaces the file, with a date that is older than the last sync.
    let mut replaced = vault_file(&fs, &user_id);
    replaced["revisionDate"] = json!("2026-10-11T11:00:00.000Z");
    let folder = json!({"id": "folder", "name": "2.name", "object": "folder"});
    replaced["sync"]["folders"]
        .as_array_mut()
        .unwrap()
        .push(folder);
    replace_vault_file(&fs, &user_id, &replaced);

    assert_eq!(revision_date(&client, &token), two_hours_later);
    let folders = body(&client.get("sync", &token))["folders"].clone();
    assert_eq!(folders.as_array().unwrap().len(), 1);
    assert_eq!(revision_date(&client, &token), NOON - 60 * MINUTE);
}

#[test]
fn the_fields_of_a_vault_that_are_not_known_are_kept_as_they_are() {
    let (client, fs) = browser();
    let (token, user_id) = client.register_and_log_in();
    let mut vault = vault_file(&fs, &user_id);
    vault["fromTheFuture"] = json!({"kept": true});
    vault["account"]["other"] = json!(1);
    vault["sync"]["profile"]["newField"] = json!("kept");
    vault["sync"]["newList"] = json!([1]);
    // Numbers as another client may write them, which are kept as they are written.
    let numbers = r#""numbers": [1.0, 1e3, 9007199254740993, 0.10]"#;
    let content = vault.to_string();
    let content = format!("{}, {numbers}}}", &content[..content.len() - 1]);
    let file = device_file(&user_id, DEVICE);
    fs.put(&file, content);

    let folder = json!({"name": "2.folder"});
    client.send("POST", "folders", &token, folder);

    let written = String::from_utf8(fs.get(&file).unwrap()).unwrap();
    assert!(written.contains("1.0"));
    // The exponent is written with its sign, as serde_json writes it.
    assert!(written.contains("1e+3"));
    assert!(written.contains("9007199254740993"));
    assert!(written.contains("0.10"));
    let written: Value = serde_json::from_str(&written).unwrap();
    assert_eq!(written["fromTheFuture"], json!({"kept": true}));
    assert_eq!(written["account"]["other"], 1);
    assert_eq!(written["sync"]["profile"]["newField"], "kept");
    assert_eq!(written["sync"]["newList"], json!([1]));
    assert_eq!(written["sync"]["folders"].as_array().unwrap().len(), 1);
}

#[test]
fn the_vault_is_read_from_its_backup_when_the_vault_file_is_not_complete() {
    let (client, fs) = browser();
    let (token, user_id) = client.register_and_log_in();
    let folder = json!({"name": "2.folder"});
    client.send("POST", "folders", &token, folder);
    let file = device_file(&user_id, DEVICE);
    let backup = [user_id.as_str(), "devices", DEVICE, "vault.json.bak"];
    let complete = fs.get(&file).unwrap();
    assert!(read_json(&fs, &backup).is_object());

    fs.put(&file, &complete[..complete.len() / 2]);

    // The backup is the vault as it was before the folder was added.
    let sync = body(&client.get("sync", &token));
    assert_eq!(sync["folders"], json!([]));
}

#[test]
fn a_vault_of_a_version_that_is_not_known_is_left_alone() {
    let (client, fs) = browser();
    let (token, user_id) = client.register_and_log_in();
    let login = body(&client.log_in(EMAIL, PASSWORD_HASH));
    let refresh_token = login["refresh_token"].as_str().unwrap().to_owned();
    let folder = json!({"name": "2.folder"});
    client.send("POST", "folders", &token, folder);
    let mut newer = vault_file(&fs, &user_id);
    newer["version"] = json!(3);
    let content = newer.to_string();
    let file = device_file(&user_id, DEVICE);
    fs.put(&file, content.clone());

    let sync = client.request("GET", "sync").token(&token).try_send();
    let other = json!({"name": "2.other"});
    let created = client.request("POST", "folders").token(&token).json(other);
    let refresh = [
        ("grant_type", "refresh_token"),
        ("refresh_token", refresh_token.as_str()),
    ];
    let refreshed = client.request("POST", "connect/token").form(&refresh);
    let password = [
        ("grant_type", "password"),
        ("username", EMAIL),
        ("password", PASSWORD_HASH),
    ];
    let logged_in = client.request("POST", "connect/token").form(&password);
    let email = json!({"email": EMAIL});
    let prelogin = client.request("POST", "accounts/prelogin").json(email);
    let registration = registration(EMAIL, PASSWORD_HASH);
    let register = client.request("POST", "accounts/register/finish");
    let registered = register.json(registration).try_send();

    // A newer client wrote it, so the account is not taken to be gone: told so, the client would
    // log it out, derive the master key the default way, take the master password to be wrong,
    // or register the email again. Each fails as a request that did not reach the server until
    // the client is updated. The backup, which holds a vault of a version that is known but an
    // older one, is not read in its place.
    assert!(sync.is_err());
    assert!(created.try_send().is_err());
    assert!(refreshed.try_send().is_err());
    assert!(logged_in.try_send().is_err());
    assert!(prelogin.try_send().is_err());
    assert!(registered.is_err());
    assert_eq!(fs.get(&file).unwrap(), content.as_bytes());
    assert!(fs.paths().iter().all(|path| path[0] == user_id));
}

#[test]
fn a_vault_that_another_client_wrote_with_a_byte_order_mark_is_read() {
    let (client, fs) = browser();
    let (token, user_id) = client.register_and_log_in();
    let content = vault_file(&fs, &user_id).to_string();
    let file = device_file(&user_id, DEVICE);
    fs.put(&file, format!("\u{feff}{content}"));

    let sync = client.get("sync", &token);

    assert_eq!(sync.code, 200);
    assert_eq!(client.log_in(EMAIL, PASSWORD_HASH).code, 200);
}

#[test]
fn a_number_that_is_written_as_a_string_is_not_a_version() {
    let (client, fs) = browser();
    let (token, user_id) = client.register_and_log_in();
    let mut vault = vault_file(&fs, &user_id);
    vault["version"] = json!("2");
    replace_vault_file(&fs, &user_id, &vault);

    // The vault is not used, and not taken to be gone either.
    let sync = client.request("GET", "sync").token(&token);
    assert!(sync.try_send().is_err());
}

#[test]
fn a_date_without_an_offset_does_not_make_an_item_out_of_date() {
    let (client, _) = browser();
    let (token, _) = client.register_and_log_in();
    let cipher = body(&client.send("POST", "ciphers", &token, json!({"type": 1})));
    let path = format!("ciphers/{}", cipher["id"].as_str().unwrap());
    // A date that means another time on every device, which is not taken to mean any.
    let update = json!({"type": 1, "lastKnownRevisionDate": "2026-10-11T01:00:00"});

    let updated = client.send("PUT", &path, &token, update);

    assert_eq!(updated.code, 200);
}
