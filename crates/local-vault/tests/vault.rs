//! The items, folders and attachments of a vault.

#![allow(clippy::unwrap_used, clippy::indexing_slicing)]

mod common;

use std::sync::atomic::{AtomicBool, Ordering};

use common::*;
use local_vault::{ClientKind, FileSystem, IoError, LocalResponse, MemoryFileSystem};
use serde_json::{Value, json};

const USER_KEY_ID: &str = "1b8c188c823891f64b2cb36afc678d21";
const OTHER_KEY_ID: &str = "b16642850e9a7bd0fe6658f98e8dfdf1";

/// 2026-10-11T12:05:00.000Z, and so on.
const FIVE_PAST: i64 = NOON + 5 * MINUTE;
const TEN_PAST: i64 = NOON + 10 * MINUTE;
const QUARTER_PAST: i64 = NOON + 15 * MINUTE;

fn browser() -> (Client<MemoryFileSystem>, MemoryFileSystem) {
    Client::in_memory(ClientKind::Browser)
}

fn id(value: &Value) -> String {
    value["id"].as_str().unwrap().to_owned()
}

fn names(list: &Value) -> Vec<Value> {
    field_of_each(list, "name")
}

fn field_of_each(list: &Value, key: &str) -> Vec<Value> {
    let field = |item: &Value| item.get(key).cloned().unwrap_or(Value::Null);
    list.as_array().unwrap().iter().map(field).collect()
}

#[test]
fn a_cipher_is_created_updated_trashed_restored_and_deleted() {
    let (client, fs) = browser();
    let (token, user_id) = client.register_and_log_in();
    let cipher = json!({
        "type": 1,
        "name": "2.name",
        "login": {"username": "2.username", "newField": "kept"},
        "lastKnownRevisionDate": null,
        "encryptedFor": user_id,
        "encryptedByKeyId": "key",
    });
    let request = json!({"cipher": cipher, "collectionIds": []});

    let created = body(&client.send("POST", "ciphers/create", &token, request));

    // Without what is about the request and not about the item, which is not stored.
    let expected = json!({
        "type": 1,
        "name": "2.name",
        "login": {"username": "2.username", "newField": "kept"},
        "id": id(&created),
        "organizationId": null,
        "collectionIds": [],
        "edit": true,
        "viewPassword": true,
        "organizationUseTotp": false,
        "permissions": {"delete": true, "restore": true},
        "attachments": null,
        "creationDate": "2026-10-11T12:00:00.000Z",
        "deletedDate": null,
        "revisionDate": "2026-10-11T12:00:00.000Z",
        "object": "cipherDetails",
    });
    assert_eq!(created, expected);
    let cipher_path = format!("ciphers/{}", id(&created));
    assert_eq!(body(&client.get(&cipher_path, &token)), created);
    let details = body(&client.get(&format!("{cipher_path}/details"), &token));
    assert_eq!(details, created);

    client.platform.set_now(FIVE_PAST);
    let stale = json!({"type": 1, "lastKnownRevisionDate": "2026-10-11T11:00:00.000Z"});
    let out_of_date = client.send("PUT", &cipher_path, &token, stale);
    assert_eq!(out_of_date.code, 400);
    assert!(message(&out_of_date).contains("out of date"));

    // Within the second that dates may lose on their way, and with the ID in another case.
    let upper_case_path = cipher_path.to_uppercase().replace("CIPHERS", "ciphers");
    let update = json!({
        "type": 1,
        "name": "2.renamed",
        "lastKnownRevisionDate": "2026-10-11T12:00:00.900Z",
    });
    let updated = body(&client.send("PUT", &upper_case_path, &token, update));
    // The item keeps its ID, in whatever case a request names it.
    assert_eq!(updated["id"], created["id"]);
    assert_eq!(updated["name"], "2.renamed");
    assert_eq!(updated["creationDate"], "2026-10-11T12:00:00.000Z");
    assert_eq!(updated["revisionDate"], "2026-10-11T12:05:00.000Z");

    client.platform.set_now(TEN_PAST);
    let trashed = client.call("PUT", &format!("{cipher_path}/delete"), &token);
    assert_eq!(trashed.json(), None);
    let stored = &vault_file(&fs, &user_id)["sync"]["ciphers"][0];
    assert_eq!(stored["deletedDate"], "2026-10-11T12:10:00.000Z");
    // The client was not sent the item, so the revision date that it knows it by still holds.
    assert_eq!(stored["revisionDate"], "2026-10-11T12:05:00.000Z");

    client.platform.set_now(QUARTER_PAST);
    let restore_path = format!("{cipher_path}/restore");
    let restored = body(&client.call("PUT", &restore_path, &token));
    assert_eq!(restored["deletedDate"], json!(null));
    assert_eq!(restored["revisionDate"], "2026-10-11T12:15:00.000Z");

    let partial_path = format!("{cipher_path}/partial");
    let change = json!({"folderId": "folder", "favorite": true});
    let partial = body(&client.send("PUT", &partial_path, &token, change));
    assert_eq!(partial["folderId"], "folder");
    assert_eq!(partial["favorite"], true);
    assert_eq!(partial["name"], "2.renamed");

    let deleted = client.call("DELETE", &cipher_path, &token);
    assert_eq!(deleted.code, 200);
    assert_eq!(vault_file(&fs, &user_id)["sync"]["ciphers"], json!([]));
    assert_eq!(client.get(&cipher_path, &token).code, 404);
    assert_eq!(client.call("DELETE", &cipher_path, &token).code, 404);
}

#[test]
fn an_item_that_was_encrypted_for_another_account_is_refused() {
    let (client, fs) = browser();
    let (token, user_id) = client.register_and_log_in();
    // The account of the token, in whatever case.
    let mine = json!({"type": 1, "name": "2.mine", "encryptedFor": user_id.to_uppercase()});
    let mine = body(&client.send("POST", "ciphers", &token, mine));
    let item = json!({"type": 1, "name": "2.other", "encryptedFor": UNKNOWN_ID});
    let first = json!({"type": 1, "name": "2.first", "encryptedFor": user_id});
    let import = json!({"ciphers": [first, item], "folders": [{"name": "2.folder"}]});

    let send = |method: &str, path: &str, value: Value| client.send(method, path, &token, value);
    let responses = [
        send("POST", "ciphers", item.clone()),
        send("POST", "ciphers/create", json!({"cipher": item})),
        send("PUT", &format!("ciphers/{}", id(&mine)), item.clone()),
        send("POST", "ciphers/import", import),
    ];

    for response in responses {
        assert_eq!(response.code, 400);
        assert!(message(&response).contains("not encrypted for the account"));
    }
    // Nothing of the import is stored, although only one of its items is for another account.
    let sync = &vault_file(&fs, &user_id)["sync"];
    assert_eq!(names(&sync["ciphers"]), ["2.mine"]);
    assert_eq!(sync["folders"], json!([]));
    // The account that an item was encrypted for is checked, and not stored with the item.
    assert_eq!(mine.get("encryptedFor"), None);
    assert!(!sync.to_string().contains("encryptedFor"));
}

#[test]
fn an_item_that_was_encrypted_with_another_key_than_the_user_key_is_refused() {
    let (client, fs) = browser();
    let (token, user_id) = client.register_and_log_in();
    let item = json!({"type": 1, "name": "2.other", "encryptedByKeyId": OTHER_KEY_ID});
    // Before the ID of the user key is recorded, there is nothing to tell the key by.
    let early = json!({"type": 1, "name": "2.early", "encryptedByKeyId": OTHER_KEY_ID});
    let early = client.send("POST", "ciphers", &token, early);
    let record = json!({"userKeyId": USER_KEY_ID});
    let path = "accounts/key-management/user-key-id";
    client.send("POST", path, &token, record);
    let key_id = USER_KEY_ID.to_uppercase();
    let mine = json!({"type": 1, "name": "2.mine", "encryptedByKeyId": key_id});
    let mine = body(&client.send("POST", "ciphers", &token, mine));
    // What a client sends that does not know of the IDs of keys.
    let without = json!({"type": 1, "name": "2.old"});
    let without = client.send("POST", "ciphers", &token, without);
    let first = json!({"type": 1, "name": "2.first", "encryptedByKeyId": USER_KEY_ID});
    let import = json!({"ciphers": [first, item], "folders": [{"name": "2.folder"}]});

    let send = |method: &str, path: &str, value: Value| client.send(method, path, &token, value);
    let responses = [
        send("POST", "ciphers", item.clone()),
        send("POST", "ciphers/create", json!({"cipher": item})),
        send("PUT", &format!("ciphers/{}", id(&mine)), item.clone()),
        send("POST", "ciphers/import", import),
    ];

    assert_eq!(early.code, 200);
    assert_eq!(without.code, 200);
    for response in responses {
        assert_eq!(response.code, 400);
        let message = message(&response);
        assert!(message.contains("not encrypted with the user key"));
    }
    let sync = &vault_file(&fs, &user_id)["sync"];
    assert_eq!(names(&sync["ciphers"]), ["2.early", "2.mine", "2.old"]);
    assert_eq!(sync["folders"], json!([]));
    // The ID is about the request, and is not stored with the item.
    assert!(!sync["ciphers"].to_string().contains("encryptedByKeyId"));
}

#[test]
fn several_ciphers_are_changed_at_once() {
    let (client, fs) = browser();
    let (token, user_id) = client.register_and_log_in();
    let mut ids = Vec::new();
    for name in ["a", "b", "c"] {
        let cipher = json!({"type": 2, "name": name});
        ids.push(id(&body(&client.send("POST", "ciphers", &token, cipher))));
    }
    let [first, second, third] = [&ids[0], &ids[1], &ids[2]];
    let ciphers = || vault_file(&fs, &user_id)["sync"]["ciphers"].clone();
    client.platform.set_now(NOON + 60 * MINUTE);
    let at_one = json!("2026-10-11T13:00:00.000Z");

    let moved = json!({"ids": [first, second], "folderId": "f"});
    client.send("PUT", "ciphers/move", &token, moved);
    let folder_ids = field_of_each(&ciphers(), "folderId");
    assert_eq!(folder_ids, [json!("f"), json!("f"), Value::Null]);

    let trashed = json!({"ids": [first, second]});
    client.send("PUT", "ciphers/delete", &token, trashed);
    let deleted_dates = field_of_each(&ciphers(), "deletedDate");
    assert_eq!(deleted_dates, [at_one.clone(), at_one.clone(), Value::Null]);

    let restored = json!({"ids": [first]});
    let restored = body(&client.send("PUT", "ciphers/restore", &token, restored));
    assert_eq!(restored["object"], "list");
    assert_eq!(field_of_each(&restored["data"], "id"), [first.as_str()]);
    let deleted_dates = field_of_each(&restored["data"], "deletedDate");
    assert_eq!(deleted_dates, [Value::Null]);

    let archived = json!({"ids": [first, third]});
    let archived = body(&client.send("PUT", "ciphers/archive", &token, archived));
    let archived_dates = field_of_each(&archived["data"], "archivedDate");
    assert_eq!(archived_dates, [at_one.clone(), at_one]);
    let unarchived = json!({"ids": [third]});
    let unarchived = body(&client.send("PUT", "ciphers/unarchive", &token, unarchived));
    assert_eq!(field_of_each(&unarchived["data"], "id"), [third.as_str()]);
    let archived_dates = field_of_each(&unarchived["data"], "archivedDate");
    assert_eq!(archived_dates, [Value::Null]);

    let deleted = json!({"ids": [second, third, "unknown"]});
    client.send("DELETE", "ciphers", &token, deleted);
    assert_eq!(field_of_each(&ciphers(), "id"), [first.as_str()]);
}

#[test]
fn a_cipher_is_archived_and_unarchived() {
    let (client, _) = browser();
    let (token, _) = client.register_and_log_in();
    let cipher = body(&client.send("POST", "ciphers", &token, json!({"type": 1})));
    client.platform.set_now(NOON + 60 * MINUTE);
    let path = format!("ciphers/{}", id(&cipher));

    let archived = client.call("PUT", &format!("{path}/archive"), &token);
    let unarchived = client.call("PUT", &format!("{path}/unarchive"), &token);
    let unknown = format!("ciphers/{UNKNOWN_ID}/archive");
    let unknown = client.call("PUT", &unknown, &token);

    let archived = body(&archived);
    assert_eq!(archived["archivedDate"], "2026-10-11T13:00:00.000Z");
    assert_eq!(archived["revisionDate"], "2026-10-11T13:00:00.000Z");
    assert_eq!(body(&unarchived)["archivedDate"], json!(null));
    assert_eq!(unknown.code, 404);
}

#[test]
fn a_folder_is_created_renamed_and_deleted_along_with_the_references_to_it() {
    let (client, fs) = browser();
    let (token, user_id) = client.register_and_log_in();
    let folder = json!({"name": "2.folder"});
    let folder = body(&client.send("POST", "folders", &token, folder));
    let expected = json!({
        "id": id(&folder),
        "name": "2.folder",
        "revisionDate": "2026-10-11T12:00:00.000Z",
        "object": "folder",
    });
    assert_eq!(folder, expected);
    let in_folder = json!({"type": 1, "folderId": id(&folder)});
    client.send("POST", "ciphers", &token, in_folder);
    let in_other = json!({"type": 1, "folderId": "other"});
    client.send("POST", "ciphers", &token, in_other);

    client.platform.set_now(NOON + 30 * MINUTE);
    let path = format!("folders/{}", id(&folder));
    let upper_case_path = format!("folders/{}", id(&folder).to_uppercase());
    let rename = json!({"name": "2.renamed"});
    let renamed = body(&client.send("PUT", &upper_case_path, &token, rename));
    // The folder keeps its ID, in whatever case a request names it.
    assert_eq!(renamed["id"], folder["id"]);
    assert_eq!(renamed["name"], "2.renamed");
    assert_eq!(renamed["revisionDate"], "2026-10-11T12:30:00.000Z");
    assert_eq!(body(&client.get(&path, &token)), renamed);

    let deleted = client.call("DELETE", &path, &token);

    assert_eq!(deleted.code, 200);
    let sync = body(&client.get("sync", &token));
    assert_eq!(sync["folders"], json!([]));
    let folder_ids = field_of_each(&sync["ciphers"], "folderId");
    assert_eq!(folder_ids, [Value::Null, json!("other")]);
    assert_eq!(client.get(&path, &token).code, 404);
    // The items themselves are not changed, so that a change of one of them on another device is
    // not lost to the deletion: the one in the folder is in none as the folder was deleted.
    let file = &vault_file(&fs, &user_id)["sync"];
    assert_eq!(file["folders"], json!([]));
    let folder_ids = field_of_each(&file["ciphers"], "folderId");
    assert_eq!(folder_ids, [folder["id"].clone(), json!("other")]);
}

#[test]
fn several_folders_are_deleted_at_once() {
    let (client, fs) = browser();
    let (token, user_id) = client.register_and_log_in();
    let mut ids = Vec::new();
    for name in ["a", "b", "c"] {
        let folder = json!({"name": name});
        ids.push(id(&body(&client.send("POST", "folders", &token, folder))));
    }
    let in_folder = json!({"type": 1, "folderId": ids[2]});
    client.send("POST", "ciphers", &token, in_folder);
    let sync = || body(&client.get("sync", &token));

    let deleted = json!({"ids": [ids[0]]});
    client.send("DELETE", "folders", &token, deleted);
    let remaining = [ids[1].as_str(), ids[2].as_str()];
    assert_eq!(field_of_each(&sync()["folders"], "id"), remaining);

    client.call("DELETE", "folders/all", &token);
    assert_eq!(sync()["folders"], json!([]));
    assert_eq!(sync()["ciphers"][0]["folderId"], json!(null));
    // The item itself is not changed: it is in no folder as its folder was deleted.
    let file = vault_file(&fs, &user_id);
    assert_eq!(file["sync"]["ciphers"][0]["folderId"], json!(ids[2]));
}

#[test]
fn an_attachment_is_created_uploaded_downloaded_and_deleted() {
    let (client, fs) = browser();
    let (token, user_id) = client.register_and_log_in();
    let cipher = body(&client.send("POST", "ciphers", &token, json!({"type": 1})));
    let cipher_id = id(&cipher);
    let content = [1, 2, 3, 250];
    client.platform.set_now(NOON + 30 * MINUTE);
    let new_attachment = json!({
        "fileName": "2.fileName",
        "key": "2.key",
        "fileSize": 2048,
        "adminRequest": false,
    });

    let path = format!("ciphers/{cipher_id}/attachment/v2");
    let upload = body(&client.send("POST", &path, &token, new_attachment));

    let attachment_id = upload["attachmentId"].as_str().unwrap().to_owned();
    assert_eq!(attachment_id.len(), 32);
    assert!(attachment_id.bytes().all(|b| b.is_ascii_hexdigit()));
    let content_path = format!("attachments/{user_id}/{cipher_id}/{attachment_id}");
    let url = format!("https://vault.local.invalid/{content_path}");
    assert_eq!(upload["url"], url.as_str());
    assert_eq!(upload["fileUploadType"], 1);
    assert_eq!(upload["object"], "attachment-fileUpload");
    let cipher_response = &upload["cipherResponse"];
    assert_eq!(cipher_response["id"], cipher_id.as_str());
    assert_eq!(cipher_response["revisionDate"], "2026-10-11T12:30:00.000Z");
    let expected = json!([{
        "id": attachment_id,
        "url": null,
        "fileName": "2.fileName",
        "key": "2.key",
        "size": "2048",
        "sizeName": "2.00 KB",
        "object": "attachment",
    }]);
    assert_eq!(cipher_response["attachments"], expected);

    let uploaded = client.request("PUT", &content_path).bytes(&content).send();
    assert_eq!(uploaded.code, 201);
    let file = [
        user_id.as_str(),
        "attachments",
        cipher_id.as_str(),
        attachment_id.as_str(),
    ];
    assert_eq!(fs.get(&file).unwrap(), content);

    let attachment_path = format!("ciphers/{cipher_id}/attachment/{attachment_id}");
    let attachment = body(&client.get(&attachment_path, &token));
    assert_eq!(attachment["id"], attachment_id.as_str());
    assert_eq!(attachment["url"], url.as_str());
    assert_eq!(attachment["fileName"], "2.fileName");
    // The content is where it was stored, in whatever case a request names the item.
    let upper_case_id = cipher_id.to_uppercase();
    let upper_case = format!("ciphers/{upper_case_id}/attachment/{attachment_id}");
    assert_eq!(body(&client.get(&upper_case, &token))["url"], url.as_str());
    // The address does not expire, so a client that asks for it again gets the same one.
    let renewed = body(&client.get(&format!("{attachment_path}/renew"), &token));
    assert_eq!(renewed["attachmentId"], attachment_id.as_str());
    assert_eq!(renewed["url"], url.as_str());
    assert_eq!(renewed["cipherResponse"]["id"], cipher_id.as_str());
    let unknown = format!("ciphers/{cipher_id}/attachment/unknown/renew");
    assert_eq!(client.get(&unknown, &token).code, 404);
    assert_eq!(client.download(&content_path).unwrap(), content);

    // An update of the item keeps its attachments, with what the client re-encrypted of them.
    let update = json!({
        "type": 1,
        "attachments": {attachment_id.as_str(): "2.newFileName"},
        "attachments2": {attachment_id.as_str(): {"fileName": "2.newFileName", "key": null}},
    });
    let cipher_path = format!("ciphers/{cipher_id}");
    let updated = body(&client.send("PUT", &cipher_path, &token, update));
    assert_eq!(updated["attachments"][0]["id"], attachment_id.as_str());
    assert_eq!(updated["attachments"][0]["fileName"], "2.newFileName");
    assert_eq!(updated["attachments"][0]["key"], "2.key");
    assert_eq!(updated.get("attachments2"), None);

    client.platform.set_now(NOON + 45 * MINUTE);
    let deleted = body(&client.call("DELETE", &attachment_path, &token));
    assert_eq!(deleted["cipher"]["id"], cipher_id.as_str());
    assert_eq!(deleted["cipher"]["attachments"], json!(null));
    // The revision date stays, which the Android app counts on: it is not sent the item.
    assert_eq!(deleted["cipher"]["revisionDate"], updated["revisionDate"]);
    let stored = &vault_file(&fs, &user_id)["sync"]["ciphers"][0];
    assert_eq!(stored["revisionDate"], updated["revisionDate"]);
    assert_eq!(client.request("GET", &content_path).send().code, 404);
    assert_eq!(client.get(&attachment_path, &token).code, 404);
    // The content is kept until nothing can bring the attachment back, but not handed out.
    assert_eq!(fs.get(&file).unwrap(), content);
    let removed = format!("{cipher_id}/{attachment_id}");
    let removed_at = &vault_file(&fs, &user_id)["removedAttachments"][&removed];
    assert_eq!(*removed_at, NOON + 45 * MINUTE);

    // Then it is deleted. The directory of the content of the item stays, as the vault still has
    // the item, and the content of a new attachment of it can be on its way there.
    client.platform.set_now(NOON + 45 * MINUTE + GRACE);
    client.get("sync", &token);
    assert_eq!(fs.get(&file), None);
    assert!(block_on_exists(&fs, &file[..3]));
}

#[test]
fn the_attachments_of_a_cipher_that_is_deleted_are_removed_once_nothing_can_bring_it_back() {
    let (client, fs) = browser();
    let (token, user_id) = client.register_and_log_in();
    let cipher = body(&client.send("POST", "ciphers", &token, json!({"type": 1})));
    let cipher_id = id(&cipher);
    upload_attachment(&client, &token, &cipher_id);
    let attachments = [user_id.as_str(), "attachments"];
    let of_item = [user_id.as_str(), "attachments", cipher_id.as_str()];

    // The files are named after the ID that the item has, in whatever case a request names it.
    let path = format!("ciphers/{}", cipher_id.to_uppercase());
    client.call("DELETE", &path, &token);
    client.get("sync", &token);

    // A device that has not seen the deletion yet can still bring the item back with a change.
    assert!(block_on_exists(&fs, &of_item));
    client.platform.set_now(NOON + GRACE);
    client.get("sync", &token);

    // The directory of the content of the item goes with it, as the vault no longer has the item.
    assert!(!block_on_exists(&fs, &of_item));
    assert!(block_on_list(&fs, &attachments).is_empty());
    assert_eq!(vault_file(&fs, &user_id)["removedAttachments"], json!({}));
    assert!(client.platform.logs().is_empty());
}

#[test]
fn the_content_of_attachments_that_cannot_be_deleted_is_deleted_the_next_time() {
    for fails_with_error in [false, true] {
        let fs = MemoryFileSystem::new();
        let failing = NoDelete {
            fs: fs.clone(),
            fails_with_error,
        };
        let client = Client::on(failing, TestPlatform::at(NOON), ClientKind::Browser);
        let (token, user_id) = client.register_and_log_in();
        let cipher = body(&client.send("POST", "ciphers", &token, json!({"type": 1})));
        upload_attachment(&client, &token, &id(&cipher));

        let deleted = client.call("DELETE", &format!("ciphers/{}", id(&cipher)), &token);
        client.platform.set_now(NOON + GRACE);
        let synced = client.get("sync", &token);

        // The item is gone from the vault, which is what the request is for, and the content of
        // its attachment is still to be deleted.
        assert_eq!(deleted.code, 200);
        assert_eq!(synced.code, 200);
        let file = vault_file(&fs, &user_id);
        assert_eq!(file["sync"]["ciphers"], json!([]));
        let attachments = [user_id.as_str(), "attachments"];
        assert!(block_on_exists(&fs, &attachments));
        let removed = file["removedAttachments"].as_object().unwrap();
        assert_eq!(removed.len(), 1);
        assert!(client.platform.logs().is_empty());
    }
}

#[test]
fn a_file_that_could_not_be_tidied_is_tidied_at_the_next_sync() {
    let fs = MemoryFileSystem::new();
    let full = Full {
        fs: fs.clone(),
        is_full: AtomicBool::new(false),
    };
    let client = Client::on(full, TestPlatform::at(NOON), ClientKind::Browser);
    let (token, user_id) = client.register_and_log_in();
    let cipher = body(&client.send("POST", "ciphers", &token, json!({"type": 1})));
    upload_attachment(&client, &token, &id(&cipher));
    client.call("DELETE", &format!("ciphers/{}", id(&cipher)), &token);
    let removed = || vault_file(&fs, &user_id)["removedAttachments"].clone();
    let failed = "Local server could not leave out of its file what other devices replaced.";

    // The vault folder is full when the device first looks at its file, which the sync itself
    // does not need.
    let is_full = &client.server.file_system().is_full;
    is_full.store(true, Ordering::SeqCst);
    client.platform.set_now(NOON + GRACE);
    assert_eq!(client.get("sync", &token).code, 200);
    is_full.store(false, Ordering::SeqCst);
    assert_eq!(client.platform.logs(), [failed]);
    assert_eq!(removed().as_object().unwrap().len(), 1);

    // It looks again at the next sync, not a day later.
    client.platform.set_now(NOON + GRACE + MINUTE);
    assert_eq!(client.get("sync", &token).code, 200);
    assert_eq!(removed(), json!({}));
    assert_eq!(client.platform.logs(), [failed]);
}

#[test]
fn the_upload_of_an_attachment_in_blocks_is_refused() {
    let (client, fs) = browser();
    let (token, user_id) = client.register_and_log_in();
    let cipher = body(&client.send("POST", "ciphers", &token, json!({"type": 1})));
    let path = format!("ciphers/{}/attachment/v2", id(&cipher));
    let upload = body(&client.send("POST", &path, &token, json!({})));
    let content_path = path_of(upload["url"].as_str().unwrap());

    // What a client sends for a file that is too large for a single request: the blocks, and
    // then the list of them, which is not the content of the attachment.
    let queries: [&[(&str, &str)]; 2] = [
        &[("comp", "block"), ("blockid", "MA==")],
        &[("comp", "blocklist")],
    ];
    for query in queries {
        let request = client.request("PUT", &content_path).query(query);
        let response = request.bytes(&[1]).send();

        assert_eq!(response.code, 400);
        assert_eq!(body(&response)["object"], "error");
    }
    assert!(!block_on_exists(&fs, &[user_id.as_str(), "attachments"]));
}

#[test]
fn the_content_of_attachments_is_only_reached_inside_of_the_vault() {
    let (client, fs) = browser();
    let (token, user_id) = client.register_and_log_in();
    let cipher = body(&client.send("POST", "ciphers", &token, json!({"type": 1})));
    let cipher_id = id(&cipher);
    let get = |path: String| client.request("GET", &format!("attachments/{path}")).send();
    let put = |path: String| put_one_byte(&client, &format!("attachments/{path}"));
    let responses = [
        get(format!("{user_id}/../vault.json")),
        get(format!("{user_id}/{cipher_id}")),
        get(format!("{user_id}/..%2F/vault.json")),
        put(format!("{user_id}/{cipher_id}/unknown")),
        put(format!("{user_id}/unknown/attachment")),
        put(format!("unknown/{cipher_id}/attachment")),
    ];

    for response in responses {
        assert_eq!(response.code, 404);
    }
    let other_method = format!("attachments/{user_id}/{cipher_id}/a");
    assert_eq!(client.request("DELETE", &other_method).send().code, 400);
    let has_attachments = |path: &Vec<String>| path.iter().any(|name| name == "attachments");
    assert!(!fs.paths().iter().any(has_attachments));
}

#[test]
fn imported_items_are_added_to_the_folders_that_they_come_with() {
    let (client, fs) = browser();
    let (token, user_id) = client.register_and_log_in();
    let existing = json!({"name": "2.existing"});
    client.send("POST", "folders", &token, existing);
    let import = json!({
        "ciphers": [
            {"type": 1, "name": "2.first", "lastKnownRevisionDate": null},
            {"type": 2, "name": "2.second"},
            {"type": 1, "name": "2.third"},
        ],
        "folders": [{"name": "2.one"}, {"name": "2.two"}],
        "folderRelationships": [
            {"key": 0, "value": 1},
            {"key": 2, "value": 0},
            {"key": 1, "value": 5},
        ],
    });

    let response = client.send("POST", "ciphers/import", &token, import);

    assert_eq!(response.code, 200);
    let sync = &vault_file(&fs, &user_id)["sync"];
    assert_eq!(names(&sync["folders"]), ["2.existing", "2.one", "2.two"]);
    let folder_ids = field_of_each(&sync["folders"], "id");
    let expected = [folder_ids[2].clone(), Value::Null, folder_ids[1].clone()];
    assert_eq!(field_of_each(&sync["ciphers"], "folderId"), expected);
    let first = &sync["ciphers"][0];
    assert_eq!(first["name"], "2.first");
    assert_eq!(first["object"], "cipherDetails");
    assert_eq!(first["edit"], true);
    assert_eq!(first.get("lastKnownRevisionDate"), None);
    let ids = field_of_each(&sync["ciphers"], "id");
    let unique: std::collections::BTreeSet<String> = ids.iter().map(Value::to_string).collect();
    assert_eq!(unique.len(), 3);
}

#[test]
fn imported_items_are_added_to_a_folder_of_the_vault_that_they_come_with() {
    let (client, fs) = browser();
    let (token, user_id) = client.register_and_log_in();
    let existing = json!({"name": "2.existing"});
    let existing = body(&client.send("POST", "folders", &token, existing));
    client.platform.set_now(NOON + MINUTE);
    // What a client sends when it imports into a folder: that folder first, with its ID, here in
    // another case than the vault has it in.
    let existing_id = id(&existing).to_uppercase();
    let import = json!({
        "ciphers": [{"type": 1, "name": "2.first"}, {"type": 1, "name": "2.second"}],
        "folders": [{"id": existing_id, "name": "2.existing"}, {"name": "2.existing/new"}],
        "folderRelationships": [{"key": 0, "value": 0}, {"key": 1, "value": 1}],
    });

    let response = client.send("POST", "ciphers/import", &token, import);

    assert_eq!(response.code, 200);
    let sync = &vault_file(&fs, &user_id)["sync"];
    assert_eq!(names(&sync["folders"]), ["2.existing", "2.existing/new"]);
    assert_eq!(sync["folders"][0], existing);
    let folder_ids = field_of_each(&sync["folders"], "id");
    assert_eq!(field_of_each(&sync["ciphers"], "folderId"), folder_ids);
}

#[test]
fn purging_the_vault_removes_every_item_folder_and_attachment() {
    let (client, fs) = browser();
    let (token, user_id) = client.register_and_log_in();
    let cipher = body(&client.send("POST", "ciphers", &token, json!({"type": 1})));
    let folder = json!({"name": "2.folder"});
    client.send("POST", "folders", &token, folder);
    upload_attachment(&client, &token, &id(&cipher));
    let purge = |hash: &str| {
        let body = json!({"masterPasswordHash": hash});
        client.send("POST", "ciphers/purge", &token, body)
    };

    assert_eq!(purge("d3Jvbmc=").code, 400);
    assert_ne!(vault_file(&fs, &user_id)["sync"]["ciphers"], json!([]));
    assert_eq!(purge(PASSWORD_HASH).code, 200);

    let sync = &vault_file(&fs, &user_id)["sync"];
    assert_eq!(sync["ciphers"], json!([]));
    assert_eq!(sync["folders"], json!([]));
    // The content of the attachments is deleted once nothing can bring them back, and so are the
    // directories that held it.
    let attachments = [user_id.as_str(), "attachments"];
    assert!(!block_on_list(&fs, &attachments).is_empty());
    client.platform.set_now(NOON + GRACE);
    client.get("sync", &token);
    assert!(block_on_list(&fs, &attachments).is_empty());
}

/// Adds an attachment to the item and uploads its content.
fn upload_attachment<F: FileSystem>(client: &Client<F>, token: &str, cipher_id: &str) {
    let path = format!("ciphers/{cipher_id}/attachment/v2");
    let upload = body(&client.send("POST", &path, token, json!({})));
    let content_path = path_of(upload["url"].as_str().unwrap());
    let uploaded = client.request("PUT", &content_path).bytes(&[1]).send();
    assert_eq!(uploaded.code, 201);
}

fn put_one_byte(client: &Client<MemoryFileSystem>, path: &str) -> LocalResponse {
    client.request("PUT", path).bytes(&[1]).send()
}

fn block_on_exists(fs: &MemoryFileSystem, path: &[&str]) -> bool {
    futures::executor::block_on(fs.exists(path)).unwrap()
}

fn block_on_list(fs: &MemoryFileSystem, directory: &[&str]) -> Vec<String> {
    futures::executor::block_on(fs.list(directory)).unwrap()
}

/// A file system that does not delete attachments: it fails to, or leaves them where they are.
/// The files that a vault is replaced through are deleted as ever.
struct NoDelete {
    fs: MemoryFileSystem,
    fails_with_error: bool,
}

impl FileSystem for NoDelete {
    async fn list(&self, directory: &[&str]) -> Result<Vec<String>, IoError> {
        self.fs.list(directory).await
    }

    async fn exists(&self, path: &[&str]) -> Result<bool, IoError> {
        self.fs.exists(path).await
    }

    async fn read(&self, path: &[&str]) -> Result<Option<Vec<u8>>, IoError> {
        self.fs.read(path).await
    }

    async fn write(&self, path: &[&str], content: &[u8]) -> Result<(), IoError> {
        self.fs.write(path, content).await
    }

    async fn rename(&self, path: &[&str], new_name: &str) -> Result<bool, IoError> {
        self.fs.rename(path, new_name).await
    }

    async fn delete(&self, path: &[&str]) -> Result<bool, IoError> {
        if !path.contains(&"attachments") {
            self.fs.delete(path).await
        } else if self.fails_with_error {
            Err(IoError::new("busy"))
        } else {
            Ok(false)
        }
    }
}

/// A vault folder on a drive that can be full, where nothing can be written then, but what is
/// there can be read and deleted.
struct Full {
    fs: MemoryFileSystem,
    is_full: AtomicBool,
}

impl FileSystem for Full {
    async fn list(&self, directory: &[&str]) -> Result<Vec<String>, IoError> {
        self.fs.list(directory).await
    }

    async fn exists(&self, path: &[&str]) -> Result<bool, IoError> {
        self.fs.exists(path).await
    }

    async fn read(&self, path: &[&str]) -> Result<Option<Vec<u8>>, IoError> {
        self.fs.read(path).await
    }

    async fn write(&self, path: &[&str], content: &[u8]) -> Result<(), IoError> {
        if self.is_full.load(Ordering::SeqCst) {
            return Err(IoError::new("The drive is full."));
        }
        self.fs.write(path, content).await
    }

    async fn rename(&self, path: &[&str], new_name: &str) -> Result<bool, IoError> {
        self.fs.rename(path, new_name).await
    }

    async fn delete(&self, path: &[&str]) -> Result<bool, IoError> {
        self.fs.delete(path).await
    }
}
