//! Rotating the user key of an account: everything that it encrypts is encrypted again with a new
//! one, on one device, and on another one that shares the vault folder.

#![allow(clippy::unwrap_used, clippy::indexing_slicing)]

mod common;

use common::*;
use local_vault::{ClientKind, LocalResponse, MemoryFileSystem};
use serde_json::{Value, json};

const OTHER_DEVICE: &str = "device-b";
const NEW_HASH: &str = "bmV3LWhhc2g=";
const OTHER_HASH: &str = "b3RoZXItaGFzaA==";
const PATH: &str = "accounts/key-management/rotate-user-account-keys";

fn sync(client: &Client<MemoryFileSystem>, token: &str) -> Value {
    body(&client.get("sync", token))
}

fn id(item: &Value) -> &str {
    item["id"].as_str().unwrap()
}

/// What a client sends to rotate the user key of the account, from the vault as it has it: every
/// item and folder encrypted again with the new key, which `label` tells apart, and the master
/// password of [`NEW_HASH`], which unlocks it.
fn rotation(vault: &Value, user_id: &str, label: &str) -> Value {
    let ciphers = vault["ciphers"].as_array().unwrap().iter().map(|cipher| {
        let attachments = cipher["attachments"].as_array().into_iter().flatten();
        let attachments: serde_json::Map<String, Value> = attachments
            .map(|attachment| {
                let key = json!({"fileName": "2.fileName", "key": format!("2.{label}Attachment")});
                (id(attachment).to_owned(), key)
            })
            .collect();
        json!({
            "id": cipher["id"],
            "type": cipher["type"],
            "name": format!("2.{label}"),
            "folderId": cipher["folderId"],
            "favorite": cipher["favorite"],
            "lastKnownRevisionDate": cipher["revisionDate"],
            "attachments2": attachments,
            "encryptedFor": user_id,
            "encryptedByKeyId": format!("{label}-key-id"),
        })
    });
    let folders = vault["folders"]
        .as_array()
        .unwrap()
        .iter()
        .map(|folder| json!({"id": folder["id"], "name": format!("2.{label}Folder")}));
    let private_key = format!("2.{label}PrivateKey");
    json!({
        "oldMasterKeyAuthenticationHash": PASSWORD_HASH,
        "accountUnlockData": {
            "masterPasswordUnlockData": {
                "kdfType": 0,
                "kdfIterations": 600000,
                "email": EMAIL,
                "masterKeyAuthenticationHash": NEW_HASH,
                "masterKeyEncryptedUserKey": format!("2.{label}UserKey"),
                "masterPasswordHint": "new hint",
            },
            "emergencyAccessUnlockData": [],
            "organizationAccountRecoveryUnlockData": [],
            "passkeyUnlockData": [],
            "deviceKeyUnlockData": [],
        },
        "accountKeys": {
            "userKeyEncryptedAccountPrivateKey": private_key,
            "accountPublicKey": "publicKey",
            "publicKeyEncryptionKeyPair": {"wrappedPrivateKey": private_key, "publicKey": "publicKey"},
        },
        "accountData": {"ciphers": ciphers.collect::<Vec<_>>(), "folders": folders.collect::<Vec<_>>(), "sends": []},
    })
}

fn rotate(client: &Client<MemoryFileSystem>, token: &str, rotation: Value) -> LocalResponse {
    client.send("POST", PATH, token, rotation)
}

/// Logs in with the master password of the hash, and returns the access token.
fn log_in(client: &Client<MemoryFileSystem>, password_hash: &str) -> String {
    let login = client.log_in(EMAIL, password_hash);
    assert_eq!(login.code, 200, "{:?}", login.json());
    body(&login)["access_token"].as_str().unwrap().to_owned()
}

/// An account with an item that has an attachment, in a folder, and with the ID of its user key
/// recorded. Returns the token of the account and its ID.
fn account_with_items(client: &Client<MemoryFileSystem>) -> (String, String) {
    let (token, user_id) = client.register_and_log_in();
    let folder = body(&client.send("POST", "folders", &token, json!({"name": "2.folder"})));
    let cipher = json!({"type": 1, "name": "2.item", "folderId": folder["id"]});
    let cipher = body(&client.send("POST", "ciphers", &token, cipher));
    let path = format!("ciphers/{}/attachment/v2", id(&cipher));
    let attachment = json!({"fileName": "2.fileName", "key": "2.key", "fileSize": 1});
    let upload = body(&client.send("POST", &path, &token, attachment));
    let content_path = path_of(upload["url"].as_str().unwrap());
    assert_eq!(
        client.request("PUT", &content_path).bytes(&[7]).send().code,
        201
    );
    let record = json!({"userKeyId": "key-id"});
    let path = "accounts/key-management/user-key-id";
    assert_eq!(client.send("POST", path, &token, record).code, 200);
    (token, user_id)
}

#[test]
fn a_rotation_replaces_what_the_user_key_encrypts_and_the_master_password() {
    let (client, fs) = Client::in_memory(ClientKind::Browser);
    let (token, user_id) = account_with_items(&client);
    let before = sync(&client, &token);
    client.platform.set_now(NOON + MINUTE);

    let rotated = rotate(&client, &token, rotation(&before, &user_id, "rotated"));

    assert_eq!(rotated.code, 200, "{:?}", rotated.json());
    assert_eq!(client.log_in(EMAIL, PASSWORD_HASH).code, 400);
    let login = body(&client.log_in(EMAIL, NEW_HASH));
    assert_eq!(login["Key"], "2.rotatedUserKey");
    assert_eq!(login["PrivateKey"], "2.rotatedPrivateKey");
    let new_token = login["access_token"].as_str().unwrap();
    let after = sync(&client, new_token);
    let profile = &after["profile"];
    assert_eq!(profile["key"], "2.rotatedUserKey");
    assert_eq!(profile["privateKey"], "2.rotatedPrivateKey");
    let pair = &profile["accountKeys"]["publicKeyEncryptionKeyPair"];
    assert_eq!(pair["wrappedPrivateKey"], "2.rotatedPrivateKey");
    assert_eq!(pair["publicKey"], "publicKey");
    assert_eq!(profile["masterPasswordHint"], "new hint");
    assert_ne!(profile["securityStamp"], before["profile"]["securityStamp"]);
    let unlock = &after["userDecryption"]["masterPasswordUnlock"];
    assert_eq!(unlock["masterKeyEncryptedUserKey"], "2.rotatedUserKey");
    assert_eq!(
        unlock["kdf"],
        before["userDecryption"]["masterPasswordUnlock"]["kdf"]
    );
    // The ID that was recorded is that of the key before.
    assert_eq!(after["userDecryption"].get("userKeyId"), None);
    let cipher = &after["ciphers"][0];
    assert_eq!(cipher["name"], "2.rotated");
    assert_eq!(cipher["folderId"], before["folders"][0]["id"]);
    assert_eq!(cipher["attachments"][0]["key"], "2.rotatedAttachment");
    assert_eq!(cipher["revisionDate"], "2026-10-11T12:01:00.000Z");
    assert_eq!(cipher.get("encryptedByKeyId"), None);
    assert_eq!(after["folders"][0]["name"], "2.rotatedFolder");
    // The content of the attachment is encrypted with its own key, which is all that changes.
    let attachment = &cipher["attachments"][0];
    let download = format!("ciphers/{}/attachment/{}", id(cipher), id(attachment));
    let download = body(&client.get(&download, new_token));
    assert_eq!(
        client.download(&path_of(download["url"].as_str().unwrap())),
        Some(vec![7])
    );
    // A client that does not know of rotated keys leaves the file alone.
    let file = vault_file(&fs, &user_id);
    // Every field that the rotation wrote is returned.
    assert_eq!(after, file["sync"]);
    assert_eq!(file["version"], 4);
    let rotation = json!({"at": NOON + MINUTE, "by": DEVICE});
    assert_eq!(file["account"]["userKeyRotation"], rotation);
    assert_eq!(file["records"]["masterPassword"]["key"], rotation);
    assert_eq!(
        file["records"][format!("cipher:{}", id(cipher))]["key"],
        rotation
    );
}

#[test]
fn a_token_that_was_issued_before_the_rotation_is_refused_and_not_renewed() {
    let (client, _) = Client::in_memory(ClientKind::Android);
    let (token, user_id) = client.register_and_log_in();
    let login = body(&client.log_in(EMAIL, PASSWORD_HASH));
    let refresh_token = login["refresh_token"].as_str().unwrap().to_owned();
    let before = sync(&client, &token);
    assert_eq!(
        rotate(&client, &token, rotation(&before, &user_id, "rotated")).code,
        200
    );

    let refresh = |refresh_token: &str| {
        let form = [
            ("grant_type", "refresh_token"),
            ("refresh_token", refresh_token),
        ];
        client.request("POST", "connect/token").form(&form).send()
    };

    // The client still has the key before, and would write with it.
    assert_eq!(client.get("sync", &token).code, 401);
    let cipher = json!({"type": 1, "name": "2.oldKey"});
    assert_eq!(client.send("POST", "ciphers", &token, cipher).code, 401);
    let refused = refresh(&refresh_token);
    assert_eq!(refused.code, 400);
    assert_eq!(body(&refused)["error"], "invalid_grant");
    // Logged in again, with the master password that unlocks the new key.
    let login = body(&client.log_in(EMAIL, NEW_HASH));
    let new_token = login["access_token"].as_str().unwrap();
    assert_eq!(
        claims_of(new_token)["user_key"],
        json!({"at": NOON, "by": DEVICE})
    );
    assert_eq!(sync(&client, new_token)["ciphers"], json!([]));
    let renewed = refresh(login["refresh_token"].as_str().unwrap());
    assert_eq!(renewed.code, 200);
    let renewed_token = body(&renewed)["access_token"].as_str().unwrap().to_owned();
    assert_eq!(client.get("sync", &renewed_token).code, 200);
}

#[test]
fn a_rotation_that_leaves_an_item_or_a_folder_out_or_has_another_one_is_refused() {
    let (client, fs) = Client::in_memory(ClientKind::Browser);
    let (token, user_id) = account_with_items(&client);
    let vault = sync(&client, &token);
    let full = rotation(&vault, &user_id, "rotated");
    let mut without_item = full.clone();
    without_item["accountData"]["ciphers"] = json!([]);
    let mut without_folder = full.clone();
    without_folder["accountData"]["folders"] = json!([]);
    let mut other_item = full.clone();
    other_item["accountData"]["ciphers"][0]["id"] = json!(UNKNOWN_ID);
    let mut item_twice = full.clone();
    let folder = full["accountData"]["folders"][0].clone();
    let cipher = full["accountData"]["ciphers"][0].clone();
    item_twice["accountData"]["ciphers"] = json!([cipher, cipher]);
    item_twice["accountData"]["folders"] = json!([folder, folder]);
    let files = fs.paths();
    let file = vault_file(&fs, &user_id);

    for refused in [without_item, without_folder, other_item, item_twice] {
        let response = rotate(&client, &token, refused);

        assert_eq!(response.code, 400);
        assert!(
            message(&response).contains("Sync your vault"),
            "{}",
            message(&response)
        );
    }
    assert_eq!(fs.paths(), files);
    assert_eq!(vault_file(&fs, &user_id), file);
}

#[test]
fn a_rotation_is_refused_unless_the_master_key_and_the_key_pair_stay_the_same() {
    let (client, fs) = Client::in_memory(ClientKind::Browser);
    let (token, user_id) = account_with_items(&client);
    let vault = sync(&client, &token);
    let full = rotation(&vault, &user_id, "rotated");
    let changed = |change: &dyn Fn(&mut Value)| {
        let mut rotation = full.clone();
        change(&mut rotation);
        rotation
    };
    let cases = [
        changed(&|r| r["oldMasterKeyAuthenticationHash"] = json!(NEW_HASH)),
        changed(&|r| unlock(r)["kdfIterations"] = json!(700000)),
        changed(&|r| unlock(r)["email"] = json!("other@example.com")),
        changed(&|r| r["accountKeys"]["publicKeyEncryptionKeyPair"]["publicKey"] = json!("other")),
        changed(&|r| r["accountKeys"]["signatureKeyPair"] = json!({"wrappedSigningKey": "7.x"})),
        changed(&|r| r["accountData"]["ciphers"][0]["encryptedFor"] = json!(UNKNOWN_ID)),
        changed(&|r| {
            let date = json!("2026-10-11T11:00:00.000Z");
            r["accountData"]["ciphers"][0]["lastKnownRevisionDate"] = date;
        }),
    ];
    let file = vault_file(&fs, &user_id);

    for refused in cases {
        assert_eq!(rotate(&client, &token, refused).code, 400);
    }
    let without_keys = changed(&|r| r["accountKeys"] = json!({}));
    assert_eq!(rotate(&client, &token, without_keys).code, 400);
    assert_eq!(vault_file(&fs, &user_id), file);
    assert_eq!(client.log_in(EMAIL, PASSWORD_HASH).code, 200);
}

fn unlock(rotation: &mut Value) -> &mut Value {
    &mut rotation["accountUnlockData"]["masterPasswordUnlockData"]
}

#[test]
fn a_rotation_that_leaves_out_the_key_of_an_attachment_is_refused() {
    let (client, fs) = Client::in_memory(ClientKind::Browser);
    let (token, user_id) = account_with_items(&client);
    let vault = sync(&client, &token);
    let full = rotation(&vault, &user_id, "rotated");
    let attachment_id = id(&vault["ciphers"][0]["attachments"][0]).to_owned();
    let mut without_attachment = full.clone();
    without_attachment["accountData"]["ciphers"][0]["attachments2"] = json!({});
    let mut without_key = full.clone();
    let attachments = &mut without_key["accountData"]["ciphers"][0]["attachments2"];
    attachments[attachment_id.as_str()]["key"] = Value::Null;
    let file = vault_file(&fs, &user_id);

    for refused in [without_attachment, without_key] {
        let response = rotate(&client, &token, refused);

        // The content of the attachment could no longer be decrypted.
        assert_eq!(response.code, 400);
        assert_eq!(
            message(&response),
            "The keys of some attachments were left out of the rotation of the user key."
        );
    }
    assert_eq!(vault_file(&fs, &user_id), file);
    assert_eq!(client.log_in(EMAIL, PASSWORD_HASH).code, 200);
}

#[test]
fn a_rotation_of_a_vault_without_the_public_key_of_the_account_is_refused() {
    let (client, fs) = Client::in_memory(ClientKind::Browser);
    let (token, user_id) = client.register_and_log_in();
    let vault = sync(&client, &token);
    let mut file = vault_file(&fs, &user_id);
    let profile = file["sync"]["profile"].as_object_mut().unwrap();
    profile.remove("accountKeys");
    replace_vault_file(&fs, &user_id, &file);

    let response = rotate(&client, &token, rotation(&vault, &user_id, "rotated"));

    // Nothing tells whether the key pair stays the same.
    assert_eq!(response.code, 400);
    assert_eq!(
        message(&response),
        "The vault has no key pair of the account to keep."
    );
}

/// Two devices, each with its own copy of the vault folder, with an account that was registered
/// on the first one and an item in it, whose files have come to the other one. Returns the
/// clients and their copies, the token of the account and its ID.
fn two_devices() -> (
    [Client<MemoryFileSystem>; 2],
    [MemoryFileSystem; 2],
    String,
    String,
) {
    let a_fs = MemoryFileSystem::new();
    let b_fs = MemoryFileSystem::new();
    let a = Client::on_device(
        a_fs.clone(),
        TestPlatform::seeded(NOON, 1),
        ClientKind::Browser,
        DEVICE,
    );
    let b_platform = TestPlatform::seeded(NOON, 1 << 40);
    let b = Client::on_device(b_fs.clone(), b_platform, ClientKind::Android, OTHER_DEVICE);
    let (token, user_id) = a.register_and_log_in();
    a.send(
        "POST",
        "ciphers",
        &token,
        json!({"type": 1, "name": "2.item"}),
    );
    deliver(&a_fs, DEVICE, &b_fs);
    ([a, b], [a_fs, b_fs], token, user_id)
}

fn exchange_files(fs: &[MemoryFileSystem; 2]) {
    deliver(&fs[0], DEVICE, &fs[1]);
    deliver(&fs[1], OTHER_DEVICE, &fs[0]);
}

#[test]
fn what_a_device_writes_with_the_key_before_does_not_replace_what_the_rotation_wrote() {
    let ([a, b], fs, token, user_id) = two_devices();
    let vault = sync(&b, &token);
    a.platform.set_now(NOON + MINUTE);
    b.platform.set_now(NOON + 2 * MINUTE);

    // The other device, which does not have the rotation yet, changes the item later, records
    // the ID of the key before, which is a change of the account, and adds an item.
    assert_eq!(
        rotate(&a, &token, rotation(&vault, &user_id, "rotated")).code,
        200
    );
    let cipher = &vault["ciphers"][0];
    let update = json!({
        "type": 1,
        "name": "2.changedWithTheKeyBefore",
        "lastKnownRevisionDate": cipher["revisionDate"],
    });
    assert_eq!(
        b.send("PUT", &format!("ciphers/{}", id(cipher)), &token, update)
            .code,
        200
    );
    let record = json!({"userKeyId": "key-id-before"});
    let path = "accounts/key-management/user-key-id";
    assert_eq!(b.send("POST", path, &token, record).code, 200);
    let added = json!({"type": 1, "name": "2.addedWithTheKeyBefore"});
    assert_eq!(b.send("POST", "ciphers", &token, added).code, 200);
    let kdf = json!({"kdfType": 0, "iterations": 600000});
    let change = json!({
        "masterPasswordHash": PASSWORD_HASH,
        "authenticationData": {"salt": EMAIL, "kdf": kdf, "masterPasswordAuthenticationHash": OTHER_HASH},
        "unlockData": {"salt": EMAIL, "kdf": kdf, "masterKeyWrappedUserKey": "2.keyBefore"},
    });
    assert_eq!(
        b.send("POST", "accounts/password", &token, change).code,
        200
    );
    exchange_files(&fs);

    // Neither undoes the rotation. The item that was added stays, which the new key does not
    // decrypt.
    assert_eq!(b.get("sync", &token).code, 401);
    assert_eq!(b.log_in(EMAIL, OTHER_HASH).code, 400);
    let vaults = [&a, &b].map(|client| sync(client, &log_in(client, NEW_HASH)));
    for vault in &vaults {
        assert_eq!(vault["profile"]["privateKey"], "2.rotatedPrivateKey");
        assert_eq!(vault["userDecryption"].get("userKeyId"), None);
        let names = vault["ciphers"]
            .as_array()
            .unwrap()
            .iter()
            .map(|c| c["name"].clone());
        let names: Vec<Value> = names.collect();
        assert_eq!(
            names,
            [json!("2.rotated"), json!("2.addedWithTheKeyBefore")]
        );
    }
    assert_eq!(vaults[0], vaults[1]);
    assert_eq!(a.log_in(EMAIL, PASSWORD_HASH).code, 400);
    // The master password that the device changed with the key before is left out of its file
    // as soon as it writes it, as one that the rotation replaced.
    let file = read_json(&fs[1], &device_file(&user_id, OTHER_DEVICE));
    assert!(file["records"].get("masterPassword").is_some());
    let new_token = log_in(&b, NEW_HASH);
    b.send("POST", "folders", &new_token, json!({"name": "2.newKey"}));
    let file = read_json(&fs[1], &device_file(&user_id, OTHER_DEVICE));
    assert!(file["records"].get("masterPassword").is_none());
    assert_eq!(file["version"], 4);
}

#[test]
fn a_device_that_has_the_rotation_refuses_to_write_with_the_key_before() {
    let ([a, b], fs, token, user_id) = two_devices();
    let vault = sync(&b, &token);
    assert_eq!(
        rotate(&a, &token, rotation(&vault, &user_id, "rotated")).code,
        200
    );
    exchange_files(&fs);
    let files = fs[1].paths();

    let cipher = &vault["ciphers"][0];
    let update =
        json!({"type": 1, "name": "2.oldKey", "lastKnownRevisionDate": cipher["revisionDate"]});
    let updated = b.send("PUT", &format!("ciphers/{}", id(cipher)), &token, update);

    assert_eq!(updated.code, 401);
    assert_eq!(fs[1].paths(), files);
    // Logged in again, it has the new key, and writes with it.
    let new_token = log_in(&b, NEW_HASH);
    let cipher = &sync(&b, &new_token)["ciphers"][0];
    let update =
        json!({"type": 1, "name": "2.newKey", "lastKnownRevisionDate": cipher["revisionDate"]});
    assert_eq!(
        b.send(
            "PUT",
            &format!("ciphers/{}", id(cipher)),
            &new_token,
            update
        )
        .code,
        200
    );
    let file = read_json(&fs[1], &device_file(&user_id, OTHER_DEVICE));
    assert_eq!(file["version"], 4);
    assert_eq!(
        file["records"][format!("cipher:{}", id(cipher))]["key"]["by"],
        DEVICE
    );
}

#[test]
fn of_two_rotations_that_two_devices_make_at_once_the_later_one_is_kept_whole() {
    let ([a, b], fs, token, user_id) = two_devices();
    let vault = sync(&b, &token);
    a.platform.set_now(NOON + 2 * MINUTE);
    b.platform.set_now(NOON + MINUTE);

    assert_eq!(
        rotate(&a, &token, rotation(&vault, &user_id, "later")).code,
        200
    );
    assert_eq!(
        rotate(&b, &token, rotation(&vault, &user_id, "earlier")).code,
        200
    );
    // A device that rotated the key before changes the item afterwards, with its own new key.
    let earlier_token = log_in(&b, NEW_HASH);
    let cipher = &sync(&b, &earlier_token)["ciphers"][0];
    b.platform.set_now(NOON + 3 * MINUTE);
    let update = json!({"type": 1, "name": "2.earlierChanged", "lastKnownRevisionDate": cipher["revisionDate"]});
    assert_eq!(
        b.send(
            "PUT",
            &format!("ciphers/{}", id(cipher)),
            &earlier_token,
            update
        )
        .code,
        200
    );
    exchange_files(&fs);

    assert_eq!(b.get("sync", &earlier_token).code, 401);
    for client in [&a, &b] {
        let vault = sync(client, &log_in(client, NEW_HASH));
        assert_eq!(vault["profile"]["key"], "2.laterUserKey");
        assert_eq!(vault["profile"]["privateKey"], "2.laterPrivateKey");
        assert_eq!(vault["ciphers"][0]["name"], "2.later");
    }
}
