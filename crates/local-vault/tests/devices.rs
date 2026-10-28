//! Devices that share a vault folder through a tool that syncs it, such as Syncthing. Each device
//! has a copy of the folder, writes only its own files in it, and gets the files of the others
//! some time later.

#![allow(clippy::unwrap_used, clippy::indexing_slicing)]

mod common;

use common::*;
use futures::executor::block_on;
use local_vault::{ClientKind, FileSystem, LocalResponse, LocalServer, MemoryFileSystem};
use serde_json::{Value, json};

const OTHER_DEVICE: &str = "device-b";

const NEW_HASH: &str = "bmV3LWhhc2g=";

/// Two devices, each with its own copy of the vault folder.
struct Devices {
    a: Client<MemoryFileSystem>,
    a_fs: MemoryFileSystem,
    b: Client<MemoryFileSystem>,
    b_fs: MemoryFileSystem,
}

impl Devices {
    fn new() -> Self {
        let a_fs = MemoryFileSystem::new();
        let b_fs = MemoryFileSystem::new();
        let a_platform = TestPlatform::seeded(NOON, 1);
        let b_platform = TestPlatform::seeded(NOON, 1 << 40);
        let a = Client::on_device(a_fs.clone(), a_platform, ClientKind::Browser, DEVICE);
        let b = Client::on_device(b_fs.clone(), b_platform, ClientKind::Android, OTHER_DEVICE);
        Self { a, a_fs, b, b_fs }
    }

    /// Two devices with an account that was registered on the first one, whose files have come
    /// to the second one. Returns the token of the account and its ID.
    fn registered() -> (Self, String, String) {
        let devices = Self::new();
        let (token, user_id) = devices.a.register_and_log_in();
        devices.sync_files();
        assert_eq!(devices.b.log_in(EMAIL, PASSWORD_HASH).code, 200);
        (devices, token, user_id)
    }

    /// Brings the files that each device wrote to the other one.
    fn sync_files(&self) {
        deliver(&self.a_fs, DEVICE, &self.b_fs);
        deliver(&self.b_fs, OTHER_DEVICE, &self.a_fs);
    }

    fn clients(&self) -> [&Client<MemoryFileSystem>; 2] {
        [&self.a, &self.b]
    }
}

fn sync(client: &Client<MemoryFileSystem>, token: &str) -> Value {
    body(&client.get("sync", token))
}

fn names(list: &Value) -> Vec<Value> {
    let items = list.as_array().unwrap().iter();
    items.map(|item| item["name"].clone()).collect()
}

fn create_cipher(client: &Client<MemoryFileSystem>, token: &str, name: &str) -> Value {
    let cipher = json!({"type": 1, "name": name});
    body(&client.send("POST", "ciphers", token, cipher))
}

fn update_cipher(
    client: &Client<MemoryFileSystem>,
    token: &str,
    cipher: &Value,
    name: &str,
) -> LocalResponse {
    let path = format!("ciphers/{}", id(cipher));
    let update = json!({
        "type": 1,
        "name": name,
        "lastKnownRevisionDate": cipher["revisionDate"],
    });
    client.send("PUT", &path, token, update)
}

fn id(item: &Value) -> &str {
    item["id"].as_str().unwrap()
}

/// The key of an item in the file of a device.
fn cipher_key(cipher: &Value) -> String {
    format!("cipher:{}", id(cipher))
}

/// Changes the master password to the one of [`NEW_HASH`].
fn change_password(client: &Client<MemoryFileSystem>, token: &str) -> LocalResponse {
    change_password_of(client, token, EMAIL, PASSWORD_HASH)
}

/// Changes the master password of the account with the email from the one of the hash to the one
/// of [`NEW_HASH`].
fn change_password_of(
    client: &Client<MemoryFileSystem>,
    token: &str,
    email: &str,
    password_hash: &str,
) -> LocalResponse {
    let kdf = json!({"kdfType": 0, "iterations": 600000});
    let change = json!({
        "masterPasswordHash": password_hash,
        "authenticationData": {
            "salt": email,
            "kdf": kdf,
            "masterPasswordAuthenticationHash": NEW_HASH,
        },
        "unlockData": {"salt": email, "kdf": kdf, "masterKeyWrappedUserKey": "2.newUserKey"},
    });
    client.send("POST", "accounts/password", token, change)
}

/// Adds an attachment to the item and uploads its content, and returns where the content is
/// downloaded from.
fn upload_attachment(client: &Client<MemoryFileSystem>, token: &str, cipher_id: &str) -> String {
    let path = format!("ciphers/{cipher_id}/attachment/v2");
    let attachment = json!({"fileName": "2.fileName", "key": "2.key", "fileSize": 1});
    let upload = body(&client.send("POST", &path, token, attachment));
    let content_path = path_of(upload["url"].as_str().unwrap());
    let uploaded = client.request("PUT", &content_path).bytes(&[1]).send();
    assert_eq!(uploaded.code, 201);
    content_path
}

#[test]
fn no_local_server_is_made_for_a_device_id_that_cannot_be_the_name_of_a_directory() {
    let long = "x".repeat(129);
    for device_id in ["", "..", "a/b", "a.b", "a b", long.as_str()] {
        let fs = MemoryFileSystem::new();
        let platform = TestPlatform::at(NOON);
        let server = LocalServer::new(fs, platform, ClientKind::Browser, device_id, "chrome", 2);
        assert!(server.is_err(), "{device_id}");
    }
}

#[test]
fn changes_to_different_items_on_two_devices_are_both_kept() {
    let (devices, token, _) = Devices::registered();
    let first = create_cipher(&devices.a, &token, "2.first");
    devices.sync_files();

    // Each device changes the vault before the changes of the other one have come to it.
    devices.a.platform.set_now(NOON + MINUTE);
    devices.b.platform.set_now(NOON + 2 * MINUTE);
    let renamed = update_cipher(&devices.a, &token, &first, "2.renamed");
    create_cipher(&devices.b, &token, "2.second");
    let folder = json!({"name": "2.folder"});
    devices.b.send("POST", "folders", &token, folder);
    devices.sync_files();

    assert_eq!(renamed.code, 200);
    for client in devices.clients() {
        let vault = sync(client, &token);
        assert_eq!(names(&vault["ciphers"]), ["2.renamed", "2.second"]);
        assert_eq!(names(&vault["folders"]), ["2.folder"]);
    }
    assert_eq!(sync(&devices.a, &token), sync(&devices.b, &token));
}

#[test]
fn of_two_changes_to_the_same_item_the_later_one_is_kept() {
    let (devices, token, _) = Devices::registered();
    let cipher = create_cipher(&devices.a, &token, "2.first");
    devices.sync_files();

    devices.a.platform.set_now(NOON + 2 * MINUTE);
    devices.b.platform.set_now(NOON + MINUTE);
    let later = update_cipher(&devices.a, &token, &cipher, "2.later");
    let earlier = update_cipher(&devices.b, &token, &cipher, "2.earlier");
    devices.sync_files();

    assert_eq!(later.code, 200);
    assert_eq!(earlier.code, 200);
    for client in devices.clients() {
        assert_eq!(names(&sync(client, &token)["ciphers"]), ["2.later"]);
    }
}

#[test]
fn a_change_that_is_made_after_another_one_is_kept_even_where_the_clock_is_behind() {
    let (devices, token, _) = Devices::registered();
    let cipher = create_cipher(&devices.a, &token, "2.first");
    devices.a.platform.set_now(NOON + 10 * MINUTE);
    let updated = body(&update_cipher(&devices.a, &token, &cipher, "2.second"));
    devices.sync_files();

    // The clock of the other device is five minutes behind.
    devices.b.platform.set_now(NOON + 5 * MINUTE);
    let made_after = update_cipher(&devices.b, &token, &updated, "2.third");
    devices.sync_files();

    assert_eq!(made_after.code, 200);
    for client in devices.clients() {
        assert_eq!(names(&sync(client, &token)["ciphers"]), ["2.third"]);
    }
}

#[test]
fn an_item_that_is_deleted_on_one_device_stays_deleted_unless_another_one_changed_it_later() {
    for (deleted_at, changed_at, is_kept) in [(2, 1, false), (1, 2, true)] {
        let (devices, token, _) = Devices::registered();
        let cipher = create_cipher(&devices.a, &token, "2.first");
        devices.sync_files();

        devices.a.platform.set_now(NOON + deleted_at * MINUTE);
        devices.b.platform.set_now(NOON + changed_at * MINUTE);
        let path = format!("ciphers/{}", id(&cipher));
        let deleted = devices.a.call("DELETE", &path, &token);
        let changed = update_cipher(&devices.b, &token, &cipher, "2.changed");
        devices.sync_files();

        assert_eq!(deleted.code, 200);
        assert_eq!(changed.code, 200);
        let expected: &[&str] = if is_kept { &["2.changed"] } else { &[] };
        for client in devices.clients() {
            assert_eq!(names(&sync(client, &token)["ciphers"]), expected);
        }
    }
}

#[test]
fn an_item_that_is_put_in_a_folder_that_another_device_deleted_is_in_none() {
    let (devices, token, _) = Devices::registered();
    let folder = json!({"name": "2.folder"});
    let folder = body(&devices.a.send("POST", "folders", &token, folder));
    let cipher = create_cipher(&devices.a, &token, "2.item");
    devices.sync_files();

    let folder_path = format!("folders/{}", id(&folder));
    let deleted = devices.a.call("DELETE", &folder_path, &token);
    let partial = format!("ciphers/{}/partial", id(&cipher));
    let into_folder = json!({"folderId": folder["id"], "favorite": false});
    let moved = devices.b.send("PUT", &partial, &token, into_folder);
    devices.sync_files();

    assert_eq!(deleted.code, 200);
    assert_eq!(moved.code, 200);
    for client in devices.clients() {
        let vault = sync(client, &token);
        assert_eq!(vault["folders"], json!([]));
        assert_eq!(vault["ciphers"][0]["folderId"], Value::Null);
    }

    // The deletion of the folder is not forgotten while the other device holds the item in it,
    // which would then be in a folder that is not there.
    devices.a.platform.set_now(NOON + GRACE + DAY);
    sync(&devices.a, &token);
    devices.sync_files();
    for client in devices.clients() {
        assert_eq!(sync(client, &token)["ciphers"][0]["folderId"], Value::Null);
    }
}

#[test]
fn a_change_of_an_item_is_kept_when_another_device_deletes_its_folder_later() {
    let (devices, token, _) = Devices::registered();
    let folder = json!({"name": "2.folder"});
    let folder = body(&devices.a.send("POST", "folders", &token, folder));
    let in_folder = json!({"type": 1, "name": "2.item", "folderId": folder["id"]});
    let cipher = body(&devices.a.send("POST", "ciphers", &token, in_folder));
    devices.sync_files();

    // The other device changes the item before the deletion of its folder has come to it, which
    // is made later.
    devices.a.platform.set_now(NOON + 2 * MINUTE);
    devices.b.platform.set_now(NOON + MINUTE);
    let folder_path = format!("folders/{}", id(&folder));
    let deleted = devices.a.call("DELETE", &folder_path, &token);
    let change = json!({
        "type": 1,
        "name": "2.changed",
        "folderId": folder["id"],
        "lastKnownRevisionDate": cipher["revisionDate"],
    });
    let path = format!("ciphers/{}", id(&cipher));
    let changed = devices.b.send("PUT", &path, &token, change);
    devices.sync_files();

    assert_eq!(deleted.code, 200);
    assert_eq!(changed.code, 200);
    for client in devices.clients() {
        let vault = sync(client, &token);
        assert_eq!(vault["folders"], json!([]));
        assert_eq!(names(&vault["ciphers"]), ["2.changed"]);
        assert_eq!(vault["ciphers"][0]["folderId"], Value::Null);
    }
}

#[test]
fn the_revision_date_is_now_once_the_changes_of_another_device_have_come() {
    let (devices, token, _) = Devices::registered();
    devices.a.get("sync", &token);
    let revision_date = || body(&devices.a.get("accounts/revision-date", &token));
    assert_eq!(revision_date(), NOON);

    devices.b.platform.set_now(NOON + MINUTE);
    create_cipher(&devices.b, &token, "2.item");
    devices.sync_files();
    devices.a.platform.set_now(NOON + 5 * MINUTE);

    assert_eq!(revision_date(), NOON + 5 * MINUTE);
    assert_eq!(names(&sync(&devices.a, &token)["ciphers"]), ["2.item"]);
    assert_eq!(revision_date(), NOON + MINUTE);
}

#[test]
fn a_device_writes_only_its_own_files() {
    let (devices, token, user_id) = Devices::registered();

    create_cipher(&devices.b, &token, "2.item");
    let folder = json!({"name": "2.folder"});
    devices.b.send("POST", "folders", &token, folder);

    let differs = |path: &Vec<String>| {
        let names = strs(path);
        devices.a_fs.get(&names) != devices.b_fs.get(&names)
    };
    let changed: Vec<Vec<String>> = devices.b_fs.paths().into_iter().filter(differs).collect();
    assert!(!changed.is_empty());
    for path in changed {
        assert_eq!(
            path[..3],
            [user_id.as_str(), "devices", OTHER_DEVICE],
            "{path:?}"
        );
    }
    assert!(devices.a_fs.paths().iter().all(|path| !differs(path)));
}

#[test]
fn the_email_of_an_account_of_which_only_the_vault_json_has_come_is_not_taken_to_be_free() {
    let devices = Devices::new();
    // The account has other KDF settings than the ones that an email without an account gets.
    let mut registered = registration(EMAIL, PASSWORD_HASH);
    for data in ["masterPasswordAuthentication", "masterPasswordUnlock"] {
        registered[data]["kdf"]["iterations"] = json!(700_000);
    }
    let path = "accounts/register/finish";
    assert_eq!(devices.a.send_anonymous("POST", path, registered).code, 200);
    let user_id = logged_in_id(&body(&devices.a.log_in(EMAIL, PASSWORD_HASH)));

    // Of what the first device wrote, only the `vault.json` of the account has come to the other
    // device.
    let root = [user_id.as_str(), "vault.json"];
    devices.b_fs.put(&root, devices.a_fs.get(&root).unwrap());
    let email = json!({"email": EMAIL});
    let prelogin = || {
        let request = devices.b.request("POST", "accounts/prelogin");
        request.json(email.clone()).try_send()
    };
    let form = [
        ("grant_type", "password"),
        ("username", EMAIL),
        ("password", PASSWORD_HASH),
    ];
    let logged_in = devices
        .b
        .request("POST", "connect/token")
        .form(&form)
        .try_send();
    let register = devices.b.request("POST", path);
    let registered = register.json(registration(EMAIL, PASSWORD_HASH)).try_send();

    // The client is not told how the master key of an account that does not have the email is
    // derived, that the master password is wrong, or that the email is free: each fails as a
    // request that did not reach the server, until the file of the first device has come.
    assert!(prelogin().is_err());
    assert!(logged_in.is_err());
    assert!(registered.is_err());
    assert_eq!(devices.b_fs.paths(), [root]);
    devices.sync_files();
    assert_eq!(body(&prelogin().unwrap())["kdfIterations"], 700_000);
    assert_eq!(devices.b.log_in(EMAIL, PASSWORD_HASH).code, 200);
}

#[test]
fn an_email_is_not_taken_to_be_free_while_only_files_without_the_record_have_come() {
    let (devices, token, user_id) = Devices::registered();
    let folder = json!({"name": "2.folder"});
    assert_eq!(devices.b.send("POST", "folders", &token, folder).code, 200);

    // A third device has the file of the other device, which does not hold the record of the
    // account, but neither the file of the first device nor the `vault.json` of the account.
    let c_fs = MemoryFileSystem::new();
    deliver(&devices.b_fs, OTHER_DEVICE, &c_fs);
    block_on(c_fs.delete(&[user_id.as_str(), "devices", DEVICE])).unwrap();
    block_on(c_fs.delete(&[user_id.as_str(), "vault.json"])).unwrap();
    let b_file = read_json(&c_fs, &device_file(&user_id, OTHER_DEVICE));
    assert!(b_file["records"].get("account").is_none());
    let c_platform = TestPlatform::seeded(NOON, 1 << 50);
    let c = Client::on_device(c_fs.clone(), c_platform, ClientKind::Android, "device-c");
    let email = json!({"email": EMAIL});
    let prelogin = || {
        let request = c.request("POST", "accounts/prelogin");
        request.json(email.clone()).try_send()
    };
    let register = c.request("POST", "accounts/register/finish");
    let registered = register.json(registration(EMAIL, PASSWORD_HASH)).try_send();

    // The client is not told how the master key of an account that does not have the email is
    // derived, or that the email is free: both fail as requests that did not reach the server,
    // until the other files have come.
    assert!(prelogin().is_err());
    assert!(registered.is_err());
    deliver(&devices.b_fs, OTHER_DEVICE, &c_fs);
    assert_eq!(prelogin().unwrap().code, 200);
    assert_eq!(c.log_in(EMAIL, PASSWORD_HASH).code, 200);
}

#[test]
fn an_account_that_is_deleted_stays_deleted_on_a_device_that_changed_it_in_the_meantime() {
    let (devices, token, user_id) = Devices::registered();
    let password = json!({"MasterPasswordHash": PASSWORD_HASH});
    let deleted = devices.a.send("DELETE", "accounts", &token, password);
    // The other device changes the vault before the deletion has come to it.
    create_cipher(&devices.b, &token, "2.item");

    // Then the deletion comes: the file of the first device is deleted, and the `vault.json` of
    // the account says that it was deleted. The file of the other device is not deleted, as that
    // device wrote it after the deletion.
    devices.sync_files();
    let root = [user_id.as_str(), "vault.json"];
    devices.b_fs.put(&root, devices.a_fs.get(&root).unwrap());

    assert_eq!(deleted.code, 200);
    for client in devices.clients() {
        assert_eq!(client.get("sync", &token).code, 401);
        assert_eq!(client.log_in(EMAIL, PASSWORD_HASH).code, 400);
    }
    // The email is free again, which it would not be if the account were taken to be on its way.
    devices.b.register();
}

#[test]
fn an_account_is_not_logged_out_while_the_newer_master_password_is_on_its_way() {
    let (devices, token, user_id) = Devices::registered();
    assert_eq!(change_password(&devices.b, &token).code, 200);
    devices.sync_files();
    // The first device leaves the master password out of its file when it syncs, as the other
    // device holds a newer one, but not the rest of the account, which the other device did not
    // change.
    sync(&devices.a, &token);
    let a_file = read_json(&devices.a_fs, &device_file(&user_id, DEVICE));
    assert!(a_file["records"].get("masterPassword").is_none());
    assert!(a_file["records"].get("account").is_some());

    // A third device gets the file of the first device before that of the other one.
    let c_fs = MemoryFileSystem::new();
    deliver(&devices.a_fs, DEVICE, &c_fs);
    block_on(c_fs.delete(&[user_id.as_str(), "devices", OTHER_DEVICE])).unwrap();
    let c_platform = TestPlatform::seeded(NOON, 1 << 50);
    let c = Client::on_device(c_fs.clone(), c_platform, ClientKind::Android, "device-c");

    assert!(c.request("GET", "sync").token(&token).try_send().is_err());
    deliver(&devices.b_fs, OTHER_DEVICE, &c_fs);
    assert_eq!(c.log_in(EMAIL, NEW_HASH).code, 200);
    let vault = sync(&c, &token);
    assert_eq!(vault["profile"]["key"], "2.newUserKey");
}

#[test]
fn a_change_of_the_account_on_a_device_without_the_new_master_password_does_not_undo_it() {
    let (devices, token, _) = Devices::registered();
    devices.a.platform.set_now(NOON + MINUTE);
    devices.b.platform.set_now(NOON + 2 * MINUTE);

    // The first device changes the master password. The other one, which does not have the
    // change yet, records the ID of the user key later, as the SDK of the browser extension does.
    assert_eq!(change_password(&devices.a, &token).code, 200);
    let record = json!({"userKeyId": "user-key-id"});
    let path = "accounts/key-management/user-key-id";
    assert_eq!(devices.b.send("POST", path, &token, record).code, 200);
    devices.sync_files();

    // Both changes are kept, and the old master password is not brought back.
    for client in devices.clients() {
        assert_eq!(client.log_in(EMAIL, PASSWORD_HASH).code, 400);
        assert_eq!(client.log_in(EMAIL, NEW_HASH).code, 200);
        let vault = sync(client, &token);
        assert_eq!(vault["profile"]["key"], "2.newUserKey");
        assert_eq!(vault["userDecryption"]["userKeyId"], "user-key-id");
    }
    assert_eq!(sync(&devices.a, &token), sync(&devices.b, &token));
}

#[test]
fn the_attachments_of_an_item_that_another_device_brings_back_keep_their_content() {
    let (devices, token, user_id) = Devices::registered();
    let cipher = create_cipher(&devices.a, &token, "2.first");
    let content_path = upload_attachment(&devices.a, &token, id(&cipher));
    devices.sync_files();
    let cipher = sync(&devices.b, &token)["ciphers"][0].clone();

    // The first device deletes the item, and the other one, which has not seen the deletion yet,
    // changes it later.
    devices.a.platform.set_now(NOON + MINUTE);
    devices.b.platform.set_now(NOON + 2 * MINUTE);
    let path = format!("ciphers/{}", id(&cipher));
    assert_eq!(devices.a.call("DELETE", &path, &token).code, 200);
    assert_eq!(
        update_cipher(&devices.b, &token, &cipher, "2.changed").code,
        200
    );
    devices.sync_files();
    devices.a.platform.set_now(NOON + GRACE + DAY);
    let vault = sync(&devices.a, &token);

    assert_eq!(names(&vault["ciphers"]), ["2.changed"]);
    assert_eq!(devices.a.download(&content_path).unwrap(), [1]);
    let a_file = read_json(&devices.a_fs, &device_file(&user_id, DEVICE));
    assert_eq!(a_file["removedAttachments"], json!({}));
}

#[test]
fn purging_the_vault_keeps_the_attachments_of_an_item_whose_file_has_not_come_yet() {
    let (devices, token, _) = Devices::registered();
    let cipher = create_cipher(&devices.b, &token, "2.other");
    let content_path = upload_attachment(&devices.b, &token, id(&cipher));
    // The content of the attachment comes to the first device before the file of the other one.
    for path in devices.b_fs.paths() {
        if path.get(1).is_some_and(|name| name == "attachments") {
            let names = strs(&path);
            devices.a_fs.put(&names, devices.b_fs.get(&names).unwrap());
        }
    }

    let purge = json!({"masterPasswordHash": PASSWORD_HASH});
    assert_eq!(
        devices.a.send("POST", "ciphers/purge", &token, purge).code,
        200
    );
    devices.sync_files();
    devices.a.platform.set_now(NOON + GRACE + DAY);
    sync(&devices.a, &token);

    assert_eq!(names(&sync(&devices.a, &token)["ciphers"]), ["2.other"]);
    assert_eq!(devices.a.download(&content_path).unwrap(), [1]);
}

#[test]
fn a_device_leaves_out_of_its_file_an_item_that_another_device_changed() {
    let (devices, token, user_id) = Devices::registered();
    let cipher = create_cipher(&devices.a, &token, "2.first");
    devices.sync_files();
    let changed = update_cipher(&devices.b, &token, &cipher, "2.second");
    devices.sync_files();
    let file = || read_json(&devices.a_fs, &device_file(&user_id, DEVICE));
    assert_eq!(changed.code, 200);
    assert!(file()["records"].get(cipher_key(&cipher)).is_some());

    // A device looks at its file when it syncs, and leaves the item out once every device has
    // had time to get the change.
    let vault = sync(&devices.a, &token);
    assert_eq!(names(&vault["ciphers"]), ["2.second"]);
    assert!(file()["records"].get(cipher_key(&cipher)).is_some());
    devices.a.platform.set_now(NOON + GRACE + MINUTE);
    let vault = sync(&devices.a, &token);

    assert_eq!(names(&vault["ciphers"]), ["2.second"]);
    assert!(file()["records"].get(cipher_key(&cipher)).is_none());
    assert_eq!(file()["sync"]["ciphers"], json!([]));
    assert_eq!(names(&sync(&devices.b, &token)["ciphers"]), ["2.second"]);
}

#[test]
fn an_item_that_another_device_changed_stays_on_a_device_that_gets_the_files_out_of_order() {
    let (devices, token, user_id) = Devices::registered();
    let cipher = create_cipher(&devices.a, &token, "2.first");
    devices.sync_files();
    let changed = update_cipher(&devices.b, &token, &cipher, "2.second");
    devices.sync_files();
    // The first device writes its file again once it has the change of the other one.
    create_cipher(&devices.a, &token, "2.other");

    // A third device gets that file before the file of the other device.
    let c_fs = MemoryFileSystem::new();
    deliver(&devices.a_fs, DEVICE, &c_fs);
    block_on(c_fs.delete(&[user_id.as_str(), "devices", OTHER_DEVICE])).unwrap();
    let c_platform = TestPlatform::seeded(NOON, 1 << 50);
    let c = Client::on_device(c_fs.clone(), c_platform, ClientKind::Android, "device-c");
    let ciphers = || names(&sync(&c, &token)["ciphers"]);

    // It has the item as it was before the change, until the change comes.
    assert_eq!(changed.code, 200);
    assert_eq!(ciphers(), ["2.first", "2.other"]);
    deliver(&devices.b_fs, OTHER_DEVICE, &c_fs);
    assert_eq!(ciphers(), ["2.second", "2.other"]);
}

#[test]
fn a_deleted_item_stays_deleted_on_a_device_that_gets_the_files_out_of_order() {
    let (devices, token, user_id) = Devices::registered();
    // The other device creates the item, and the first one changes it. The other device keeps
    // the version that it created, as the change has not been in the file of the first one for
    // 90 days.
    let cipher = create_cipher(&devices.b, &token, "2.first");
    devices.sync_files();
    devices.a.platform.set_now(NOON + MINUTE);
    let changed = update_cipher(&devices.a, &token, &cipher, "2.changed");
    assert_eq!(changed.code, 200);
    devices.sync_files();
    // A third device has the files of both as they are now.
    let c_fs = MemoryFileSystem::new();
    deliver(&devices.a_fs, DEVICE, &c_fs);
    deliver(&devices.b_fs, OTHER_DEVICE, &c_fs);
    let c_platform = TestPlatform::seeded(NOON + 4 * MINUTE, 1 << 50);
    let c = Client::on_device(c_fs.clone(), c_platform, ClientKind::Android, "device-c");
    assert_eq!(names(&sync(&c, &token)["ciphers"]), ["2.changed"]);

    // The other device deletes the item, which puts the deletion in place of the version that it
    // created. The first device puts the deletion in place of its change when it next writes.
    devices.b.platform.set_now(NOON + 2 * MINUTE);
    let path = format!("ciphers/{}", id(&cipher));
    assert_eq!(devices.b.call("DELETE", &path, &token).code, 200);
    deliver(&devices.b_fs, OTHER_DEVICE, &devices.a_fs);
    devices.a.platform.set_now(NOON + 3 * MINUTE);
    create_cipher(&devices.a, &token, "2.other");
    let a_file = read_json(&devices.a_fs, &device_file(&user_id, DEVICE));
    assert!(a_file["records"].get(cipher_key(&cipher)).is_none());
    assert!(a_file["tombstones"].get(cipher_key(&cipher)).is_some());

    // The third device gets the new file of the first device before the new one of the other
    // device, and still has the file of the other device from before, with the version that it
    // created. It does not take that version for the item, so a change of the item there, which
    // would bring it back for every device, cannot be made.
    deliver(&devices.a_fs, DEVICE, &c_fs);

    assert_eq!(names(&sync(&c, &token)["ciphers"]), ["2.other"]);
    assert_eq!(update_cipher(&c, &token, &cipher, "2.edited").code, 404);
}

#[test]
fn a_deletion_is_kept_while_another_device_holds_the_item() {
    let (devices, token, user_id) = Devices::registered();
    let cipher = create_cipher(&devices.a, &token, "2.item");
    devices.sync_files();
    let path = format!("ciphers/{}", id(&cipher));
    assert_eq!(devices.b.call("DELETE", &path, &token).code, 200);
    let file = || read_json(&devices.b_fs, &device_file(&user_id, OTHER_DEVICE));

    // The other device has not synced since, so its file still holds the item.
    devices.b.platform.set_now(NOON + GRACE + DAY);
    let vault = sync(&devices.b, &token);

    assert_eq!(vault["ciphers"], json!([]));
    assert!(file()["tombstones"].get(cipher_key(&cipher)).is_some());
}

#[test]
fn a_deletion_is_forgotten_after_a_grace_period_once_no_device_holds_the_item() {
    let (devices, token, user_id) = Devices::registered();
    let cipher = create_cipher(&devices.a, &token, "2.item");
    devices.sync_files();
    let path = format!("ciphers/{}", id(&cipher));
    assert_eq!(devices.b.call("DELETE", &path, &token).code, 200);
    devices.sync_files();
    let file = || read_json(&devices.b_fs, &device_file(&user_id, OTHER_DEVICE));
    let has_deletion = || file()["tombstones"].get(cipher_key(&cipher)).is_some();

    // The first device puts the deletion in place of the item in its file when it syncs.
    devices.a.platform.set_now(NOON + DAY);
    sync(&devices.a, &token);
    devices.sync_files();
    let a_file = || read_json(&devices.a_fs, &device_file(&user_id, DEVICE));
    let a_has_deletion = || a_file()["tombstones"].get(cipher_key(&cipher)).is_some();
    assert!(a_file()["records"].get(cipher_key(&cipher)).is_none());
    assert!(a_has_deletion());

    devices.b.platform.set_now(NOON + 2 * DAY);
    sync(&devices.b, &token);
    assert!(has_deletion());

    // Both forget it once it is old enough.
    devices.b.platform.set_now(NOON + GRACE + DAY);
    sync(&devices.b, &token);
    assert!(!has_deletion());
    devices.a.platform.set_now(NOON + GRACE + DAY);
    sync(&devices.a, &token);
    assert!(!a_has_deletion());
    devices.sync_files();
    for client in devices.clients() {
        assert_eq!(sync(client, &token)["ciphers"], json!([]));
    }
}
