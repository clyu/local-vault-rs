//! Retiring a device that is gone for good: another device takes its file over, and its directory
//! is deleted 90 days later. Each device has a copy of the vault folder, writes only its own files
//! in it, and gets the files of the others some time later.

#![allow(clippy::unwrap_used, clippy::indexing_slicing)]

mod common;

use common::*;
use futures::executor::block_on;
use local_vault::{ClientKind, FileSystem, LocalResponse, MemoryFileSystem};
use serde_json::{Value, json};

const OLD: &str = "device-old";

const NEW_HASH: &str = "bmV3LWhhc2g=";

const INCOMPLETE: &[u8] = b"{\"format\": \"bitwarden-loc";

/// A device that shares the vault folder, with its own copy of it.
struct Device {
    id: &'static str,
    client: Client<MemoryFileSystem>,
    fs: MemoryFileSystem,
}

impl Device {
    /// An installation of the extension.
    fn new(id: &'static str, seed: u64) -> Self {
        Self::of(ClientKind::Browser, id, seed)
    }

    fn of(kind: ClientKind, id: &'static str, seed: u64) -> Self {
        let fs = MemoryFileSystem::new();
        let platform = TestPlatform::seeded(NOON, seed);
        let client = Client::on_device(fs.clone(), platform, kind, id);
        Self { id, client, fs }
    }

    /// The device that registers the account, holds the records of the account and of its master
    /// password, and is gone for good after the test sets it up.
    fn old() -> Self {
        Self::new(OLD, 1)
    }

    fn at(&self, millis: i64) {
        self.client.platform.set_now(millis);
    }

    /// Brings the files that this device wrote to the copy of the other one.
    fn deliver_to(&self, other: &Device) {
        deliver(&self.fs, self.id, &other.fs);
    }

    fn sync(&self, token: &str) -> Value {
        body(&self.client.get("sync", token))
    }

    fn devices(&self, token: &str) -> Value {
        body(&self.client.get("local-vault/devices", token))["data"].clone()
    }

    /// The device as this one lists it.
    fn listed(&self, token: &str, device_id: &str) -> Value {
        let devices = self.devices(token);
        let mut devices = devices.as_array().unwrap().iter();
        devices
            .find(|device| device["id"] == device_id)
            .unwrap()
            .clone()
    }

    fn retire(&self, token: &str, device_id: &str) -> LocalResponse {
        let path = format!("local-vault/devices/{device_id}/retire");
        self.client.call("POST", &path, token)
    }

    fn has_directory(&self, user_id: &str, device_id: &str) -> bool {
        block_on(self.fs.exists(&[user_id, "devices", device_id])).unwrap()
    }

    /// The file of the vault of the account that this device writes.
    fn file(&self, user_id: &str) -> Value {
        read_json(&self.fs, &device_file(user_id, self.id))
    }
}

/// Brings the files that every device wrote to every other one.
fn sync_files(devices: &[&Device]) {
    for from in devices {
        for to in devices.iter().filter(|to| to.id != from.id) {
            from.deliver_to(to);
        }
    }
}

fn create_cipher(device: &Device, token: &str, name: &str) -> Value {
    let cipher = json!({"type": 1, "name": name});
    body(&device.client.send("POST", "ciphers", token, cipher))
}

fn names(list: &Value) -> Vec<Value> {
    let items = list.as_array().unwrap().iter();
    items.map(|item| item["name"].clone()).collect()
}

/// The names of the items in the order of the names: a vault has its items in the order of the
/// files that they were first read in, which a file that takes another one over changes.
fn sorted_names(list: &Value) -> Vec<String> {
    let names = names(list).into_iter();
    let names = names.map(|name| name.as_str().unwrap().to_owned());
    let mut names: Vec<String> = names.collect();
    names.sort();
    names
}

fn ids(list: &Value) -> Vec<Value> {
    let items = list.as_array().unwrap().iter();
    items.map(|item| item["id"].clone()).collect()
}

fn id(item: &Value) -> &str {
    item["id"].as_str().unwrap()
}

/// The key of an item or a folder in the file of a device.
fn key(prefix: &str, item: &Value) -> String {
    format!("{prefix}:{}", id(item))
}

#[test]
fn a_device_that_is_gone_for_good_is_retired_and_the_vault_stays_the_same() {
    let old = Device::old();
    let a = Device::new("device-a", 1 << 20);
    let b = Device::new("device-b", 1 << 40);
    let (token, user_id) = old.client.register_and_log_in();
    old.at(NOON + MINUTE);
    create_cipher(&old, &token, "2.first");
    sync_files(&[&old, &a, &b]);
    a.at(NOON + 2 * MINUTE);
    create_cipher(&a, &token, "2.second");
    b.at(NOON + 3 * MINUTE);
    b.client
        .send("POST", "folders", &token, json!({"name": "2.folder"}));
    sync_files(&[&a, &b]);
    let before = a.sync(&token);
    assert_eq!(a.file(&user_id)["version"], 2);

    a.at(NOON + DAY);
    let retired = a.retire(&token, OLD);

    let expected = json!({
        "object": "localVaultDevice",
        "id": OLD,
        "name": "chrome",
        "type": 2,
        "isCurrentDevice": false,
        "revisionDate": "2026-10-11T12:01:00.000Z",
        "retiredDate": "2026-10-12T12:00:00.000Z",
        "removalDate": "2027-01-10T12:00:00.000Z",
    });
    assert_eq!(retired.code, 200);
    assert_eq!(body(&retired), expected);
    // This device took over what the other one held, as it held it, and the vault is the same.
    let file = a.file(&user_id);
    assert_eq!(file["version"], 3);
    assert_eq!(file["records"]["account"]["by"], OLD);
    assert_eq!(file["records"]["masterPassword"]["by"], OLD);
    let retirement = json!({"at": NOON + DAY, "revisionDate": "2026-10-11T12:01:00.000Z"});
    assert_eq!(file["retiredDevices"], json!({OLD: retirement}));
    a.deliver_to(&b);
    for device in [&a, &b] {
        assert_eq!(device.sync(&token), before);
        let devices = device.devices(&token);
        assert_eq!(ids(&devices), ["device-a", "device-b", OLD]);
        assert_eq!(device.listed(&token, OLD), expected);
        assert_eq!(device.listed(&token, device.id)["isCurrentDevice"], true);
    }
    // Retiring it again changes nothing.
    let file = a.file(&user_id);
    assert_eq!(body(&a.retire(&token, OLD)), expected);
    assert_eq!(a.file(&user_id), file);

    // Its directory is deleted 90 days later, by the first device that tidies its file then.
    b.at(NOON + DAY + GRACE - MINUTE);
    b.sync(&token);
    assert!(b.has_directory(&user_id, OLD));
    b.at(NOON + 2 * DAY + GRACE);
    assert_eq!(b.sync(&token), before);
    assert!(!b.has_directory(&user_id, OLD));
    deliver_deletion(&b.fs, &user_id, OLD, &a.fs);
    for device in [&a, &b] {
        assert_eq!(device.sync(&token), before);
        assert_eq!(device.client.log_in(EMAIL, PASSWORD_HASH).code, 200);
        assert_eq!(ids(&device.devices(&token)), ["device-a", "device-b"]);
    }
}

#[test]
fn a_deletion_that_only_a_device_that_is_gone_kept_is_forgotten_once_that_device_is_retired() {
    let old = Device::old();
    let a = Device::new("device-a", 1 << 20);
    let (token, user_id) = old.client.register_and_log_in();
    let cipher = create_cipher(&old, &token, "2.item");
    sync_files(&[&old, &a]);
    a.at(NOON + MINUTE);
    let path = format!("ciphers/{}", id(&cipher));
    assert_eq!(a.client.call("DELETE", &path, &token).code, 200);
    let has_deletion = || {
        a.file(&user_id)["tombstones"]
            .get(key("cipher", &cipher))
            .is_some()
    };

    // The device that is gone holds the item, and never puts the deletion in its place.
    a.at(NOON + GRACE + DAY);
    a.sync(&token);
    assert!(has_deletion());
    a.at(NOON + GRACE + 2 * DAY);
    assert_eq!(a.retire(&token, OLD).code, 200);
    // The file of the device still counts until every device has had time to get the note.
    a.at(NOON + 2 * GRACE + DAY);
    a.sync(&token);
    assert!(has_deletion());
    assert!(a.has_directory(&user_id, OLD));
    a.at(NOON + 2 * GRACE + 3 * DAY);
    let vault = a.sync(&token);

    assert!(!has_deletion());
    assert!(!a.has_directory(&user_id, OLD));
    assert_eq!(vault["ciphers"], json!([]));
    assert_eq!(a.sync(&token)["ciphers"], json!([]));
}

#[test]
fn an_item_that_was_deleted_stays_deleted_on_a_device_whose_clock_is_behind() {
    let old = Device::old();
    let a = Device::new("device-a", 1 << 20);
    let b = Device::new("device-b", 1 << 40);
    let (token, user_id) = old.client.register_and_log_in();
    let cipher = create_cipher(&old, &token, "2.item");
    sync_files(&[&old, &a, &b]);
    a.at(NOON + MINUTE);
    let path = format!("ciphers/{}", id(&cipher));
    assert_eq!(a.client.call("DELETE", &path, &token).code, 200);
    a.at(NOON + DAY);
    assert_eq!(a.retire(&token, OLD).code, 200);

    // The clock of the device that retired the other one is ahead: it forgets the deletion, which
    // only the item in the file of the retired device kept, and deletes the directory of that
    // device. The device whose clock is behind gets its file before the deletion of the directory.
    a.at(NOON + DAY + GRACE + DAY);
    a.sync(&token);
    assert!(
        a.file(&user_id)["tombstones"]
            .get(key("cipher", &cipher))
            .is_none()
    );
    assert!(!a.has_directory(&user_id, OLD));
    a.deliver_to(&b);

    // It leaves out the file of the retired device as well, whatever its clock says.
    assert!(b.has_directory(&user_id, OLD));
    assert_eq!(b.sync(&token)["ciphers"], json!([]));
}

#[test]
fn a_device_that_is_retired_but_still_in_use_is_not_retired_anymore_once_it_syncs() {
    let old = Device::old();
    let a = Device::new("device-a", 1 << 20);
    let (token, user_id) = old.client.register_and_log_in();
    sync_files(&[&old, &a]);
    a.at(NOON + MINUTE);
    assert_eq!(a.retire(&token, OLD).code, 200);
    a.deliver_to(&old);

    // It writes its file again when it syncs, which makes the note one about the file before.
    old.at(NOON + DAY);
    old.sync(&token);
    old.deliver_to(&a);

    assert_eq!(a.listed(&token, OLD)["retiredDate"], Value::Null);
    assert_eq!(old.listed(&token, OLD)["retiredDate"], Value::Null);
    a.at(NOON + GRACE + DAY);
    a.sync(&token);
    assert!(a.has_directory(&user_id, OLD));
    old.at(NOON + GRACE + 2 * DAY);
    create_cipher(&old, &token, "2.later");
    old.deliver_to(&a);
    assert_eq!(names(&a.sync(&token)["ciphers"]), ["2.later"]);
}

#[test]
fn a_device_that_only_reads_the_vault_is_listed_by_what_its_client_names_it_once_it_syncs() {
    let old = Device::old();
    let phone = Device::of(ClientKind::Android, "device-phone", 1 << 20);
    let a = Device::new("device-a", 1 << 40);
    let (token, user_id) = old.client.register_and_log_in();
    sync_files(&[&old, &phone]);
    phone.at(NOON + MINUTE);
    create_cipher(&phone, &token, "2.item");
    // An earlier version of the app wrote the file, which does not say what the device is. It has
    // the field of another device instead, which it took for part of the record of the account.
    let mut file = phone.file(&user_id);
    file["device"] = json!({"id": OLD, "name": "chrome", "type": 2});
    let path = device_file(&user_id, phone.id);
    phone.fs.put(&path, file.to_string());
    sync_files(&[&old, &phone, &a]);

    let listed = a.listed(&token, phone.id);
    assert_eq!(listed["name"], Value::Null);
    assert_eq!(listed["type"], Value::Null);
    // This device is listed as what it is, although it has no file yet, and so is the one whose
    // file says so.
    let this = a.listed(&token, a.id);
    assert_eq!(this["name"], "chrome");
    assert_eq!(this["type"], 2);
    assert_eq!(a.listed(&token, OLD)["name"], "chrome");

    // The app is updated, and only reads the vault from then on: it says what the device is the
    // first time that it syncs.
    phone.at(NOON + DAY);
    phone.sync(&token);
    phone.deliver_to(&a);

    let listed = a.listed(&token, phone.id);
    assert_eq!(listed["name"], "Pixel 8");
    assert_eq!(listed["type"], 0);
    // It did not change the vault.
    assert_eq!(listed["revisionDate"], "2026-10-11T12:01:00.000Z");
    let device = json!({"id": phone.id, "name": "Pixel 8", "type": 0});
    assert_eq!(phone.file(&user_id)["device"], device);
    assert_eq!(names(&a.sync(&token)["ciphers"]), ["2.item"]);
}

#[test]
fn a_device_that_is_retired_but_changes_the_vault_keeps_its_change() {
    let old = Device::old();
    let a = Device::new("device-a", 1 << 20);
    let (token, user_id) = old.client.register_and_log_in();
    sync_files(&[&old, &a]);
    a.at(NOON + MINUTE);
    assert_eq!(a.retire(&token, OLD).code, 200);

    // The device changes the vault before the note has come to it.
    old.at(NOON + 2 * MINUTE);
    create_cipher(&old, &token, "2.item");
    old.deliver_to(&a);

    assert_eq!(names(&a.sync(&token)["ciphers"]), ["2.item"]);
    assert_eq!(a.listed(&token, OLD)["retiredDate"], Value::Null);
    a.at(NOON + GRACE + DAY);
    assert_eq!(names(&a.sync(&token)["ciphers"]), ["2.item"]);
    assert!(a.has_directory(&user_id, OLD));
}

#[test]
fn a_retired_device_that_comes_back_after_90_days_starts_a_file_of_its_own() {
    let old = Device::old();
    let a = Device::new("device-a", 1 << 20);
    let (token, user_id) = old.client.register_and_log_in();
    old.at(NOON + MINUTE);
    create_cipher(&old, &token, "2.first");
    sync_files(&[&old, &a]);
    a.at(NOON + 2 * MINUTE);
    assert_eq!(a.retire(&token, OLD).code, 200);
    a.at(NOON + GRACE + DAY);
    a.sync(&token);
    assert!(!a.has_directory(&user_id, OLD));

    // It comes back with a copy of the vault folder that the deletion has not come to.
    a.deliver_to(&old);
    old.at(NOON + GRACE + DAY + MINUTE);
    create_cipher(&old, &token, "2.second");

    // What it held before is held by the device that retired it.
    let old_file = read_json(&old.fs, &device_file(&user_id, OLD));
    assert!(old_file["records"].get("account").is_none());
    assert!(old_file["records"].get("masterPassword").is_none());
    assert_eq!(names(&old_file["sync"]["ciphers"]), ["2.second"]);
    old.deliver_to(&a);
    assert_eq!(names(&a.sync(&token)["ciphers"]), ["2.first", "2.second"]);
    assert_eq!(a.client.log_in(EMAIL, PASSWORD_HASH).code, 200);
    assert_eq!(a.listed(&token, OLD)["retiredDate"], Value::Null);
}

#[test]
fn a_retired_device_that_changes_the_vault_before_the_note_comes_brings_back_nothing_deleted() {
    let old = Device::old();
    let a = Device::new("device-a", 1 << 20);
    let (token, user_id) = old.client.register_and_log_in();
    old.at(NOON + MINUTE);
    let cipher = create_cipher(&old, &token, "2.item");
    sync_files(&[&old, &a]);
    a.at(NOON + 2 * MINUTE);
    let path = format!("ciphers/{}", id(&cipher));
    assert_eq!(a.client.call("DELETE", &path, &token).code, 200);
    assert_eq!(a.retire(&token, OLD).code, 200);
    // The deletion is forgotten once the directory of the device is deleted.
    a.at(NOON + GRACE + DAY);
    a.sync(&token);
    assert!(!a.has_directory(&user_id, OLD));
    let tombstones = &a.file(&user_id)["tombstones"];
    assert!(tombstones.get(key("cipher", &cipher)).is_none());

    // It was still in use after all, with a copy of the vault folder that nothing has come to
    // since, and changes the vault before the files of the other device come to it.
    old.at(NOON + GRACE + DAY + MINUTE);
    create_cipher(&old, &token, "2.later");
    old.deliver_to(&a);

    assert_eq!(names(&a.sync(&token)["ciphers"]), ["2.later"]);
    assert_eq!(a.listed(&token, OLD)["retiredDate"], Value::Null);
    a.deliver_to(&old);
    assert_eq!(names(&old.sync(&token)["ciphers"]), ["2.later"]);
}

#[test]
fn a_file_of_a_retired_device_from_before_the_one_that_was_taken_over_is_left_out_as_well() {
    let old = Device::old();
    let a = Device::new("device-a", 1 << 20);
    let b = Device::new("device-b", 1 << 40);
    let (token, user_id) = old.client.register_and_log_in();
    old.at(NOON + MINUTE);
    let cipher = create_cipher(&old, &token, "2.item");
    let earlier = old.fs.get(&device_file(&user_id, OLD)).unwrap();
    old.at(NOON + 2 * MINUTE);
    let path = format!("ciphers/{}", id(&cipher));
    assert_eq!(old.client.call("DELETE", &path, &token).code, 200);
    sync_files(&[&old, &a, &b]);
    a.at(NOON + DAY);
    assert_eq!(a.retire(&token, OLD).code, 200);
    a.at(NOON + GRACE + 2 * DAY);
    a.sync(&token);
    assert!(!a.has_directory(&user_id, OLD));
    let tombstones = &a.file(&user_id)["tombstones"];
    assert!(tombstones.get(key("cipher", &cipher)).is_none());

    // The deletion of the directory comes to another device out of order, which leaves the backup
    // of the file of the device on its own for a while: the file from before the item was deleted.
    a.deliver_to(&b);
    block_on(b.fs.delete(&device_file(&user_id, OLD))).unwrap();
    assert_eq!(b.sync(&token)["ciphers"], json!([]));
    // A copy of the directory from before, as from a backup, is left out as well, and deleted again.
    a.fs.put(&device_file(&user_id, OLD), earlier);
    assert_eq!(a.sync(&token)["ciphers"], json!([]));
    assert!(a.listed(&token, OLD)["retiredDate"].is_string());
    a.at(NOON + GRACE + 3 * DAY);
    a.sync(&token);
    assert!(!a.has_directory(&user_id, OLD));
}

#[test]
fn a_retired_device_whose_clock_is_behind_keeps_what_it_changes_once_its_directory_is_deleted() {
    let old = Device::old();
    let a = Device::new("device-a", 1 << 20);
    let (token, user_id) = old.client.register_and_log_in();
    old.at(NOON + MINUTE);
    create_cipher(&old, &token, "2.first");
    sync_files(&[&old, &a]);
    a.at(NOON + 2 * MINUTE);
    assert_eq!(a.retire(&token, OLD).code, 200);
    a.at(NOON + GRACE + DAY);
    a.sync(&token);
    a.deliver_to(&old);
    deliver_deletion(&a.fs, &user_id, OLD, &old.fs);

    // Its clock is behind the date of the file that was taken over as it changes the vault again.
    old.at(NOON);
    create_cipher(&old, &token, "2.second");
    old.deliver_to(&a);

    assert_eq!(names(&a.sync(&token)["ciphers"]), ["2.first", "2.second"]);
    assert_eq!(a.listed(&token, OLD)["retiredDate"], Value::Null);
}

#[test]
fn a_device_that_retires_the_one_that_retired_it_keeps_what_that_one_took_over_from_it() {
    let a = Device::new("device-a", 1 << 20);
    let b = Device::new("device-b", 1 << 40);
    let (token, user_id) = a.client.register_and_log_in();
    a.at(NOON + MINUTE);
    create_cipher(&a, &token, "2.first");
    sync_files(&[&a, &b]);
    // The other device retires this one, which is still in use, and is not retired for long.
    b.at(NOON + 2 * MINUTE);
    assert_eq!(b.retire(&token, "device-a").code, 200);
    b.deliver_to(&a);
    a.at(NOON + DAY);
    a.sync(&token);
    a.deliver_to(&b);
    assert_eq!(b.listed(&token, "device-a")["retiredDate"], Value::Null);

    // The other device is gone for good later, and this one retires it.
    a.at(NOON + 2 * DAY);
    assert_eq!(a.retire(&token, "device-b").code, 200);

    assert_eq!(names(&a.sync(&token)["ciphers"]), ["2.first"]);
    a.at(NOON + 2 * DAY + GRACE);
    assert_eq!(names(&a.sync(&token)["ciphers"]), ["2.first"]);
    assert!(!a.has_directory(&user_id, "device-b"));
}

#[test]
fn what_a_device_takes_over_after_it_was_retired_counts_whoever_wrote_it_and_when() {
    let a = Device::new("device-a", 1 << 20);
    let b = Device::new("device-b", 1 << 40);
    let c = Device::new("device-c", 1 << 60);
    let (token, user_id) = a.client.register_and_log_in();
    a.at(NOON + MINUTE);
    create_cipher(&a, &token, "2.first");
    sync_files(&[&a, &b, &c]);
    // The second device retires this one, which is not used for long enough that its directory is
    // deleted, and is then used again, with a file of its own.
    b.at(NOON + 2 * MINUTE);
    assert_eq!(b.retire(&token, "device-a").code, 200);
    b.at(NOON + GRACE + DAY);
    b.sync(&token);
    b.deliver_to(&a);
    deliver_deletion(&b.fs, &user_id, "device-a", &a.fs);
    a.at(NOON + GRACE + 2 * DAY);
    create_cipher(&a, &token, "2.second");
    sync_files(&[&a, &b, &c]);
    // The third device retires it as well, and it is not retired for long.
    c.at(NOON + GRACE + 3 * DAY);
    assert_eq!(c.retire(&token, "device-a").code, 200);
    c.deliver_to(&a);
    a.at(NOON + GRACE + 4 * DAY);
    a.sync(&token);

    // Then it retires the second one, which holds what it wrote before its directory was deleted:
    // that is older than the file that the third device took over, and counts nonetheless.
    a.at(NOON + GRACE + 5 * DAY);
    assert_eq!(a.retire(&token, "device-b").code, 200);
    a.deliver_to(&c);

    for device in [&a, &c] {
        let names = sorted_names(&device.sync(&token)["ciphers"]);
        assert_eq!(names, ["2.first", "2.second"]);
    }
}

#[test]
fn a_device_that_retired_another_one_can_be_retired_in_turn() {
    let old = Device::old();
    let a = Device::new("device-a", 1 << 20);
    let b = Device::new("device-b", 1 << 40);
    let (token, user_id) = old.client.register_and_log_in();
    old.at(NOON + MINUTE);
    create_cipher(&old, &token, "2.first");
    sync_files(&[&old, &a, &b]);
    let before = b.sync(&token);
    a.at(NOON + DAY);
    assert_eq!(a.retire(&token, OLD).code, 200);
    a.deliver_to(&b);

    // The device that retired the other one is gone for good as well.
    b.at(NOON + 2 * DAY);
    assert_eq!(b.retire(&token, "device-a").code, 200);

    let file = b.file(&user_id);
    let retired = file["retiredDevices"].as_object().unwrap().keys();
    assert_eq!(retired.collect::<Vec<_>>(), ["device-a", OLD]);
    assert_eq!(b.sync(&token), before);
    assert_eq!(
        b.listed(&token, OLD)["retiredDate"],
        "2026-10-12T12:00:00.000Z"
    );
    // Each directory is deleted 90 days after its device was retired.
    b.at(NOON + GRACE + 2 * DAY - MINUTE);
    assert_eq!(b.sync(&token), before);
    assert!(!b.has_directory(&user_id, OLD));
    assert!(b.has_directory(&user_id, "device-a"));
    b.at(NOON + GRACE + 3 * DAY);
    assert_eq!(b.sync(&token), before);
    assert!(!b.has_directory(&user_id, "device-a"));
    assert_eq!(b.client.log_in(EMAIL, PASSWORD_HASH).code, 200);
}

#[test]
fn a_device_that_was_retired_from_an_earlier_file_of_it_is_not_left_out() {
    let a = Device::new("device-a", 1 << 20);
    let b = Device::new("device-b", 1 << 40);
    let (token, user_id) = a.client.register_and_log_in();
    sync_files(&[&a, &b]);

    // The device changes the vault, and the other one retires it before the change comes to it.
    a.at(NOON + MINUTE);
    create_cipher(&a, &token, "2.item");
    b.at(NOON + 2 * MINUTE);
    assert_eq!(b.retire(&token, "device-a").code, 200);
    a.deliver_to(&b);

    assert_eq!(names(&b.sync(&token)["ciphers"]), ["2.item"]);
    assert_eq!(b.listed(&token, "device-a")["retiredDate"], Value::Null);
    b.at(NOON + GRACE + DAY);
    assert_eq!(names(&b.sync(&token)["ciphers"]), ["2.item"]);
    assert!(b.has_directory(&user_id, "device-a"));
}

#[test]
fn two_devices_that_retire_the_same_device_at_once_both_keep_what_it_held() {
    let old = Device::old();
    let a = Device::new("device-a", 1 << 20);
    let b = Device::new("device-b", 1 << 40);
    let (token, user_id) = old.client.register_and_log_in();
    old.at(NOON + MINUTE);
    create_cipher(&old, &token, "2.first");
    sync_files(&[&old, &a, &b]);
    let before = a.sync(&token);

    a.at(NOON + DAY);
    assert_eq!(a.retire(&token, OLD).code, 200);
    b.at(NOON + 2 * DAY);
    assert_eq!(b.retire(&token, OLD).code, 200);
    sync_files(&[&a, &b]);

    // The directory is deleted 90 days after the earlier of the two.
    for device in [&a, &b] {
        assert_eq!(device.sync(&token), before);
        let retired_date = device.listed(&token, OLD)["retiredDate"].clone();
        assert_eq!(retired_date, "2026-10-12T12:00:00.000Z");
    }
    b.at(NOON + GRACE + DAY + MINUTE);
    assert_eq!(b.sync(&token), before);
    assert!(!b.has_directory(&user_id, OLD));
    deliver_deletion(&b.fs, &user_id, OLD, &a.fs);
    assert_eq!(a.sync(&token), before);
}

#[test]
fn two_devices_that_retire_each_other_at_once_are_neither_retired() {
    let a = Device::new("device-a", 1 << 20);
    let b = Device::new("device-b", 1 << 40);
    let (token, user_id) = a.client.register_and_log_in();
    a.at(NOON + MINUTE);
    create_cipher(&a, &token, "2.first");
    sync_files(&[&a, &b]);
    b.at(NOON + 2 * MINUTE);
    create_cipher(&b, &token, "2.second");
    sync_files(&[&a, &b]);

    // Each one retires the other before the note of the other one has come to it.
    a.at(NOON + DAY);
    assert_eq!(a.retire(&token, "device-b").code, 200);
    b.at(NOON + DAY + MINUTE);
    assert_eq!(b.retire(&token, "device-a").code, 200);
    sync_files(&[&a, &b]);

    // Each note is about the file of the other one from before it wrote its own with its note,
    // so neither file is left out, and each holds what the other one held.
    let both = ["2.first", "2.second"];
    for device in [&a, &b] {
        assert_eq!(sorted_names(&device.sync(&token)["ciphers"]), both);
        for id in ["device-a", "device-b"] {
            assert_eq!(device.listed(&token, id)["retiredDate"], Value::Null);
        }
        assert_eq!(device.file(&user_id)["version"], 3);
    }
    // Neither directory is deleted 90 days later.
    for device in [&a, &b] {
        device.at(NOON + GRACE + 2 * DAY);
        assert_eq!(sorted_names(&device.sync(&token)["ciphers"]), both);
        assert!(device.has_directory(&user_id, "device-a"));
        assert!(device.has_directory(&user_id, "device-b"));
        assert_eq!(device.client.log_in(EMAIL, PASSWORD_HASH).code, 200);
    }
}

#[test]
fn the_directory_of_a_device_whose_clock_was_ahead_is_kept_90_days_from_the_date_of_its_file() {
    let old = Device::old();
    let a = Device::new("device-a", 1 << 20);
    let b = Device::new("device-b", 1 << 40);
    let (token, user_id) = old.client.register_and_log_in();
    // The clock of the device that is gone for good was ten days ahead when it last changed the
    // vault.
    old.at(NOON + 10 * DAY);
    create_cipher(&old, &token, "2.first");
    sync_files(&[&old, &a, &b]);
    let before = a.sync(&token);

    a.at(NOON + DAY);
    let retired = body(&a.retire(&token, OLD));

    // The note is not older than the file that it is about, and every device leaves that file out
    // at once, whatever its clock says.
    assert_eq!(retired["revisionDate"], "2026-10-21T12:00:00.000Z");
    assert_eq!(retired["retiredDate"], "2026-10-21T12:00:00.000Z");
    assert_eq!(retired["removalDate"], "2027-01-19T12:00:00.000Z");
    a.deliver_to(&b);
    for device in [&a, &b] {
        assert_eq!(device.sync(&token), before);
        assert_eq!(device.listed(&token, OLD), retired);
    }
    // Its directory is kept until 90 days after the date of that file, by the clock of the device
    // that tidies.
    b.at(NOON + GRACE + 2 * DAY);
    assert_eq!(b.sync(&token), before);
    assert!(b.has_directory(&user_id, OLD));
    b.at(NOON + GRACE + 10 * DAY);
    assert_eq!(b.sync(&token), before);
    assert!(!b.has_directory(&user_id, OLD));
}

#[test]
fn the_directory_of_a_retired_device_is_not_deleted_while_its_newer_file_has_not_fully_come() {
    let old = Device::old();
    let a = Device::new("device-a", 1 << 20);
    let (token, user_id) = old.client.register_and_log_in();
    old.at(NOON + MINUTE);
    create_cipher(&old, &token, "2.first");
    sync_files(&[&old, &a]);
    a.at(NOON + DAY);
    assert_eq!(a.retire(&token, OLD).code, 200);

    // The device changes the vault again, and only part of that file has come when the 90 days are
    // up. The file that was taken over is its backup now, which stands in for it.
    old.at(NOON + 2 * DAY);
    create_cipher(&old, &token, "2.second");
    let backup = [user_id.as_str(), "devices", OLD, "vault.json.bak"];
    a.fs.put(&backup, old.fs.get(&backup).unwrap());
    a.fs.put(&device_file(&user_id, OLD), INCOMPLETE);
    a.at(NOON + GRACE + 2 * DAY);
    assert_eq!(names(&a.sync(&token)["ciphers"]), ["2.first"]);
    assert!(a.has_directory(&user_id, OLD));

    // Once it has come, the device is not retired, and its change is there.
    old.deliver_to(&a);
    assert_eq!(names(&a.sync(&token)["ciphers"]), ["2.first", "2.second"]);
    assert_eq!(a.listed(&token, OLD)["retiredDate"], Value::Null);
}

#[test]
fn the_content_of_an_attachment_that_a_retired_device_removed_is_deleted_90_days_after_it_was_retired()
 {
    let old = Device::old();
    let a = Device::new("device-a", 1 << 20);
    let (token, user_id) = old.client.register_and_log_in();
    let cipher = create_cipher(&old, &token, "2.item");
    let path = format!("ciphers/{}/attachment/v2", id(&cipher));
    let attachment = json!({"fileName": "2.fileName", "key": "2.key", "fileSize": 1});
    let upload = body(&old.client.send("POST", &path, &token, attachment));
    let attachment_id = upload["attachmentId"].as_str().unwrap().to_owned();
    let content_path = path_of(upload["url"].as_str().unwrap());
    let uploaded = old.client.request("PUT", &content_path).bytes(&[1]);
    assert_eq!(uploaded.send().code, 201);
    // The device removes the attachment, and is gone before it deletes its content.
    old.at(NOON + MINUTE);
    let removal = format!("ciphers/{}/attachment/{attachment_id}", id(&cipher));
    assert_eq!(old.client.call("DELETE", &removal, &token).code, 200);
    sync_files(&[&old, &a]);
    let content = [user_id.as_str(), "attachments", id(&cipher), &attachment_id];
    assert!(a.fs.get(&content).is_some());

    a.at(NOON + DAY);
    assert_eq!(a.retire(&token, OLD).code, 200);
    let removed = format!("{}/{attachment_id}", id(&cipher));
    assert_eq!(
        a.file(&user_id)["removedAttachments"],
        json!({removed: NOON + DAY})
    );
    // The device that was retired may not have seen the attachment come back, and be removed again
    // by a device that deletes the content 90 days after that.
    a.at(NOON + MINUTE + GRACE);
    a.sync(&token);
    assert!(a.fs.get(&content).is_some());
    a.at(NOON + DAY + GRACE + MINUTE);
    a.sync(&token);
    assert!(a.fs.get(&content).is_none());
    assert_eq!(a.file(&user_id)["removedAttachments"], json!({}));
}

#[test]
fn the_deletion_of_a_folder_is_kept_while_an_item_that_was_taken_over_is_in_it() {
    let old = Device::old();
    let a = Device::new("device-a", 1 << 20);
    let (token, user_id) = old.client.register_and_log_in();
    let folder = body(
        &old.client
            .send("POST", "folders", &token, json!({"name": "2.f"})),
    );
    let in_folder = json!({"type": 1, "name": "2.item", "folderId": folder["id"]});
    old.client.send("POST", "ciphers", &token, in_folder);
    sync_files(&[&old, &a]);
    a.at(NOON + MINUTE);
    let path = format!("folders/{}", id(&folder));
    assert_eq!(a.client.call("DELETE", &path, &token).code, 200);
    a.at(NOON + DAY);
    assert_eq!(a.retire(&token, OLD).code, 200);

    a.at(NOON + DAY + GRACE + DAY);
    let vault = a.sync(&token);

    // The item is in no folder only as long as the deletion of the folder is there.
    assert!(!a.has_directory(&user_id, OLD));
    let tombstones = &a.file(&user_id)["tombstones"];
    assert!(tombstones.get(key("folder", &folder)).is_some());
    assert_eq!(vault["folders"], json!([]));
    assert_eq!(vault["ciphers"][0]["folderId"], Value::Null);
}

#[test]
fn the_master_password_that_a_retired_device_held_before_it_was_changed_is_not_taken_over() {
    let old = Device::old();
    let a = Device::new("device-a", 1 << 20);
    let (token, user_id) = old.client.register_and_log_in();
    sync_files(&[&old, &a]);
    a.at(NOON + MINUTE);
    let kdf = json!({"kdfType": 0, "iterations": 600000});
    let change = json!({
        "masterPasswordHash": PASSWORD_HASH,
        "authenticationData": {
            "salt": EMAIL,
            "kdf": kdf,
            "masterPasswordAuthenticationHash": NEW_HASH,
        },
        "unlockData": {"salt": EMAIL, "kdf": kdf, "masterKeyWrappedUserKey": "2.newUserKey"},
    });
    let changed = a.client.send("POST", "accounts/password", &token, change);
    assert_eq!(changed.code, 200);
    a.at(NOON + DAY);
    assert_eq!(a.retire(&token, OLD).code, 200);
    assert_eq!(
        a.file(&user_id)["records"]["masterPassword"]["by"],
        "device-a"
    );

    // Once the directory of the device is deleted, no file has the user key that the old master
    // password unlocks.
    a.at(NOON + DAY + GRACE + DAY);
    a.sync(&token);
    assert!(!a.has_directory(&user_id, OLD));
    for path in a.fs.paths() {
        let content = String::from_utf8(a.fs.get(&strs(&path)).unwrap()).unwrap();
        assert!(!content.contains(USER_KEY), "{path:?}");
    }
    assert_eq!(a.client.log_in(EMAIL, NEW_HASH).code, 200);
}

#[test]
fn this_device_and_a_device_whose_file_has_not_fully_come_cannot_be_retired() {
    let old = Device::old();
    let a = Device::new("device-a", 1 << 20);
    let (token, user_id) = old.client.register_and_log_in();
    old.at(NOON + MINUTE);
    create_cipher(&old, &token, "2.first");
    sync_files(&[&old, &a]);
    a.at(NOON + 2 * MINUTE);
    create_cipher(&a, &token, "2.second");
    // A newer file of the device has not fully come, and the one before stands in for it.
    a.fs.put(&device_file(&user_id, OLD), INCOMPLETE);
    let files = || {
        let paths = a.fs.paths().into_iter();
        paths
            .map(|path| (a.fs.get(&strs(&path)), path))
            .collect::<Vec<_>>()
    };
    let before = files();

    let this = a.retire(&token, "device-a");
    let this_in_another_case = a.retire(&token, "DEVICE-A");
    let unknown = a.retire(&token, "device-x");
    let not_a_name = a.retire(&token, "a.b");
    let not_complete = a.retire(&token, OLD);

    assert_eq!(this.code, 400);
    assert_eq!(message(&this), "This device cannot be retired.");
    // An ID is that of a directory as it is named: in another case, it is no device's.
    assert_eq!(this_in_another_case.code, 404);
    assert_eq!(unknown.code, 404);
    assert_eq!(not_a_name.code, 404);
    assert_eq!(not_complete.code, 400);
    let not_come = "The file of the device has not fully come to this device yet. Try again later.";
    assert_eq!(message(&not_complete), not_come);
    assert_eq!(files(), before);
}
