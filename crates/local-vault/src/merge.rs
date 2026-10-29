//! The vault of an account, put together from the files of the devices that share it.
//!
//! Every device writes a file of its own, which nothing else writes, so that a tool that syncs the
//! vault folder never has two versions of one file to choose from. The file of a device holds the
//! versions of the records that the device wrote and that no other device has replaced since, or
//! not long enough ago for every device to have the newer version: the record of the master
//! password, that of the rest of the account, the folders and the items. A deletion is a version
//! as well, one without a record, so that a record that another file still has is not taken to be
//! there. A device that holds a version of a record that another device deleted since puts that
//! deletion in its file in place of the version (see [`tidy`]).
//!
//! Every version has a [`Stamp`]: when it was written, and by which device. The vault is the newest
//! version of each record. A version that is made from another one is stamped later than that one,
//! even where the clock of its device is behind, so only versions that two devices made from the
//! same one are told apart by the clocks of the devices. The encrypted content of a record is not
//! looked into, so the newer of two such versions replaces the other one whole.
//!
//! The content of an attachment is not a version: it is a file of its own, which every device
//! shares. A device that removes an attachment from the vault keeps a note of it in its file, and
//! deletes the content once nothing can bring the attachment back (see [`removal`]).
//!
//! A device that is gone for good never leaves anything out of its file. Another device can retire
//! it: it takes the file over into its own, and notes that it did (see [`take_over`]). The vault is
//! then put together without that file (see [`left_out`]), and without what a later file of that
//! device still holds from it (see [`Source::not_taken_over`]).
//!
//! The user key of an account can be replaced by a new one, with which every record is encrypted
//! again (see [`KeyRotation`]). A device that does not have the new key yet still writes with the
//! one before, so the stamp of a version also says which key the vault had when it was written,
//! and a version that was written with a later key is newer than one that was written with an
//! earlier one, whenever either was written.

use std::borrow::Cow;
use std::cmp::Ordering;
use std::collections::{BTreeMap, HashSet};

use indexmap::IndexMap;
use serde_json::{Value, json};

use crate::account::{KEY_PASSWORD_VERIFIER, KEY_USER_KEY_ROTATION, user_key_rotation};
use crate::date::parse_date_millis;
use crate::json::{
    JsonObject, element, eq_ignore_case, int, is_safe_segment, obj, objects, string, with_fields,
};
use crate::store::{
    KEY_ACCOUNT, KEY_FORMAT, KEY_REVISION_DATE, KEY_SYNC, KEY_VERSION, LOCAL_VAULT_FORMAT,
    LOCAL_VAULT_VERSION, RETIRED_DEVICES_VERSION, USER_KEY_ROTATION_VERSION,
};

/// The field of the file of a device with the stamps of the records that it holds, by their keys.
const KEY_RECORDS: &str = "records";

/// The field of the file of a device with the stamps of the deletions that it holds, by the keys
/// of the records.
const KEY_TOMBSTONES: &str = "tombstones";

/// The field of a stamp in the file of a device with when the version came into the file: the
/// revision date that the file has when the device first writes it with the version, in
/// milliseconds since the epoch. It tells what a file holds since a file of its device that another
/// device took over from what came into it later (see [`Source::not_taken_over`]). Earlier clients
/// did not write it.
const KEY_CAME_IN: &str = "in";

/// The field of the file of a device in which earlier clients wrote when the device first wrote
/// it. It is not part of the record of the account, and is left out when the file is written.
const KEY_SINCE: &str = "since";

/// The field of the file of a device with the attachments that the device removed from the
/// vault and whose content it has yet to delete, by `<cipher id>/<attachment id>`, with when it
/// removed them, in milliseconds since the epoch.
const KEY_REMOVED_ATTACHMENTS: &str = "removedAttachments";

/// The field of the file of a device with the devices that the device retired, by their IDs: when
/// it retired each of them, and the revision date of the file of that device that it took over.
const KEY_RETIRED_DEVICES: &str = "retiredDevices";

/// The field of the file of a device that says what the device is (see [`DeviceDescription`]),
/// with the ID of the device, which tells it from one that a client that does not know the field
/// took over from the file of another device.
const KEY_DEVICE: &str = "device";

/// The fields of a file that are about the file, and not part of the record of the account.
const FILE_FIELDS: [&str; 9] = [
    KEY_FORMAT,
    KEY_VERSION,
    KEY_REVISION_DATE,
    KEY_SINCE,
    KEY_RECORDS,
    KEY_TOMBSTONES,
    KEY_REMOVED_ATTACHMENTS,
    KEY_RETIRED_DEVICES,
    KEY_DEVICE,
];

const FOLDERS: &str = "folders";
const CIPHERS: &str = "ciphers";

/// The key of the record of the account. Those of a folder and an item are their IDs in lower
/// case, after these prefixes.
const ACCOUNT_KEY: &str = "account";
const FOLDER_PREFIX: &str = "folder:";
const CIPHER_PREFIX: &str = "cipher:";

/// The key of the record of the master password of the account: the fields of
/// [`MASTER_PASSWORD_FIELDS`].
const MASTER_PASSWORD_KEY: &str = "masterPassword";

/// The fields of a vault that are about the master password, by their paths: what it is
/// recognized by, the user key encrypted with the master key, which also says how that is
/// derived, its hint, the security stamp that a change of it replaces, and the rotation that made
/// the user key that it unlocks. They are a record of their own, apart from the rest of the
/// account, so that they are never taken from two versions, and so that a change of the rest of
/// the account, which a device that does not have the newest master password yet can make, does
/// not bring an older master password back.
const MASTER_PASSWORD_FIELDS: [&[&str]; 6] = [
    &[KEY_ACCOUNT, KEY_PASSWORD_VERIFIER],
    &[KEY_ACCOUNT, KEY_USER_KEY_ROTATION],
    &[KEY_SYNC, "profile", "key"],
    &[KEY_SYNC, "profile", "masterPasswordHint"],
    &[KEY_SYNC, "profile", "securityStamp"],
    &[KEY_SYNC, "userDecryption", "masterPasswordUnlock"],
];

/// The field of a stamp with the user key that the vault had when the version was written, as the
/// rotation that made it (see [`KeyRotation`]). A stamp without it is that of a version that was
/// written with the key that the account was registered with.
const KEY_USER_KEY: &str = "key";

/// How long a file can take to come to every device that shares the vault folder, as a device can
/// be off for a while. A device holds a deletion that long once no other file has a version of
/// the record from before it, as such a version may still be on its way: if it comes after the
/// deletion is gone, the record is back. And it holds a version that another file has a newer one
/// of until that one was written that long ago, as a device that gets the file without the version
/// before the file with the newer one would be without the record in the meantime. The content
/// of an attachment that a device removed is kept that long as well, as a version of the item
/// that has the attachment again may still be on its way. And so is the file of a device that was
/// retired, as the file that says so may still be on its way to another device.
pub(crate) const GRACE_MILLIS: i64 = 90 * 24 * 60 * 60 * 1000;

/// Which records of a file are read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Scope {
    /// Every record: the account, its master password, the folders and the items.
    Vault,
    /// Only the records of the account and of its master password, which tell who the account is
    /// and how it logs in: all that a request that looks for an account needs. The folders and
    /// the items, of which a file can have many, are not copied.
    Account,
}

impl Scope {
    /// Returns `true` if the record with the key is read.
    fn includes(self, key: &str) -> bool {
        self == Self::Vault || key == ACCOUNT_KEY || key == MASTER_PASSWORD_KEY
    }
}

/// The rotation that made the user key of an account: when the key was made, and by which device.
/// Every record of the vault is encrypted again with the new key, and a version that was written
/// with it is newer than every one that was written with the key before (see [`Stamp`]). A
/// rotation is later than the one that made the key that it replaces, even where the clock of its
/// device is behind, so of two keys, the one of the later rotation is the newer one.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct KeyRotation {
    /// When the key was made, in milliseconds since the epoch.
    pub(crate) at: i64,
    /// The ID of the device that made it.
    pub(crate) by: String,
}

impl KeyRotation {
    /// The rotation that the device makes now, of the key that the rotation `previous` made, or
    /// of the key that the account was registered with.
    pub(crate) fn next(previous: Option<&KeyRotation>, now_millis: i64, device_id: &str) -> Self {
        let after_previous = previous.map(|previous| previous.at.saturating_add(1));
        Self {
            at: after_previous.map_or(now_millis, |at| at.max(now_millis)),
            by: device_id.to_owned(),
        }
    }

    /// Reads a rotation, which a file has as an object with `at` and `by`.
    pub(crate) fn read(value: &Value) -> Option<Self> {
        let rotation = value.as_object()?;
        let at = int(rotation, "at")?;
        let by = string(rotation, "by")?.to_owned();
        Some(Self { at, by })
    }

    pub(crate) fn to_json(&self) -> Value {
        json!({"at": self.at, "by": self.by})
    }
}

/// When a version was written, and by which device, with which user key. Of two versions of a
/// record, the one that was written with the later key is the newer one, whenever either was
/// written: a device that does not have the newest key yet still writes with the one before,
/// which the vault no longer has. Of two that were written with the same key, the one with the
/// later stamp is the newer one, and the ID of the device decides between two that were written in
/// the same millisecond.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct Stamp {
    /// The rotation that made the user key that the vault had when the version was written, or
    /// `None` for the key that the account was registered with.
    pub(crate) key: Option<KeyRotation>,
    /// When the version was written, in milliseconds since the epoch.
    pub(crate) at: i64,
    /// The ID of the device that wrote it. A version that a device took over from a vault of the
    /// earlier layout, or that a file does not have a stamp for, has none.
    pub(crate) by: String,
}

impl Stamp {
    /// The stamp of a version that the device writes now with the user key that the rotation `key`
    /// made, in place of the version with the stamp `previous`. It is later than that one even
    /// where the clock of the device is behind.
    pub(crate) fn next(
        previous: Option<&Stamp>,
        now_millis: i64,
        device_id: &str,
        key: Option<&KeyRotation>,
    ) -> Self {
        let after_previous = previous.map(|previous| previous.at.saturating_add(1));
        Self {
            key: key.cloned(),
            at: after_previous.map_or(now_millis, |at| at.max(now_millis)),
            by: device_id.to_owned(),
        }
    }

    /// Reads a stamp. One whose key is not a rotation is not a stamp.
    fn read(value: &Value) -> Option<Self> {
        let stamp = value.as_object()?;
        let at = int(stamp, "at")?;
        let by = string(stamp, "by")?.to_owned();
        let key = match stamp.get(KEY_USER_KEY) {
            None | Some(Value::Null) => None,
            Some(key) => Some(KeyRotation::read(key)?),
        };
        Some(Self { key, at, by })
    }

    /// The stamp as the file of a device has it, with when the version came into the file, if
    /// that is known (see [`KEY_CAME_IN`]).
    fn to_json(&self, came_in: Option<i64>) -> Value {
        let mut stamp = JsonObject::new();
        stamp.insert("at".to_owned(), Value::from(self.at));
        stamp.insert("by".to_owned(), Value::from(self.by.as_str()));
        if let Some(came_in) = came_in {
            stamp.insert(KEY_CAME_IN.to_owned(), Value::from(came_in));
        }
        if let Some(key) = &self.key {
            stamp.insert(KEY_USER_KEY.to_owned(), key.to_json());
        }
        Value::Object(stamp)
    }
}

/// A version of a record.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct Version {
    pub(crate) stamp: Stamp,
    /// The record, or `None` if it was deleted.
    pub(crate) record: Option<JsonObject>,
}

impl Version {
    /// The version of a record that has the record.
    fn of(stamp: Stamp, record: JsonObject) -> Self {
        Self {
            stamp,
            record: Some(record),
        }
    }

    /// The version of a record that says that it was deleted.
    fn deletion(stamp: Stamp) -> Self {
        Self {
            stamp,
            record: None,
        }
    }
}

/// Versions of records, by their keys, in the order that the keys were added in. A version that
/// is put in place of another one keeps the place of that one.
pub(crate) type Versions = IndexMap<String, Version>;

/// Returns `true` if a version with the stamp is newer than the one with the key, or if there is
/// none.
fn is_newer(versions: &Versions, key: &str, stamp: &Stamp) -> bool {
    versions
        .get(key)
        .is_none_or(|existing| *stamp > existing.stamp)
}

/// Puts the version in place of the one with the key if it is newer than that one.
fn offer(versions: &mut Versions, key: &str, version: Version) {
    if is_newer(versions, key, &version.stamp) {
        versions.insert(key.to_owned(), version);
    }
}

/// The file of a device in the vault of an account.
#[derive(Default)]
pub(crate) struct Source {
    /// The device that wrote the file.
    pub(crate) device_id: String,
    pub(crate) versions: Versions,
    /// When the file was last written, as it says.
    pub(crate) revision_date: Value,
    /// The attachments that the device removed and has yet to delete the content of.
    pub(crate) removed_attachments: RemovedAttachments,
    /// The devices that the device retired, whose files it took over.
    pub(crate) retired_devices: RetiredDevices,
    /// What the device is, if the file says so.
    pub(crate) description: Option<DeviceDescription>,
    /// When the versions came into the file, as it was read (see [`Arrivals`]).
    pub(crate) arrivals: Arrivals,
}

/// When the versions that the file of a device was read with came into it, as the file says, if
/// it does (see [`KEY_CAME_IN`]), by the keys of the records, with the stamps of the versions. A
/// version with another stamp came into the file when it is written.
pub(crate) type Arrivals = BTreeMap<String, (Stamp, Option<i64>)>;

impl Source {
    /// The file of the device with the ID, with its versions in the scope (see
    /// [`device_versions`]).
    pub(crate) fn device(device_id: String, file: &JsonObject, scope: Scope) -> Self {
        let revision_date = file.get(KEY_REVISION_DATE).cloned();
        let retired_devices = retired_devices_of(file, &device_id);
        let description = description_of(file, &device_id);
        let versions = device_versions(file, scope);
        let arrivals = arrivals_of(file, &versions);
        Self {
            device_id,
            versions,
            revision_date: revision_date.unwrap_or(Value::Null),
            removed_attachments: removed_attachments_of(file),
            retired_devices,
            description,
            arrivals,
        }
    }

    /// Returns `true` if the file is the one that the retirement says was taken over, or one of
    /// its device from before it: its revision date is that of the file that was taken over, or
    /// earlier. A device gives every file that it writes with a change a later one than the one
    /// before, so a file that it wrote after the one that was taken over is never taken for it. One
    /// from before that one, such as a copy of the directory of the device from a backup, or its
    /// backup left on its own while the directory is deleted, holds nothing that the vault is not
    /// the same without: what the device left out of its file since then was replaced, or deleted
    /// and the deletion forgotten. A revision date that is not a date is only that of the same file.
    pub(crate) fn is_taken_over(&self, retirement: &Retirement) -> bool {
        let revision_date = self.revision_date.as_str();
        let taken_over = parse_date_millis(&retirement.revision_date);
        match (revision_date.and_then(parse_date_millis), taken_over) {
            (Some(written_at), Some(taken_over)) => written_at <= taken_over,
            _ => revision_date == Some(retirement.revision_date.as_str()),
        }
    }

    /// The versions of the file without those that it holds since a file of its device that
    /// another device took over, the latest of which had the revision date `taken_over`, if there
    /// is one (see [`taken_over_until`]). The device that took that file over holds them, or what
    /// replaced them, so the vault is the same without them. A device that is retired but still in
    /// use writes its file from the one that was taken over, also before the note comes to it,
    /// which can be after the deletions of the records that it holds older versions of were
    /// forgotten: those records would be back otherwise.
    ///
    /// The file says when a version came into it (see [`KEY_CAME_IN`]). One that it does not say
    /// that of came into it with an earlier client, and is taken to be held since a file that was
    /// taken over if the device wrote it before that file was written: a device that took it over
    /// from another one, or wrote it later with a clock that was behind, is not told apart.
    pub(crate) fn not_taken_over(&self, taken_over: Option<i64>) -> Cow<'_, Versions> {
        let Some(taken_over) = taken_over else {
            return Cow::Borrowed(&self.versions);
        };
        let versions = self.versions.iter();
        let kept = versions.filter(|(key, version)| !self.is_held_since(key, version, taken_over));
        let kept = kept.map(|(key, version)| (key.clone(), version.clone()));
        Cow::Owned(kept.collect())
    }

    /// Returns `true` if the file holds the version since a file of its device whose revision date
    /// was `taken_over` or earlier (see [`Self::not_taken_over`]).
    fn is_held_since(&self, key: &str, version: &Version, taken_over: i64) -> bool {
        match self.came_in(key, version, None) {
            Some(came_in) => came_in <= taken_over,
            None => version.stamp.by == self.device_id && version.stamp.at <= taken_over,
        }
    }

    /// When the version came into the file: when the file says, if it was read with that
    /// version, or else `written_at`, the revision date of the file that is written with it.
    fn came_in(&self, key: &str, version: &Version, written_at: Option<i64>) -> Option<i64> {
        match self.arrivals.get(key) {
            Some((stamp, came_in)) if *stamp == version.stamp => *came_in,
            _ => written_at,
        }
    }

    /// The file of the device that holds the versions, with when each came into it, the attachments
    /// that it removed and has yet to delete the content of, the devices that it retired, and what
    /// the device is.
    pub(crate) fn to_file(&self) -> JsonObject {
        let account = self.versions.get(ACCOUNT_KEY);
        let account = account.and_then(|version| version.record.clone());
        let revision_date = self.revision_date.clone();
        let written_at = revision_date.as_str().and_then(parse_date_millis);
        let mut file = assemble(&account.unwrap_or_default(), &self.versions, revision_date);
        let mut records = JsonObject::new();
        let mut tombstones = JsonObject::new();
        for (key, version) in &self.versions {
            let stamps = if version.record.is_some() {
                &mut records
            } else {
                &mut tombstones
            };
            let came_in = self.came_in(key, version, written_at);
            stamps.insert(key.clone(), version.stamp.to_json(came_in));
        }
        file.insert(KEY_RECORDS.to_owned(), Value::Object(records));
        file.insert(KEY_TOMBSTONES.to_owned(), Value::Object(tombstones));
        let removed = self.removed_attachments.iter();
        let removed = removed.map(|((cipher_id, attachment_id), at)| {
            (format!("{cipher_id}/{attachment_id}"), Value::from(*at))
        });
        file.insert(
            KEY_REMOVED_ATTACHMENTS.to_owned(),
            Value::Object(removed.collect()),
        );
        if let Some(description) = &self.description {
            let device = json!({
                "id": self.device_id,
                "name": description.name,
                "type": description.device_type,
            });
            file.insert(KEY_DEVICE.to_owned(), device);
        }
        if !self.retired_devices.is_empty() {
            let retired = self.retired_devices.iter();
            let retired = retired.map(|(device_id, retirement)| {
                let note = json!({"at": retirement.at, "revisionDate": retirement.revision_date});
                (device_id.clone(), note)
            });
            file.insert(
                KEY_RETIRED_DEVICES.to_owned(),
                Value::Object(retired.collect()),
            );
            // A client that does not know of retired devices takes the vault for one of a layout
            // that it does not know, which it neither uses nor writes. It would take the field for
            // part of the record of the account, and go on reading the files of the devices.
            file.insert(KEY_VERSION.to_owned(), Value::from(RETIRED_DEVICES_VERSION));
        }
        if self
            .versions
            .values()
            .any(|version| version.stamp.key.is_some())
        {
            // The same goes for a client that does not know of rotated user keys, which would take
            // a version that was written later with a key that the vault no longer has for the
            // newer one. The version says that the client knows of retired devices as well.
            file.insert(
                KEY_VERSION.to_owned(),
                Value::from(USER_KEY_ROTATION_VERSION),
            );
        }
        file
    }
}

/// That a device retired another one, as the file of the device says.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Retirement {
    /// When the device was retired, in milliseconds since the epoch.
    pub(crate) at: i64,
    /// The revision date of the file of the device that was retired, as it was when it was taken
    /// over.
    pub(crate) revision_date: String,
}

impl Retirement {
    /// Returns `true` if the note says more than another one about the same device: that a later
    /// file of it was taken over, which leaves out every file that the other one does (see
    /// [`Source::is_taken_over`]) and what a later file holds since then (see [`taken_over_until`]),
    /// or that the same file was taken over earlier, which deletes its directory sooner.
    fn supersedes(&self, other: &Self) -> bool {
        let revision_date = |note: &Self| parse_date_millis(&note.revision_date);
        match revision_date(self).cmp(&revision_date(other)) {
            Ordering::Greater => true,
            Ordering::Less => false,
            Ordering::Equal => self.at < other.at,
        }
    }
}

/// The devices that a device retired, by their IDs.
pub(crate) type RetiredDevices = BTreeMap<String, Retirement>;

/// What a device is, as its client names it to a Bitwarden server when it logs in (`deviceName`
/// and `deviceType`), so that the devices that share the vault folder can be told apart, and one
/// that is still used, but only reads the vault, from one that is gone for good.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DeviceDescription {
    /// The name of the device: the model of a phone, or the browser that an extension is in.
    pub(crate) name: String,
    /// The kind of the device, as the Bitwarden API numbers them (`DeviceType`): `0` for Android,
    /// `2` for an extension in Chrome, and so on.
    pub(crate) device_type: i64,
}

/// The devices that the file of a device says that the device retired. A note that is not
/// complete is left out, and so is one about the device itself, which no device writes. An ID is
/// that of the directory of a device as it is named, so IDs are told apart as they are, case
/// included, here and wherever a device is looked for.
fn retired_devices_of(file: &JsonObject, device_id: &str) -> RetiredDevices {
    let mut retired = RetiredDevices::new();
    for (id, note) in obj(file, KEY_RETIRED_DEVICES).into_iter().flatten() {
        let Some(note) = note.as_object() else {
            continue;
        };
        let (Some(at), Some(revision_date)) = (int(note, "at"), string(note, KEY_REVISION_DATE))
        else {
            continue;
        };
        if is_safe_segment(id) && id != device_id {
            let revision_date = revision_date.to_owned();
            retired.insert(id.clone(), Retirement { at, revision_date });
        }
    }
    retired
}

/// What the file of a device says that the device is, or `None` if it does not say so, as a file
/// that an earlier client wrote does not. One that names another device is not about this one: a
/// client that does not know the field takes it for part of the record of the account, and writes
/// it in its own file with a change of the account, as it came in the file of another device.
fn description_of(file: &JsonObject, device_id: &str) -> Option<DeviceDescription> {
    let device = obj(file, KEY_DEVICE)?;
    if string(device, "id") != Some(device_id) {
        return None;
    }
    Some(DeviceDescription {
        name: string(device, "name")?.to_owned(),
        device_type: int(device, "type")?,
    })
}

/// The devices whose files the vault is not put together from, as they were retired, with when the
/// earliest of the notes that say so was made. A note counts as long as the file of the device is
/// the one that was taken over or an earlier one (see [`Source::is_taken_over`]), in whichever file
/// it is, the file of a device that was retired as well: the device that took over that file took
/// the note over with it.
///
/// The file that took the file of the device over holds what it did, with the same stamps, so the
/// vault is the same with it or without it. Every device that has the same files leaves out the
/// same ones, whatever its clock says.
pub(crate) fn left_out(files: &[Source]) -> BTreeMap<String, i64> {
    let mut left_out = BTreeMap::new();
    for file in files {
        for (device_id, retirement) in &file.retired_devices {
            let is_taken_over = files.iter().any(|retired| {
                retired.device_id == *device_id && retired.is_taken_over(retirement)
            });
            if is_taken_over {
                let at = left_out.entry(device_id.clone()).or_insert(retirement.at);
                *at = retirement.at.min(*at);
            }
        }
    }
    left_out
}

/// The latest revision date, in milliseconds since the epoch, that a file of each device had when
/// another device took it over, as the files that are not left out say: what a later file of the
/// device holds since then is not part of the vault (see [`Source::not_taken_over`]). A note in a
/// file that is left out does not count. The device that took that file over took the note over
/// with it, but for one about itself: what the file that is left out took over from that device is
/// held by that device alone then.
///
/// `left_out` are the devices whose files are left out (see [`left_out`]).
pub(crate) fn taken_over_until(
    files: &[Source],
    left_out: &BTreeMap<String, i64>,
) -> BTreeMap<String, i64> {
    let mut until = BTreeMap::new();
    let is_counted = |file: &&Source| !left_out.contains_key(&file.device_id);
    for file in files.iter().filter(is_counted) {
        for (device_id, retirement) in &file.retired_devices {
            if let Some(taken_over) = parse_date_millis(&retirement.revision_date) {
                let latest = until.entry(device_id.clone()).or_insert(taken_over);
                *latest = taken_over.max(*latest);
            }
        }
    }
    until
}

/// The latest revision date, in milliseconds since the epoch, that a file of the device had when
/// another device took it over, as any of the files says, those that are left out included. A file
/// that the device writes has to be later than that, or it would be left out as well (see
/// [`Source::is_taken_over`]), as one that it starts once its directory was deleted, or with a
/// clock that is behind, could be.
pub(crate) fn latest_taken_over<'a>(
    files: impl IntoIterator<Item = &'a Source>,
    device_id: &str,
) -> Option<i64> {
    let notes = files.into_iter();
    let notes = notes.filter_map(|file| file.retired_devices.get(device_id));
    let taken_over = notes.filter_map(|note| parse_date_millis(&note.revision_date));
    taken_over.max()
}

/// Takes the file of a device that is retired over into the versions of this device: every
/// version of it that is newer than the one that this device holds, with its stamp as it is, so
/// that the vault stays the same and a newer version that another device wrote in the meantime
/// still replaces it, but for those that it holds since a file of it that another device took over,
/// the latest of which had the revision date `taken_over` (see [`Source::not_taken_over`]); the
/// attachments that it removed, and the devices that it retired. Then notes that the device was
/// retired at `at`, along with the revision date of its file, which tells that file from one that
/// the device writes later.
///
/// The retired device may not have seen that an attachment that it removed came back, and was
/// removed again later by a device that deletes the content 90 days after that. So the content
/// is kept for 90 days from now, and an attachment that the vault has again is not taken over.
///
/// Of the notes of the devices that both retired, the one about the later file of that device is
/// kept, or of two about the same file the earlier one (see [`Retirement::supersedes`]). A note
/// about this device is not taken over: the device writes its file as it takes another one over,
/// which makes the note one about an earlier file, and what the retired device took over from it
/// is held by this device alone from then on (see [`taken_over_until`]).
///
/// `merged` are the versions that the vault is made of.
pub(crate) fn take_over(
    own: &mut Source,
    own_device_id: &str,
    retired: &Source,
    taken_over: Option<i64>,
    merged: &Versions,
    at: i64,
    now_millis: i64,
) {
    for (key, version) in retired.not_taken_over(taken_over).iter() {
        offer(&mut own.versions, key, version.clone());
    }
    for (cipher_id, attachment_id) in retired.removed_attachments.keys() {
        let cipher = cipher_in(merged, cipher_id);
        if !cipher.is_some_and(|cipher| has_attachment(cipher, attachment_id)) {
            let ids = (cipher_id.clone(), attachment_id.clone());
            own.removed_attachments.entry(ids).or_insert(now_millis);
        }
    }
    for (device_id, retirement) in &retired.retired_devices {
        if device_id == own_device_id {
            continue;
        }
        let held = own.retired_devices.get(device_id);
        let is_held = held.is_some_and(|held| !retirement.supersedes(held));
        if !is_held {
            own.retired_devices
                .insert(device_id.clone(), retirement.clone());
        }
    }
    if let Some(revision_date) = retired.revision_date.as_str() {
        let revision_date = revision_date.to_owned();
        let retirement = Retirement { at, revision_date };
        own.retired_devices
            .insert(retired.device_id.clone(), retirement);
    }
}

/// The record of the account of a vault and that of its master password. That of the master
/// password is the fields of [`MASTER_PASSWORD_FIELDS`] that the vault has, at their paths, and
/// that of the account is everything else but the folders and the items, which are left empty in
/// their places, and the fields that are about the file that the vault is in.
fn account_records(vault: &JsonObject) -> (JsonObject, JsonObject) {
    let mut account = JsonObject::new();
    for (name, value) in vault {
        if FILE_FIELDS.contains(&name.as_str()) {
            continue;
        }
        // The folders and the items are not copied: a file can have many of them.
        let value = if name == KEY_SYNC {
            Value::Object(sync_without_items(vault))
        } else {
            value.clone()
        };
        account.insert(name.clone(), value);
    }
    let mut master_password = JsonObject::new();
    for path in MASTER_PASSWORD_FIELDS {
        if let Some(value) = take_at(&mut account, path) {
            put_at(&mut master_password, path, value);
        }
    }
    (account, master_password)
}

/// The `sync` of a vault with its folders and items left empty in their places.
fn sync_without_items(vault: &JsonObject) -> JsonObject {
    let mut sync = JsonObject::new();
    for (name, value) in obj(vault, KEY_SYNC).into_iter().flatten() {
        let value = match name.as_str() {
            FOLDERS | CIPHERS => Value::Array(Vec::new()),
            _ => value.clone(),
        };
        sync.insert(name.clone(), value);
    }
    for list in [FOLDERS, CIPHERS] {
        sync.insert(list.to_owned(), Value::Array(Vec::new()));
    }
    sync
}

/// The records of a vault in the scope by their keys: that of its account, of its master
/// password, its folders and its items.
fn records_of(vault: &JsonObject, scope: Scope) -> Vec<(String, JsonObject)> {
    let (account, master_password) = account_records(vault);
    let mut records = vec![
        (ACCOUNT_KEY.to_owned(), account),
        (MASTER_PASSWORD_KEY.to_owned(), master_password),
    ];
    if scope == Scope::Account {
        return records;
    }
    let sync = obj(vault, KEY_SYNC);
    for (list, prefix) in [(FOLDERS, FOLDER_PREFIX), (CIPHERS, CIPHER_PREFIX)] {
        for item in sync.map(|sync| objects(sync, list)).unwrap_or_default() {
            if let Some(id) = string(&item, "id") {
                records.push((format!("{prefix}{}", id.to_lowercase()), item));
            }
        }
    }
    records
}

/// The versions in the file of a device that are in the scope: its records with their stamps in
/// `records`, and the deletions in `tombstones`. A folder or an item without a stamp is taken to
/// have been written by no device in particular (see [`unstamped`]). The record of the account and
/// that of the master password are only in the file if `records` has a stamp for them.
fn device_versions(file: &JsonObject, scope: Scope) -> Versions {
    let no_stamps = JsonObject::new();
    let stamps = obj(file, KEY_RECORDS).unwrap_or(&no_stamps);
    let mut versions = Versions::default();
    for (key, record) in records_of(file, scope) {
        let stamp = stamps.get(&key).and_then(Stamp::read);
        let stamp = match key.as_str() {
            ACCOUNT_KEY | MASTER_PASSWORD_KEY => stamp,
            _ => Some(stamp.unwrap_or_else(|| unstamped(&record, file))),
        };
        if let Some(stamp) = stamp {
            offer(&mut versions, &key, Version::of(stamp, record));
        }
    }
    let tombstones = obj(file, KEY_TOMBSTONES).unwrap_or(&no_stamps);
    for (key, stamp) in tombstones {
        if let Some(stamp) = Stamp::read(stamp).filter(|_| scope.includes(key)) {
            offer(&mut versions, key, Version::deletion(stamp));
        }
    }
    versions
}

/// When the versions that were read from the file of a device came into it, as the stamps in its
/// `records` and `tombstones` say (see [`KEY_CAME_IN`]).
fn arrivals_of(file: &JsonObject, versions: &Versions) -> Arrivals {
    let arrival = |key: &String, version: &Version| {
        let stamps = if version.record.is_some() {
            KEY_RECORDS
        } else {
            KEY_TOMBSTONES
        };
        let stamp = obj(file, stamps).and_then(|stamps| stamps.get(key));
        let came_in = stamp.and_then(Value::as_object);
        let came_in = came_in.and_then(|stamp| int(stamp, KEY_CAME_IN));
        (key.clone(), (version.stamp.clone(), came_in))
    };
    versions
        .iter()
        .map(|(key, version)| arrival(key, version))
        .collect()
}

/// The stamp of a folder or an item that the file of a device has no stamp for: when its revision
/// date says, or else when the file was last written, by no device in particular, with the user
/// key that the account was registered with, as only an earlier client leaves a stamp out.
fn unstamped(record: &JsonObject, file: &JsonObject) -> Stamp {
    let date = |object: &JsonObject| string(object, KEY_REVISION_DATE).and_then(parse_date_millis);
    Stamp {
        key: None,
        at: date(record).or_else(|| date(file)).unwrap_or(0),
        by: String::new(),
    }
}

/// Puts the versions of several files together: the newest version of each record, and the first
/// of those that are as new, with the items in a deleted folder in none (see
/// [`without_deleted_folders`]). Files that are given in the same order come to the same versions,
/// in the same order, on every device.
pub(crate) fn merge<'a>(files: impl IntoIterator<Item = &'a Versions>) -> Versions {
    let mut merged = Versions::default();
    for (key, version) in files.into_iter().flatten() {
        if is_newer(&merged, key, &version.stamp) {
            merged.insert(key.clone(), version.clone());
        }
    }
    without_deleted_folders(&mut merged);
    merged
}

/// Takes the items that are in a deleted folder out of it. One device can delete a folder while
/// another one puts an item in it, and neither of them knows about the other.
fn without_deleted_folders(versions: &mut Versions) {
    let deleted_folders: HashSet<String> = versions
        .iter()
        .filter(|(_, version)| version.record.is_none())
        .filter_map(|(key, _)| key.strip_prefix(FOLDER_PREFIX))
        .map(str::to_owned)
        .collect();
    if deleted_folders.is_empty() {
        return;
    }
    for (key, version) in versions.iter_mut() {
        let Some(cipher) = version.record.as_mut() else {
            continue;
        };
        if key.starts_with(CIPHER_PREFIX)
            && folder_of(cipher).is_some_and(|folder_id| deleted_folders.contains(&folder_id))
        {
            cipher.insert("folderId".to_owned(), Value::Null);
        }
    }
}

/// The ID of the folder that an item is in, in lower case, as it is in the key of the folder.
fn folder_of(cipher: &JsonObject) -> Option<String> {
    string(cipher, "folderId").map(str::to_lowercase)
}

/// The vault that the versions make up, with the revision date, or `None` if they have no record
/// of an account, or none of its master password.
pub(crate) fn to_vault(versions: &Versions, revision_date: Value) -> Option<JsonObject> {
    let account = versions.get(ACCOUNT_KEY)?.record.as_ref()?;
    versions.get(MASTER_PASSWORD_KEY)?.record.as_ref()?;
    Some(assemble(account, versions, revision_date))
}

/// The attachments that a device removed from the vault and whose content it has yet to delete,
/// by the IDs of the item and of the attachment as the vault had them, with when it removed them,
/// in milliseconds since the epoch.
pub(crate) type RemovedAttachments = BTreeMap<(String, String), i64>;

/// The attachments that the file of a device says that the device removed and has yet to
/// delete the content of.
fn removed_attachments_of(file: &JsonObject) -> RemovedAttachments {
    let mut removed = RemovedAttachments::new();
    for (name, at) in obj(file, KEY_REMOVED_ATTACHMENTS).into_iter().flatten() {
        let ids = name.split_once('/');
        if let (Some((cipher_id, attachment_id)), Some(at)) = (ids, at.as_i64()) {
            removed.insert((cipher_id.to_owned(), attachment_id.to_owned()), at);
        }
    }
    removed
}

/// The attachments that the changes take out of the vault that `base` makes up, by the IDs that
/// `base` has them under: those of an item that a change deletes, and those that the new version
/// of an item no longer has.
pub(crate) fn removed_attachments(base: &Versions, changes: &Versions) -> Vec<(String, String)> {
    let mut removed = Vec::new();
    for (key, change) in changes {
        let previous = base.get(key).and_then(|previous| previous.record.as_ref());
        let Some(cipher) = previous.filter(|_| key.starts_with(CIPHER_PREFIX)) else {
            continue;
        };
        let Some(cipher_id) = string(cipher, "id") else {
            continue;
        };
        let new_record = change.record.as_ref();
        let is_kept = |id: &str| new_record.is_some_and(|record| has_attachment(record, id));
        for attachment_id in attachment_ids(cipher).filter(|id| !is_kept(id)) {
            removed.push((cipher_id.to_owned(), attachment_id.to_owned()));
        }
    }
    removed
}

/// What becomes of the content of an attachment that a device removed from the vault.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Removal {
    /// It is deleted now.
    Delete,
    /// It is kept for now.
    Wait,
    /// It is not deleted, as the vault has the attachment again.
    Forget,
}

/// Decides what becomes of the content of an attachment that the device removed at
/// `removed_at`, given the versions that the vault is made of.
///
/// A device that had not seen the removal yet can have changed the item, or deleted and changed
/// it, in a version that is newer, which has the attachment again. So the content is kept for
/// [`GRACE_MILLIS`], the time that such a version can take to come, and not deleted at all if the
/// vault has the attachment again: the device that removes it next deletes it. A version that is
/// not the newest one of the item never brings the attachment back, so what other files hold of
/// the item does not keep the content.
pub(crate) fn removal(
    (cipher_id, attachment_id): &(String, String),
    removed_at: i64,
    merged: &Versions,
    now_millis: i64,
) -> Removal {
    let cipher = cipher_in(merged, cipher_id);
    if cipher.is_some_and(|cipher| has_attachment(cipher, attachment_id)) {
        Removal::Forget
    } else if now_millis.saturating_sub(removed_at) >= GRACE_MILLIS {
        Removal::Delete
    } else {
        Removal::Wait
    }
}

/// Returns `true` if the vault that the versions make up has the item with the ID, in whatever
/// case.
pub(crate) fn has_cipher(merged: &Versions, cipher_id: &str) -> bool {
    cipher_in(merged, cipher_id).is_some()
}

/// The item with the ID, in whatever case, in the vault that the versions make up.
fn cipher_in<'a>(merged: &'a Versions, cipher_id: &str) -> Option<&'a JsonObject> {
    let key = format!("{CIPHER_PREFIX}{}", cipher_id.to_lowercase());
    merged.get(&key).and_then(|version| version.record.as_ref())
}

/// The IDs of the attachments of an item, as it has them.
fn attachment_ids(cipher: &JsonObject) -> impl Iterator<Item = &str> {
    let attachments = element(cipher, "attachments").and_then(Value::as_array);
    let attachments = attachments
        .into_iter()
        .flatten()
        .filter_map(Value::as_object);
    attachments.filter_map(|attachment| string(attachment, "id"))
}

/// Returns `true` if the item has the attachment with the ID, in whatever case.
fn has_attachment(cipher: &JsonObject, attachment_id: &str) -> bool {
    attachment_ids(cipher).any(|id| eq_ignore_case(id, attachment_id))
}

/// The versions that a device writes for what changed from the vault that `base` makes up to the
/// vault that is given: a new version of every record that is new or different, and a deletion
/// of every record that is gone, each with the user key of the vault that is given.
pub(crate) fn changes(
    base: &Versions,
    vault: &JsonObject,
    now_millis: i64,
    device_id: &str,
) -> Versions {
    let key = user_key_rotation(vault);
    let next = |previous| Stamp::next(previous, now_millis, device_id, key.as_ref());
    let records = records_of(vault, Scope::Vault);
    let kept: HashSet<String> = records.iter().map(|(key, _)| key.clone()).collect();
    let mut changes = Versions::default();
    for (key, version) in base {
        if version.record.is_some() && !kept.contains(key) {
            changes.insert(key.clone(), Version::deletion(next(Some(&version.stamp))));
        }
    }
    for (key, record) in records {
        let previous = base.get(&key);
        if previous.and_then(|previous| previous.record.as_ref()) == Some(&record) {
            continue;
        }
        let previous_stamp = previous.map(|previous| &previous.stamp);
        changes.insert(key, Version::of(next(previous_stamp), record));
    }
    changes
}

/// Leaves out of the versions of a device what it no longer has to hold, given the other files,
/// and puts the deletions that they have in place of the versions that they replaced:
///
/// - a version that one of them has a newer one of is left out once every device has had time to
///   get that one, or right away if the record is that of the master password (see
///   `is_replaced`);
/// - a version that one of them has a newer deletion of is replaced by that deletion right away,
///   or by the newest one if several of them have one, unless it is left out (see
///   `newer_deletion`);
/// - a deletion that every device has had time to get, and that none of them has an older version
///   of the record for, which it would bring back, nor, for a folder, an item in the folder, which
///   would then be in a folder that is not there, is left out (see `is_forgettable`).
///
/// Returns `true` if anything was left out or replaced. Only the device that holds a version leaves
/// it out, as no device writes the file of another. A tool that syncs the folder can bring the file
/// without the version to a third device before the file that it was left to, which is why the
/// version is held until every device has had time to get that one.
///
/// Nothing is put in the versions that none of the other files has: what is left out is held by
/// another file or no longer needed, and a deletion that is put in place of a version is held by
/// another file. Tidying thus never makes a file hold anything that would be lost without it, which
/// is why a device that only tidies its file keeps its revision date (see [`left_out`]). This has to
/// stay so.
pub(crate) fn tidy(versions: &mut Versions, others: &[&Source], now_millis: i64) -> bool {
    let mut is_changed = false;
    for (key, version) in versions.iter_mut() {
        if is_replaced(key, version, others, now_millis) {
            continue;
        }
        if let Some(deletion) = newer_deletion(key, version, others) {
            *version = deletion;
            is_changed = true;
        }
    }
    let own: &Versions = versions;
    let removable: HashSet<String> = own
        .iter()
        .filter(|(key, version)| {
            is_replaced(key, version, others, now_millis)
                || is_forgettable(key, version, own, others, now_millis)
        })
        .map(|(key, _)| key.clone())
        .collect();
    versions.retain(|key, _| !removable.contains(key));
    is_changed || !removable.is_empty()
}

/// Returns `true` if another file has a newer version of the record that the version can be left
/// to. That is one that every device has had time to get, or else a version of the master
/// password, whose older versions hold what a change of the master password replaced: a device
/// that does not have the newer one yet has no vault to use until it comes, or takes an older one
/// that another file still has for the master password until then.
fn is_replaced(key: &str, version: &Version, others: &[&Source], now_millis: i64) -> bool {
    others.iter().any(|other| {
        other.versions.get(key).is_some_and(|newer| {
            newer.stamp > version.stamp
                && (key == MASTER_PASSWORD_KEY || has_come_everywhere(newer, now_millis))
        })
    })
}

/// Returns `true` if the version was written [`GRACE_MILLIS`] ago or longer, so that every device
/// has had time to get it.
fn has_come_everywhere(version: &Version, now_millis: i64) -> bool {
    now_millis.saturating_sub(version.stamp.at) >= GRACE_MILLIS
}

/// The newest deletion of the record that one of the other files has, if it is newer than the
/// version, which it then replaces: the record is not in the vault either way, and is no longer in
/// the file either. The version is not left out, as the device that deleted the record put the
/// deletion in place of the version that it held. A device that gets this file before the one with
/// the deletion can still have the file of that device from before, with that older version, which
/// it would take for the record, and a change of it there would bring the record back, older than
/// it was. With the deletion in this file as well, that device has the deletion either way.
fn newer_deletion(key: &str, version: &Version, others: &[&Source]) -> Option<Version> {
    let held = others.iter().filter_map(|other| other.versions.get(key));
    let deletions = held.filter(|held| held.record.is_none() && held.stamp > version.stamp);
    deletions.max_by(|a, b| a.stamp.cmp(&b.stamp)).cloned()
}

/// Returns `true` if one of the other files has a version of the record that is older than the
/// version, and not a deletion.
fn is_older_held(key: &str, version: &Version, others: &[&Source]) -> bool {
    others
        .iter()
        .filter_map(|other| other.versions.get(key))
        .any(|held| held.record.is_some() && held.stamp < version.stamp)
}

/// Returns `true` if the version is a deletion that can be forgotten. It has to be older than
/// [`GRACE_MILLIS`], the time that a file with an older version of the record, which forgetting it
/// would bring back, can take to come.
///
/// The deletion of a folder is not, as long as one of the files has an item in the folder. Such an
/// item is in no folder only as long as the deletion is there (see `without_deleted_folders`), as
/// the device that put it there did not know that the folder was deleted.
fn is_forgettable(
    key: &str,
    version: &Version,
    own: &Versions,
    others: &[&Source],
    now_millis: i64,
) -> bool {
    let is_in_use = |folder_id: &str| {
        let mut files = others.iter().map(|other| &other.versions).chain([own]);
        files.any(|versions| has_item_in(versions, folder_id))
    };
    version.record.is_none()
        && has_come_everywhere(version, now_millis)
        && !is_older_held(key, version, others)
        && !key.strip_prefix(FOLDER_PREFIX).is_some_and(is_in_use)
}

/// Returns `true` if one of the versions is an item in the folder with the ID, in lower case.
fn has_item_in(versions: &Versions, folder_id: &str) -> bool {
    versions.iter().any(|(key, version)| {
        key.starts_with(CIPHER_PREFIX)
            && version.record.as_ref().and_then(folder_of).as_deref() == Some(folder_id)
    })
}

/// A vault of this layout: the record of the account, with the folders and the items of the
/// versions in their places.
fn assemble(account: &JsonObject, versions: &Versions, revision_date: Value) -> JsonObject {
    let records = |prefix: &str| {
        let records = versions
            .iter()
            .filter(|(key, _)| key.starts_with(prefix))
            .filter_map(|(_, version)| version.record.clone());
        Value::Array(records.map(Value::Object).collect())
    };
    let sync = obj(account, KEY_SYNC).cloned().unwrap_or_default();
    let sync = with_fields(
        &sync,
        [
            (FOLDERS, records(FOLDER_PREFIX)),
            (CIPHERS, records(CIPHER_PREFIX)),
        ],
    );
    let mut vault = JsonObject::new();
    vault.insert(KEY_FORMAT.to_owned(), Value::from(LOCAL_VAULT_FORMAT));
    vault.insert(KEY_VERSION.to_owned(), Value::from(LOCAL_VAULT_VERSION));
    vault.insert(KEY_REVISION_DATE.to_owned(), revision_date);
    vault.extend(account.clone());
    vault.insert(KEY_SYNC.to_owned(), Value::Object(sync));
    let master_password = versions.get(MASTER_PASSWORD_KEY);
    if let Some(master_password) = master_password.and_then(|version| version.record.as_ref()) {
        for path in MASTER_PASSWORD_FIELDS {
            if let Some(value) = value_at(master_password, path) {
                put_at(&mut vault, path, value.clone());
            }
        }
    }
    vault
}

/// The value at the path of the object, if there is one.
fn value_at<'a>(object: &'a JsonObject, path: &[&str]) -> Option<&'a Value> {
    let (last, parents) = path.split_last()?;
    let mut object = object;
    for name in parents {
        object = object.get(*name)?.as_object()?;
    }
    object.get(*last)
}

/// Takes the value at the path out of the object, if there is one. The fields around it keep
/// their order.
fn take_at(object: &mut JsonObject, path: &[&str]) -> Option<Value> {
    let (last, parents) = path.split_last()?;
    let mut object = object;
    for name in parents {
        object = object.get_mut(*name)?.as_object_mut()?;
    }
    object.shift_remove(*last)
}

/// Puts the value at the path of the object, with the objects on the way to it where they are
/// missing or `null`. A value of another kind on the way is left as it is, without the value.
fn put_at(object: &mut JsonObject, path: &[&str], value: Value) {
    let Some((last, parents)) = path.split_last() else {
        return;
    };
    let mut object = object;
    for name in parents {
        let parent = object.entry(*name).or_insert(Value::Null);
        if parent.is_null() {
            *parent = Value::Object(JsonObject::new());
        }
        let Some(parent) = parent.as_object_mut() else {
            return;
        };
        object = parent;
    }
    object.insert((*last).to_owned(), value);
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use crate::json::into_object;

    const DAY: i64 = 24 * 60 * 60 * 1000;

    fn stamp(at: i64, by: &str) -> Stamp {
        Stamp {
            key: None,
            at,
            by: by.to_owned(),
        }
    }

    fn version(at: i64, by: &str, record: Value) -> Version {
        Version::of(stamp(at, by), into_object(record))
    }

    fn deletion(at: i64, by: &str) -> Version {
        Version::deletion(stamp(at, by))
    }

    /// The versions of the records of the vault, all with the stamp.
    fn versions_of(vault: &JsonObject, at: i64, by: &str) -> Versions {
        let records = records_of(vault, Scope::Vault).into_iter();
        records
            .map(|(key, record)| (key, Version::of(stamp(at, by), record)))
            .collect()
    }

    fn folder_of(versions: &Versions, key: &str) -> Value {
        let record = versions.get(key).unwrap().record.as_ref().unwrap();
        record["folderId"].clone()
    }

    fn versions(entries: Vec<(&str, Version)>) -> Versions {
        let entries = entries.into_iter();
        entries
            .map(|(key, version)| (key.to_owned(), version))
            .collect()
    }

    fn vault(folders: Value, ciphers: Value) -> JsonObject {
        into_object(json!({
            "format": "bitwarden-local-vault",
            "version": 2,
            "revisionDate": "2026-10-11T12:00:00.000Z",
            "account": {"masterPasswordVerifier": {"hash": "x"}},
            "sync": {"profile": {"id": "user"}, "folders": folders, "ciphers": ciphers},
        }))
    }

    /// The file of another device with the versions.
    fn source(device_id: &str, versions: &Versions) -> Source {
        Source {
            device_id: device_id.to_owned(),
            versions: versions.clone(),
            ..Source::default()
        }
    }

    fn refs(sources: &[Source]) -> Vec<&Source> {
        sources.iter().collect()
    }

    /// The versions of a device once it has left out what it no longer has to hold.
    fn tidied(versions: &Versions, others: &[Source], now_millis: i64) -> Versions {
        let mut tidied = versions.clone();
        tidy(&mut tidied, &refs(others), now_millis);
        tidied
    }

    /// The keys of the versions that a device keeps.
    fn kept(versions: &Versions, others: &[Source], now_millis: i64) -> Vec<String> {
        tidied(versions, others, now_millis).into_keys().collect()
    }

    fn keys(versions: &Versions) -> Vec<&str> {
        versions.keys().map(String::as_str).collect()
    }

    #[test]
    fn a_version_is_stamped_later_than_the_one_that_it_replaces() {
        let previous = stamp(5_000, "b");

        assert_eq!(Stamp::next(None, 1_000, "a", None), stamp(1_000, "a"));
        assert_eq!(
            Stamp::next(Some(&previous), 9_000, "a", None),
            stamp(9_000, "a")
        );
        // The clock of the device is behind that of the one that wrote the previous version.
        assert_eq!(
            Stamp::next(Some(&previous), 1_000, "a", None),
            stamp(5_001, "a")
        );
        assert!(stamp(5_000, "b") > stamp(5_000, "a"));
        assert!(stamp(5_001, "a") > stamp(5_000, "b"));
    }

    #[test]
    fn the_newest_version_of_each_record_is_taken_in_the_order_of_the_files() {
        let a = versions(vec![
            ("cipher:1", version(1, "a", json!({"id": "1", "v": "a"}))),
            ("cipher:2", version(5, "a", json!({"id": "2", "v": "a"}))),
        ]);
        let b = versions(vec![
            ("cipher:3", version(1, "b", json!({"id": "3", "v": "b"}))),
            ("cipher:2", version(4, "b", json!({"id": "2", "v": "b"}))),
            ("cipher:1", deletion(2, "b")),
        ]);

        let merged = merge([&a, &b]);

        assert_eq!(keys(&merged), ["cipher:1", "cipher:2", "cipher:3"]);
        assert_eq!(merged.get("cipher:1"), Some(&deletion(2, "b")));
        assert_eq!(merged.get("cipher:2"), a.get("cipher:2"));
        // Every device that reads the same files comes to the same versions.
        let reversed = merge([&b, &a]);
        for key in ["cipher:1", "cipher:2", "cipher:3"] {
            assert_eq!(reversed.get(key), merged.get(key));
        }
    }

    #[test]
    fn a_vault_is_made_of_the_record_of_its_account_and_its_folders_and_items() {
        let folder = json!({"id": "F", "name": "2.f"});
        let cipher = json!({"id": "C", "folderId": "F"});
        let original = vault(json!([folder]), json!([cipher]));

        let versions = versions_of(&original, 1, "a");
        let mut without_account = versions.clone();
        without_account.shift_remove("account");
        let mut without_master_password = versions.clone();
        without_master_password.shift_remove("masterPassword");
        let date = json!("2026-10-11T12:00:00.000Z");

        let all_keys = ["account", "masterPassword", "folder:f", "cipher:c"];
        assert_eq!(keys(&versions), all_keys);
        let account = versions.get("account").unwrap().record.as_ref().unwrap();
        assert_eq!(account["sync"]["folders"], json!([]));
        assert_eq!(account.get("format"), None);
        // The master password is a record of its own.
        assert_eq!(account["account"], json!({}));
        let master_password = versions.get("masterPassword").unwrap().record.as_ref();
        let verifier = json!({"account": {"masterPasswordVerifier": {"hash": "x"}}});
        assert_eq!(master_password, Some(&into_object(verifier)));
        assert_eq!(to_vault(&versions, date.clone()), Some(original));
        assert_eq!(to_vault(&without_account, date.clone()), None);
        assert_eq!(to_vault(&without_master_password, date), None);
    }

    #[test]
    fn the_fields_of_the_master_password_are_taken_out_of_the_account_and_put_back() {
        let mut original = vault(json!([]), json!([]));
        original[KEY_SYNC]["profile"] = json!({
            "id": "user",
            "key": "2.userKey",
            "masterPasswordHint": null,
            "securityStamp": "stamp",
            "privateKey": "2.privateKey",
        });
        original[KEY_SYNC]["userDecryption"] = json!({
            "masterPasswordUnlock": {"salt": "salt"},
            "userKeyId": "user-key-id",
        });

        let (account, master_password) = account_records(&original);

        let profile = json!({"id": "user", "privateKey": "2.privateKey"});
        assert_eq!(account[KEY_SYNC]["profile"], profile);
        let user_decryption = json!({"userKeyId": "user-key-id"});
        assert_eq!(account[KEY_SYNC]["userDecryption"], user_decryption);
        let expected = json!({
            "account": {"masterPasswordVerifier": {"hash": "x"}},
            "sync": {
                "profile": {
                    "key": "2.userKey",
                    "masterPasswordHint": null,
                    "securityStamp": "stamp",
                },
                "userDecryption": {"masterPasswordUnlock": {"salt": "salt"}},
            },
        });
        assert_eq!(Value::Object(master_password), expected);
        let date = json!("2026-10-11T12:00:00.000Z");
        let versions = versions_of(&original, 1, "a");
        assert_eq!(to_vault(&versions, date), Some(original));
    }

    #[test]
    fn the_file_of_a_device_is_read_back_as_the_versions_that_it_was_written_from() {
        let (account, _) = account_records(&vault(json!([]), json!([])));
        let written = versions(vec![
            ("account", version(3, "a", Value::Object(account))),
            ("cipher:c", version(1, "a", json!({"id": "C"}))),
            ("folder:f", deletion(2, "a")),
        ]);
        let only_items = versions(vec![("cipher:d", version(1, "a", json!({"id": "D"})))]);
        let mut removed = RemovedAttachments::new();
        removed.insert(("C".to_owned(), "a1".to_owned()), 4);
        let name = "Pixel 8".to_owned();
        let description = DeviceDescription {
            name,
            device_type: 0,
        };
        let device = Source {
            removed_attachments: removed.clone(),
            description: Some(description.clone()),
            ..source("a", &written)
        };

        let file = device.to_file();
        let items_file = source("a", &only_items).to_file();

        assert_eq!(file["records"]["cipher:c"], json!({"at": 1, "by": "a"}));
        assert_eq!(file["tombstones"]["folder:f"], json!({"at": 2, "by": "a"}));
        assert_eq!(file["removedAttachments"], json!({"C/a1": 4}));
        assert_eq!(file.get("since"), None);
        let said = json!({"id": "a", "name": "Pixel 8", "type": 0});
        assert_eq!(file["device"], said);
        // It is not part of the record of the account, which is read back as it was written.
        let read = Source::device("a".to_owned(), &file, Scope::Vault);
        assert_eq!(read.removed_attachments, removed);
        assert_eq!(read.description, Some(description));
        for key in ["account", "masterPassword", "cipher:c", "folder:f"] {
            assert_eq!(read.versions.get(key), written.get(key), "{key}");
        }
        let read_items = Source::device("a".to_owned(), &items_file, Scope::Vault);
        assert_eq!(read_items.versions, only_items);
        assert!(read_items.removed_attachments.is_empty());
        assert_eq!(items_file.get("device"), None);
        assert_eq!(read_items.description, None);
        // Nor does the file of another device say what this one is, nor one that says it in part.
        let read_other = Source::device("b".to_owned(), &file, Scope::Vault);
        assert_eq!(read_other.description, None);
        let mut without_type = file.clone();
        without_type["device"] = json!({"id": "a", "name": "Pixel 8"});
        let read_without_type = Source::device("a".to_owned(), &without_type, Scope::Vault);
        assert_eq!(read_without_type.description, None);
    }

    #[test]
    fn only_the_account_and_its_master_password_are_read_in_the_scope_of_the_account() {
        let original = vault(json!([{"id": "F"}]), json!([{"id": "C"}]));
        let mut file = original.clone();
        let stamps = json!({
            "account": {"at": 3, "by": "a"},
            "masterPassword": {"at": 3, "by": "a"},
            "folder:f": {"at": 1, "by": "a"},
            "cipher:c": {"at": 1, "by": "a"},
        });
        file.insert("records".to_owned(), stamps);
        let tombstones = json!({"cipher:d": {"at": 2, "by": "a"}});
        file.insert("tombstones".to_owned(), tombstones);

        let account = device_versions(&file, Scope::Account);
        let whole = device_versions(&file, Scope::Vault);

        assert_eq!(keys(&account), ["account", "masterPassword"]);
        let all_keys = [
            "account",
            "masterPassword",
            "folder:f",
            "cipher:c",
            "cipher:d",
        ];
        assert_eq!(keys(&whole), all_keys);
        for key in ["account", "masterPassword"] {
            assert_eq!(account.get(key), whole.get(key), "{key}");
        }
        // The vault that they make up has no folders and no items.
        let date = json!("2026-10-11T12:00:00.000Z");
        let without_items = vault(json!([]), json!([]));
        assert_eq!(to_vault(&account, date.clone()), Some(without_items));
        assert_eq!(to_vault(&whole, date), Some(original));
    }

    #[test]
    fn the_master_password_is_only_in_a_file_with_a_stamp_for_it() {
        let mut file = vault(json!([]), json!([]));
        file.insert(
            "records".to_owned(),
            json!({"account": {"at": 3, "by": "a"}}),
        );

        let read = device_versions(&file, Scope::Vault);

        // Not with the stamp of the account, whatever fields of it the file has.
        assert_eq!(keys(&read), ["account"]);
        assert_eq!(read.get("account").unwrap().stamp, stamp(3, "a"));
    }

    #[test]
    fn a_folder_or_an_item_without_a_stamp_is_stamped_by_its_revision_date() {
        let file = vault(
            json!([{"id": "f"}]),
            json!([{"id": "c", "revisionDate": "2026-10-11T12:00:01.000Z"}]),
        );

        let read = device_versions(&file, Scope::Vault);

        // Or by that of the file, and by no device. The record of the account and that of its
        // master password are not in a file without their stamps.
        let noon = 1_791_720_000_000;
        assert_eq!(keys(&read), ["folder:f", "cipher:c"]);
        assert_eq!(read.get("folder:f").unwrap().stamp, stamp(noon, ""));
        assert_eq!(read.get("cipher:c").unwrap().stamp, stamp(noon + 1_000, ""));
    }

    #[test]
    fn what_changed_is_stamped_and_what_is_gone_is_deleted() {
        let base_vault = vault(json!([{"id": "f"}]), json!([{"id": "c"}, {"id": "d"}]));
        let base = versions_of(&base_vault, 100, "b");
        let changed = vault(
            json!([{"id": "f"}]),
            json!([{"id": "c", "v": 1}, {"id": "e"}]),
        );

        let changes = changes(&base, &changed, 50, "a");

        assert_eq!(keys(&changes), ["cipher:d", "cipher:c", "cipher:e"]);
        assert_eq!(changes.get("cipher:d"), Some(&deletion(101, "a")));
        assert_eq!(changes.get("cipher:c").unwrap().stamp, stamp(101, "a"));
        assert_eq!(changes.get("cipher:e").unwrap().stamp, stamp(50, "a"));
    }

    fn rotation(at: i64, by: &str) -> KeyRotation {
        KeyRotation {
            at,
            by: by.to_owned(),
        }
    }

    /// The stamp of a version that was written with the key that the rotation made.
    fn keyed(key: &KeyRotation, at: i64, by: &str) -> Stamp {
        Stamp {
            key: Some(key.clone()),
            ..stamp(at, by)
        }
    }

    #[test]
    fn a_version_that_was_written_with_a_later_key_is_newer_whenever_it_was_written() {
        let earlier = rotation(10, "b");
        let later = rotation(9, "c");
        let rotated = Version::of(
            keyed(&rotation(5, "a"), 5, "a"),
            into_object(json!({"v": 1})),
        );
        // Written later, with the key before, by a device that did not have the rotation yet.
        let a = versions(vec![
            ("cipher:1", rotated.clone()),
            ("cipher:2", deletion(1, "a")),
        ]);
        let b = versions(vec![
            ("cipher:1", version(50, "b", json!({"v": 0}))),
            (
                "cipher:2",
                Version::of(keyed(&earlier, 2, "b"), into_object(json!({"v": 2}))),
            ),
        ]);

        let merged = merge([&a, &b]);

        assert_eq!(merged.get("cipher:1"), Some(&rotated));
        assert_eq!(
            merged.get("cipher:2").unwrap().stamp,
            keyed(&earlier, 2, "b")
        );
        assert!(keyed(&earlier, 1, "a") > stamp(i64::MAX, "z"));
        assert!(keyed(&earlier, 1, "a") > keyed(&later, 100, "z"));
        assert!(keyed(&earlier, 2, "a") > keyed(&earlier, 1, "z"));
    }

    #[test]
    fn a_rotation_is_later_than_the_one_that_made_the_key_before() {
        let previous = rotation(5_000, "b");

        assert_eq!(KeyRotation::next(None, 1_000, "a"), rotation(1_000, "a"));
        assert_eq!(
            KeyRotation::next(Some(&previous), 9_000, "a"),
            rotation(9_000, "a")
        );
        // The clock of the device is behind that of the one that made the key before.
        assert_eq!(
            KeyRotation::next(Some(&previous), 1_000, "a"),
            rotation(5_001, "a")
        );
    }

    #[test]
    fn what_changed_is_stamped_with_the_key_of_the_vault() {
        let base_vault = vault(json!([]), json!([{"id": "c"}, {"id": "d"}]));
        let base = versions_of(&base_vault, 100, "b");
        let mut changed = vault(json!([]), json!([{"id": "c", "v": 1}]));
        let key = json!({"at": 90, "by": "a"});
        changed.insert("account".to_owned(), json!({"userKeyRotation": key}));

        let changes = changes(&base, &changed, 50, "a");

        let key = rotation(90, "a");
        assert_eq!(
            changes.get("cipher:d"),
            Some(&Version::deletion(keyed(&key, 101, "a")))
        );
        assert_eq!(
            changes.get("cipher:c").unwrap().stamp,
            keyed(&key, 101, "a")
        );
        let master_password = changes.get("masterPassword").unwrap();
        assert_eq!(master_password.stamp, keyed(&key, 101, "a"));
        let record = master_password.record.as_ref().unwrap();
        assert_eq!(
            record["account"]["userKeyRotation"],
            json!({"at": 90, "by": "a"})
        );
    }

    #[test]
    fn a_file_with_a_version_of_a_rotated_key_is_written_as_version_4_and_read_back() {
        let key = rotation(7, "b");
        let written = versions(vec![
            ("cipher:c", version(1, "a", json!({"id": "C"}))),
            ("cipher:d", Version::deletion(keyed(&key, 2, "a"))),
        ]);
        let mut device = source("a", &written);
        device
            .retired_devices
            .insert("d".to_owned(), retirement(4, NOON));

        let file = device.to_file();

        assert_eq!(file["version"], 4);
        let stamp_of_d = json!({"at": 2, "by": "a", "key": {"at": 7, "by": "b"}});
        assert_eq!(file["tombstones"]["cipher:d"], stamp_of_d);
        assert_eq!(file["records"]["cipher:c"], json!({"at": 1, "by": "a"}));
        let read = Source::device("a".to_owned(), &file, Scope::Vault);
        assert_eq!(read.versions, written);
        // A stamp whose key is not a rotation is not read.
        let mut odd = file;
        odd["records"]["cipher:c"]["key"] = json!("b");
        let read = Source::device("a".to_owned(), &odd, Scope::Vault);
        assert_eq!(read.versions.get("cipher:c").unwrap().stamp, stamp(0, ""));
    }

    #[test]
    fn an_item_in_a_deleted_folder_is_in_none() {
        let mut merged = versions(vec![
            ("folder:gone", deletion(2, "a")),
            ("folder:kept", version(1, "a", json!({"id": "kept"}))),
            (
                "cipher:1",
                version(3, "b", json!({"id": "1", "folderId": "GONE"})),
            ),
            (
                "cipher:2",
                version(3, "b", json!({"id": "2", "folderId": "kept"})),
            ),
            (
                "cipher:3",
                version(3, "b", json!({"id": "3", "folderId": "unknown"})),
            ),
        ]);

        without_deleted_folders(&mut merged);

        assert_eq!(folder_of(&merged, "cipher:1"), Value::Null);
        assert_eq!(folder_of(&merged, "cipher:2"), json!("kept"));
        // A folder that the vault never had is not taken to be deleted.
        assert_eq!(folder_of(&merged, "cipher:3"), json!("unknown"));
    }

    #[test]
    fn a_device_leaves_out_what_another_device_replaced_once_every_device_can_have_it() {
        let mut own = versions(vec![
            ("account", version(DAY, "a", json!({"v": "a"}))),
            ("masterPassword", version(DAY, "a", json!({"v": "a"}))),
            ("cipher:1", version(DAY, "a", json!({"v": "a"}))),
            ("cipher:3", version(5 * DAY, "a", json!({"v": "a"}))),
        ]);
        let newer = versions(vec![
            ("account", version(2 * DAY, "b", json!({"v": "b"}))),
            ("masterPassword", version(2 * DAY, "b", json!({"v": "b"}))),
            ("cipher:1", version(2 * DAY, "b", json!({"v": "b"}))),
            ("cipher:3", version(4 * DAY, "b", json!({"v": "b"}))),
        ]);
        let others = [source("b", &newer)];
        let due = 2 * DAY + GRACE_MILLIS;
        let waiting = ["account", "cipher:1", "cipher:3"];

        // The master password is left to the other device right away, and another version, that
        // of the account as well, once every device has had time to get it.
        assert_eq!(kept(&own, &others, 3 * DAY), waiting);
        assert_eq!(kept(&own, &others, due - 1), waiting);
        assert_eq!(kept(&own, &others, due), ["cipher:3"]);
        assert!(tidy(&mut own, &refs(&others), due));
        assert!(!tidy(&mut own, &refs(&others), due));
    }

    #[test]
    fn a_version_that_a_deletion_replaced_is_replaced_by_it_right_away() {
        let own = versions(vec![
            ("cipher:1", version(2 * DAY, "a", json!({"v": "a"}))),
            ("cipher:2", version(6 * DAY, "a", json!({"v": "a"}))),
            ("masterPassword", version(2 * DAY, "a", json!({"v": "a"}))),
        ]);
        let newer = versions(vec![
            ("cipher:1", deletion(3 * DAY, "b")),
            ("cipher:2", deletion(5 * DAY, "b")),
            ("masterPassword", version(3 * DAY, "b", json!({"v": "b"}))),
        ]);
        let newest = versions(vec![("cipher:1", deletion(4 * DAY, "c"))]);
        let older = versions(vec![("cipher:1", version(DAY, "d", json!({"v": "d"})))]);
        let others = [source("b", &newer), source("c", &newest)];
        let with_older = [
            source("b", &newer),
            source("c", &newest),
            source("d", &older),
        ];
        let due = 3 * DAY + GRACE_MILLIS;
        let replaced = versions(vec![
            ("cipher:1", deletion(4 * DAY, "c")),
            ("cipher:2", version(6 * DAY, "a", json!({"v": "a"}))),
        ]);

        // The newest of the deletions takes the place of the item, whether or not a file has an
        // older version of it: a device that gets this file before the one with the deletion can
        // still have the file of the device that deleted the item from before, with an older
        // version. A version that is newer than a deletion stays, and an older master password is
        // left out right away.
        assert_eq!(tidied(&own, &others, 4 * DAY), replaced);
        assert_eq!(tidied(&own, &with_older, 4 * DAY), replaced);
        // Once every device has had time to get a deletion, the item is left to it.
        assert_eq!(keys(&tidied(&own, &others, due)), ["cipher:2"]);
        let mut item = versions(vec![("cipher:1", version(2 * DAY, "a", json!({"v": "a"})))]);
        assert!(tidy(&mut item, &refs(&others), 4 * DAY));
        assert!(!tidy(&mut item, &refs(&others), 4 * DAY));
    }

    #[test]
    fn the_attachments_that_a_change_takes_out_of_the_vault_are_removed() {
        let with = |id: &str, attachments: Value| json!({"id": id, "attachments": attachments});
        let base = versions(vec![
            (
                "cipher:1",
                version(1, "a", with("1", json!([{"id": "A"}, {"id": "B"}]))),
            ),
            ("cipher:2", version(1, "a", with("2", json!([{"id": "C"}])))),
            ("cipher:3", version(1, "a", with("3", json!([{"id": "D"}])))),
            ("folder:f", version(1, "a", json!({"id": "f"}))),
        ]);
        let changes = versions(vec![
            // One attachment is taken out, and the other one stays, whatever its case.
            ("cipher:1", version(2, "a", with("1", json!([{"id": "a"}])))),
            ("cipher:2", deletion(2, "a")),
            ("cipher:4", version(2, "a", with("4", json!([{"id": "E"}])))),
            ("folder:f", deletion(2, "a")),
        ]);

        let removed = removed_attachments(&base, &changes);

        let ids = |cipher: &str, attachment: &str| (cipher.to_owned(), attachment.to_owned());
        assert_eq!(removed, [ids("1", "B"), ids("2", "C")]);
    }

    #[test]
    fn the_content_of_a_removed_attachment_is_deleted_once_nothing_can_bring_it_back() {
        let removed_at = 10 * DAY;
        let ids = ("C".to_owned(), "A".to_owned());
        let cipher = |attachments: Value| json!({"id": "C", "attachments": attachments});
        let without = versions(vec![(
            "cipher:c",
            version(removed_at, "a", cipher(Value::Null)),
        )]);
        let deleted = versions(vec![("cipher:c", deletion(removed_at, "a"))]);
        let listed = cipher(json!([{"id": "a"}]));
        let back = versions(vec![("cipher:c", version(removed_at + 1, "b", listed))]);
        let later = removed_at + GRACE_MILLIS;

        assert_eq!(
            removal(&ids, removed_at, &without, later - 1),
            Removal::Wait
        );
        assert_eq!(removal(&ids, removed_at, &without, later), Removal::Delete);
        assert_eq!(removal(&ids, removed_at, &deleted, later), Removal::Delete);
        let nothing = Versions::default();
        assert_eq!(removal(&ids, removed_at, &nothing, later), Removal::Delete);
        // A change of a device that had not seen the removal has the attachment again.
        assert_eq!(
            removal(&ids, removed_at, &back, removed_at),
            Removal::Forget
        );
        assert_eq!(removal(&ids, removed_at, &back, later), Removal::Forget);
    }

    #[test]
    fn a_version_that_another_device_holds_as_well_is_kept() {
        let same = version(1, "", json!({"id": "1"}));
        let own = versions(vec![("cipher:1", same.clone())]);
        let other = versions(vec![("cipher:1", same)]);

        // As two devices that took over the same vault of the earlier layout hold it: neither has
        // a newer one, and each leaves it out once another device has one that replaces it.
        assert_eq!(tidied(&own, &[source("b", &other)], 10 * GRACE_MILLIS), own);
    }

    #[test]
    fn a_deletion_is_forgotten_once_it_is_old_and_nothing_older_is_left_to_bring_back() {
        let deleted_at = 10 * DAY;
        let own = versions(vec![("cipher:1", deletion(deleted_at, "a"))]);
        let holds_older = versions(vec![("cipher:1", version(1, "b", json!({"id": "1"})))]);
        let deleted_too = versions(vec![("cipher:1", deletion(2, "b"))]);
        let later = deleted_at + GRACE_MILLIS;

        assert_eq!(tidied(&own, &[], later - 1), own);
        assert_eq!(tidied(&own, &[source("b", &holds_older)], later), own);
        assert!(tidied(&own, &[], later).is_empty());
        let deleted_too = tidied(&own, &[source("b", &deleted_too)], later);
        assert!(deleted_too.is_empty());
    }

    #[test]
    fn the_deletion_of_a_folder_is_kept_while_a_file_has_an_item_in_the_folder() {
        let deleted_at = 10 * DAY;
        let own = versions(vec![("folder:f", deletion(deleted_at, "a"))]);
        let item = |folder_id: Value| version(1, "b", json!({"id": "1", "folderId": folder_id}));
        let in_folder = versions(vec![("cipher:1", item(json!("F")))]);
        let in_none = versions(vec![("cipher:1", item(Value::Null))]);
        let later = deleted_at + GRACE_MILLIS;

        // Forgetting it would put the item back in a folder that is not there.
        assert_eq!(tidied(&own, &[source("b", &in_folder)], later), own);
        let forgotten = tidied(&own, &[source("b", &in_none)], later);
        assert!(forgotten.is_empty());
        // An item in the file of the device itself counts as well.
        let mut with_item = own.clone();
        let in_own_file = version(1, "a", json!({"id": "2", "folderId": "f"}));
        with_item.insert("cipher:2".to_owned(), in_own_file);
        assert_eq!(tidied(&with_item, &[], later), with_item);
    }

    const EARLIER: &str = "2026-10-11T11:00:00.000Z";
    const NOON: &str = "2026-10-11T12:00:00.000Z";
    const LATER: &str = "2026-10-11T13:00:00.000Z";

    /// The file of a device, written at the date, that holds nothing.
    fn file_of(device_id: &str, revision_date: &str) -> Source {
        Source {
            device_id: device_id.to_owned(),
            revision_date: json!(revision_date),
            ..Source::default()
        }
    }

    fn retirement(at: i64, revision_date: &str) -> Retirement {
        let revision_date = revision_date.to_owned();
        Retirement { at, revision_date }
    }

    #[test]
    fn the_versions_of_a_retired_device_that_are_newer_are_taken_over_with_their_stamps() {
        let own = versions(vec![
            ("cipher:1", version(2, "a", json!({"v": "a"}))),
            ("cipher:2", version(1, "a", json!({"v": "a"}))),
        ]);
        let held = versions(vec![
            ("cipher:1", version(1, "d", json!({"v": "d"}))),
            ("cipher:2", version(3, "d", json!({"v": "d"}))),
            ("cipher:3", deletion(4, "d")),
            ("account", version(1, "d", json!({"v": "d"}))),
        ]);
        let mut taking = source("a", &own);
        let retired = Source {
            revision_date: json!(NOON),
            ..source("d", &held)
        };

        take_over(
            &mut taking,
            "a",
            &retired,
            None,
            &Versions::default(),
            10,
            20,
        );

        let all_keys = ["cipher:1", "cipher:2", "cipher:3", "account"];
        assert_eq!(keys(&taking.versions), all_keys);
        assert_eq!(taking.versions.get("cipher:1"), own.get("cipher:1"));
        for key in ["cipher:2", "cipher:3", "account"] {
            assert_eq!(taking.versions.get(key), held.get(key), "{key}");
        }
        let noted = BTreeMap::from([("d".to_owned(), retirement(10, NOON))]);
        assert_eq!(taking.retired_devices, noted);
    }

    #[test]
    fn a_master_password_that_another_device_replaced_is_not_kept_after_it_is_taken_over() {
        let held = versions(vec![("masterPassword", version(1, "d", json!({"v": "d"})))]);
        let newer = versions(vec![("masterPassword", version(2, "b", json!({"v": "b"})))]);
        let mut taking = source("a", &Versions::default());
        let retired = Source {
            revision_date: json!(NOON),
            ..source("d", &held)
        };
        let other = source("b", &newer);
        let files = [&retired, &other];

        take_over(
            &mut taking,
            "a",
            &retired,
            None,
            &Versions::default(),
            10,
            20,
        );
        assert_eq!(keys(&taking.versions), ["masterPassword"]);
        tidy(&mut taking.versions, &files, 20);

        assert!(taking.versions.is_empty());
    }

    #[test]
    fn the_devices_that_a_retired_device_retired_are_taken_over_but_not_this_one() {
        let mut taking = file_of("a", LATER);
        // Notes about earlier files of devices than those of the device that is retired, made later,
        // and one about the same file, made later.
        let held = [("x", 5, EARLIER), ("z", 7, EARLIER), ("w", 9, NOON)];
        for (device_id, at, revision_date) in held {
            let note = retirement(at, revision_date);
            taking.retired_devices.insert(device_id.to_owned(), note);
        }
        let mut retired = file_of("d", LATER);
        for (device_id, at, revision_date) in [
            ("x", 3, NOON),
            ("z", 6, NOON),
            ("w", 8, NOON),
            ("y", 2, NOON),
            ("a", 4, EARLIER),
        ] {
            let note = retirement(at, revision_date);
            retired.retired_devices.insert(device_id.to_owned(), note);
        }

        take_over(
            &mut taking,
            "a",
            &retired,
            None,
            &Versions::default(),
            10,
            20,
        );

        // The note about the later file of the device, or of two about the same one the earlier.
        let expected = BTreeMap::from([
            ("d".to_owned(), retirement(10, LATER)),
            ("w".to_owned(), retirement(8, NOON)),
            ("x".to_owned(), retirement(3, NOON)),
            ("y".to_owned(), retirement(2, NOON)),
            ("z".to_owned(), retirement(6, NOON)),
        ]);
        assert_eq!(taking.retired_devices, expected);
    }

    #[test]
    fn an_attachment_that_a_retired_device_removed_waits_90_days_from_when_it_is_taken_over() {
        let ids = |cipher: &str, attachment: &str| (cipher.to_owned(), attachment.to_owned());
        let mut retired = file_of("d", NOON);
        for attachment in ["A1", "A2", "A3"] {
            retired.removed_attachments.insert(ids("C", attachment), 1);
        }
        let mut taking = file_of("a", NOON);
        taking.removed_attachments.insert(ids("C", "A3"), 5);
        // The vault has the second one again.
        let cipher = json!({"id": "C", "attachments": [{"id": "a2"}]});
        let merged = versions(vec![("cipher:c", version(2, "b", cipher))]);

        take_over(&mut taking, "a", &retired, None, &merged, 10, 20);

        let expected = BTreeMap::from([(ids("C", "A1"), 20), (ids("C", "A3"), 5)]);
        assert_eq!(taking.removed_attachments, expected);
    }

    #[test]
    fn a_file_with_retired_devices_is_written_as_version_3_and_read_back() {
        let written = versions(vec![("cipher:c", version(1, "a", json!({"id": "C"})))]);
        let mut device = source("a", &written);
        let plain = device.to_file();
        let note = retirement(4, NOON);
        device.retired_devices.insert("d".to_owned(), note);

        let file = device.to_file();

        assert_eq!(plain["version"], 2);
        assert_eq!(plain.get("retiredDevices"), None);
        assert_eq!(file["version"], 3);
        let notes = json!({"d": {"at": 4, "revisionDate": NOON}});
        assert_eq!(file["retiredDevices"], notes);
        let read = Source::device("a".to_owned(), &file, Scope::Account);
        assert_eq!(read.retired_devices, device.retired_devices);
        // It is about the file, and not part of the record of the account.
        let (account, _) = account_records(&file);
        assert_eq!(account.get("retiredDevices"), None);
        // Notes that are not complete, or that a device could not have written, are not read.
        let mut odd = file;
        odd["retiredDevices"] = json!({
            "a": {"at": 4, "revisionDate": NOON},
            "e": {"at": "4", "revisionDate": NOON},
            "f": {"at": 4},
            "g": {"at": 4, "revisionDate": 1},
            "h.i": {"at": 4, "revisionDate": NOON},
            "j": [4, NOON],
        });
        let read = Source::device("a".to_owned(), &odd, Scope::Vault);
        assert!(read.retired_devices.is_empty());
        // An ID in another case is that of another directory, and so of another device.
        odd["retiredDevices"] = json!({"A": {"at": 4, "revisionDate": NOON}});
        let read = Source::device("a".to_owned(), &odd, Scope::Vault);
        let other = BTreeMap::from([("A".to_owned(), retirement(4, NOON))]);
        assert_eq!(read.retired_devices, other);
    }

    #[test]
    fn a_device_is_left_out_as_long_as_its_file_is_the_one_that_was_taken_over_or_an_earlier_one() {
        let mut a = file_of("a", LATER);
        for device_id in ["d", "f", "g"] {
            let note = retirement(5, NOON);
            a.retired_devices.insert(device_id.to_owned(), note);
        }
        a.retired_devices
            .insert("e".to_owned(), retirement(5, EARLIER));
        a.retired_devices
            .insert("h".to_owned(), retirement(5, "noon"));
        let mut b = file_of("b", LATER);
        b.retired_devices
            .insert("d".to_owned(), retirement(3, NOON));
        // The device was retired from a file that it wrote before the one that it has now, and a
        // file that does not say when it was written is never the one that was taken over.
        let d = file_of("d", NOON);
        let e = file_of("e", NOON);
        let f = Source {
            device_id: "f".to_owned(),
            ..Source::default()
        };
        // A copy of the directory from before the file that was taken over, as from a backup, and a
        // file whose revision date is not a date, as the note says.
        let g = file_of("g", EARLIER);
        let h = file_of("h", "noon");

        let retired = left_out(&[a, b, d, e, f, g, h]);

        let expected = [("d", 3), ("g", 5), ("h", 5)];
        let expected = expected.map(|(device_id, at)| (device_id.to_owned(), at));
        assert_eq!(retired, BTreeMap::from(expected));
    }

    #[test]
    fn the_file_of_a_device_says_when_each_version_came_into_it() {
        let noon = parse_date_millis(NOON).unwrap();
        let later = parse_date_millis(LATER).unwrap();
        let written = versions(vec![
            ("cipher:1", version(1, "a", json!({"id": "1"}))),
            ("cipher:2", version(2, "a", json!({"id": "2"}))),
            ("folder:f", deletion(3, "b")),
        ]);
        let mut device = file_of("a", NOON);
        device.versions = written;
        let mut file = device.to_file();
        let first = json!({"at": 1, "by": "a", "in": noon});
        assert_eq!(file["records"]["cipher:1"], first);
        assert_eq!(file["tombstones"]["folder:f"]["in"], noon);
        // An earlier client did not say it of the second item.
        file["records"]["cipher:2"] = json!({"at": 2, "by": "a"});

        // The file is written again later, with a new version of the first item and a new one.
        let mut read = Source::device("a".to_owned(), &file, Scope::Vault);
        let first = version(4, "a", json!({"id": "1"}));
        read.versions.insert("cipher:1".to_owned(), first.clone());
        let new = version(5, "a", json!({"id": "3"}));
        read.versions.insert("cipher:3".to_owned(), new);
        read.revision_date = json!(LATER);
        let file = read.to_file();

        assert_eq!(file["records"]["cipher:1"]["in"], later);
        assert_eq!(file["records"]["cipher:2"], json!({"at": 2, "by": "a"}));
        assert_eq!(file["records"]["cipher:3"]["in"], later);
        assert_eq!(file["tombstones"]["folder:f"]["in"], noon);
        let read = Source::device("a".to_owned(), &file, Scope::Vault);
        assert_eq!(read.versions["cipher:1"], first);
    }

    #[test]
    fn what_a_file_holds_since_one_of_its_device_that_was_taken_over_is_not_counted() {
        let dates = [EARLIER, NOON, LATER].map(|date| parse_date_millis(date).unwrap());
        let [earlier, noon, later] = dates;
        let mut file = file_of("d", LATER);
        file.versions = versions(vec![
            // Held since a file that was taken over, or since a later one.
            ("cipher:1", version(earlier, "d", json!({"id": "1"}))),
            ("cipher:2", version(earlier, "d", json!({"id": "2"}))),
            // A version of another device that came into the file later, and one that this device
            // wrote later with a clock that was behind.
            ("cipher:3", version(earlier, "x", json!({"id": "3"}))),
            ("cipher:4", version(earlier, "d", json!({"id": "4"}))),
            // Versions that an earlier client did not say when they came in of: one that the
            // device wrote before the file that was taken over, one of another device, and one
            // that the device wrote later.
            ("cipher:5", version(noon, "d", json!({"id": "5"}))),
            ("cipher:6", version(earlier, "x", json!({"id": "6"}))),
            ("cipher:7", version(later, "d", json!({"id": "7"}))),
        ]);
        let came_in = [
            ("cipher:1", Some(earlier)),
            ("cipher:2", Some(later)),
            ("cipher:3", Some(later)),
            ("cipher:4", Some(later)),
            ("cipher:5", None),
            ("cipher:6", None),
            ("cipher:7", None),
        ];
        for (key, came_in) in came_in {
            let stamp = file.versions[key].stamp.clone();
            file.arrivals.insert(key.to_owned(), (stamp, came_in));
        }

        let counted = file.not_taken_over(Some(noon));

        let counted_keys = ["cipher:2", "cipher:3", "cipher:4", "cipher:6", "cipher:7"];
        assert_eq!(keys(&counted), counted_keys);
        assert_eq!(keys(&file.not_taken_over(None)).len(), 7);
        // A device that retires it does not take over what it holds since then either.
        let mut taking = file_of("a", LATER);
        take_over(
            &mut taking,
            "a",
            &file,
            Some(noon),
            &Versions::default(),
            10,
            20,
        );
        assert_eq!(keys(&taking.versions), counted_keys);
    }

    #[test]
    fn a_note_in_a_file_that_is_left_out_does_not_count_for_what_a_later_file_holds() {
        let mut a = file_of("a", LATER);
        a.retired_devices
            .insert("d".to_owned(), retirement(5, EARLIER));
        a.retired_devices
            .insert("b".to_owned(), retirement(5, NOON));
        let mut b = file_of("b", NOON);
        for device_id in ["a", "d"] {
            let note = retirement(4, NOON);
            b.retired_devices.insert(device_id.to_owned(), note);
        }
        let files = [a, b, file_of("d", LATER)];
        let left_out = left_out(&files);

        let until = taken_over_until(&files, &left_out);

        // The notes of the file that is left out, about the device that took it over and another
        // one, do not count.
        assert_eq!(left_out.keys().collect::<Vec<_>>(), ["b"]);
        let [earlier, noon] = [EARLIER, NOON].map(|date| parse_date_millis(date).unwrap());
        let expected = [("b", noon), ("d", earlier)];
        let expected = expected.map(|(device_id, until)| (device_id.to_owned(), until));
        assert_eq!(until, BTreeMap::from(expected));
        assert_eq!(latest_taken_over(&files, "d"), Some(noon));
        assert_eq!(latest_taken_over(&files, "a"), Some(noon));
        assert_eq!(latest_taken_over(&files, "x"), None);
    }
}
