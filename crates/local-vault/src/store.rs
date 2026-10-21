use std::collections::BTreeSet;
use std::ops::Deref;

use serde_json::{Value, json};

use crate::date::parse_date_millis;
use crate::fs::{FileSystem, IoError};
use crate::json::{
    self, JsonObject, int, is_entry_name, is_safe_segment, normalize_email, obj, string,
};
use crate::merge::{self, Removal, Scope, Source, Versions};

/// The value of the `format` field that identifies a local vault file.
pub const LOCAL_VAULT_FORMAT: &str = "bitwarden-local-vault";

/// The version of the local vault file layout that is written.
pub const LOCAL_VAULT_VERSION: i64 = 2;

/// The version of the layout before this one, in which the `vault.json` of an account held the
/// whole vault. The devices took such vaults over into their files, and they are no longer read.
const SINGLE_FILE_VERSION: i64 = 1;

pub(crate) const KEY_FORMAT: &str = "format";
pub(crate) const KEY_VERSION: &str = "version";
pub(crate) const KEY_REVISION_DATE: &str = "revisionDate";
pub(crate) const KEY_ACCOUNT: &str = "account";
pub(crate) const KEY_SYNC: &str = "sync";

const VAULT_FILE: &str = "vault.json";
const VAULT_TEMP_FILE: &str = "vault.json.tmp";
const VAULT_BACKUP_FILE: &str = "vault.json.bak";
const DEVICES_DIRECTORY: &str = "devices";
const ATTACHMENTS_DIRECTORY: &str = "attachments";

/// The files that can hold the complete file of a device, in the order they are trusted. Only an
/// interrupted write leaves it in anything but the first.
const DEVICE_READ_ORDER: [&str; 3] = [VAULT_FILE, VAULT_TEMP_FILE, VAULT_BACKUP_FILE];

/// The files that can hold the complete `vault.json` of an account, in the order they are trusted.
/// Its backup is not read: `vault.json.tmp` is complete whenever a write of it is interrupted, and
/// the backup can hold a vault of the earlier layout that a device took over.
const ACCOUNT_READ_ORDER: [&str; 2] = [VAULT_FILE, VAULT_TEMP_FILE];

/// The value of the `format` field of the `vault.json` of an account that was deleted. It is not
/// that of a vault, so that a client that does not know it takes the account to be of a layout
/// that it does not know, which it does not use or write.
const DELETED_FORMAT: &str = "bitwarden-local-vault-deleted";

const NOT_WRITABLE_MESSAGE: &str =
    "The vault of the account has a layout that is not known, or the account was deleted.";

const ON_ITS_WAY_MESSAGE: &str = "The vault of the account has not fully come to this device yet.";

const UNKNOWN_LAYOUT_MESSAGE: &str =
    "The vault of the account has a layout that is not known: a newer client wrote it.";

const EARLIER_LAYOUT_MESSAGE: &str =
    "The vault of the account has the layout of version 1, which this client no longer reads.";

/// Reads and writes the vault of each account on top of a [`FileSystem`].
///
/// Every account has a directory named after its ID. Every device that shares the vault folder
/// writes a file of its own in it, which nothing else writes, and the vault is put together from
/// the files of all devices (see `merge.rs`). The `vault.json` of the account only says which
/// layout the directory has, or that the account was deleted:
///
/// ```text
/// <account id>/vault.json
/// <account id>/devices/<device id>/vault.json
/// <account id>/attachments/<cipher id>/<attachment id>
/// ```
///
/// In the earlier layout, `vault.json` held the whole vault, which the devices took over into
/// their files. Such a vault is no longer read: an account that still has one cannot be used.
pub(crate) struct LocalVaultStore<F> {
    file_system: F,
    /// The ID of this device, which names the directory that it writes its files in. The local
    /// server is only made for one that can be the name of a directory.
    device_id: String,
}

/// The vault of an account as it was read, along with the versions that it was put together
/// from. A change of the vault is written against them: what is written is what differs between
/// them and the vault that the change comes to (see [`LocalVaultStore::write_vault`]). That of a
/// new account, which has no files yet, is the default one.
#[derive(Debug, Clone, Default, PartialEq)]
pub(crate) struct ReadVault {
    vault: JsonObject,
    base: Versions,
}

impl Deref for ReadVault {
    type Target = JsonObject;

    fn deref(&self) -> &JsonObject {
        &self.vault
    }
}

/// Why the vault of an account cannot be used for now, although the account may well be there,
/// and have the email that a request looks for. A client that is told that it is not there logs
/// it out, derives the master key the default way, or registers its email again.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Unusable {
    /// The account has this layout, but none of its files that have come holds the record of the
    /// account, or none holds that of its master password. A tool that syncs the vault folder
    /// does not bring files in the order that they were written, so the one that holds it is
    /// still on its way: the `vault.json` of the account can come before the file of the device
    /// that registered the account, the file of a device that left the master password out, as
    /// another device holds a newer one, before the file of that other device, and the files of
    /// the devices before the `vault.json` of the account.
    OnItsWay,
    /// A file of the account has a layout that is not known, which a newer client wrote.
    UnknownLayout,
    /// The `vault.json` of the account holds a vault of the earlier layout, which no device took
    /// over, and which is no longer read.
    EarlierLayout,
}

impl Unusable {
    /// What a request fails with that needs the vault, or that looks for an account by an email
    /// that the account may have.
    pub(crate) fn message(self) -> &'static str {
        match self {
            Self::OnItsWay => ON_ITS_WAY_MESSAGE,
            Self::UnknownLayout => UNKNOWN_LAYOUT_MESSAGE,
            Self::EarlierLayout => EARLIER_LAYOUT_MESSAGE,
        }
    }
}

/// Why the vault of an account, or the account with an email, could not be read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ReadError {
    /// The vault folder could not be read.
    Io(IoError),
    /// The vault of the account with the ID cannot be used for now. The ID is the name of the
    /// directory of the account, which is how the account is found in the vault folder.
    Unusable(String, Unusable),
}

impl From<IoError> for ReadError {
    fn from(error: IoError) -> Self {
        Self::Io(error)
    }
}

/// The files of the vault of an account.
#[derive(Default)]
struct AccountFiles {
    /// Whether `vault.json` says that the directory has this layout.
    has_marker: bool,
    /// The files of the devices, sorted by the IDs of the devices.
    devices: Vec<Source>,
}

impl AccountFiles {
    /// Takes the file of the device out of the files, if there is one.
    fn take_device(&mut self, device_id: &str) -> Option<Source> {
        let is_device = |source: &Source| source.device_id == device_id;
        let index = self.devices.iter().position(is_device)?;
        Some(self.devices.remove(index))
    }

    /// The versions that the vault is made of (see [`merge::merge`]).
    fn merged(&self) -> Versions {
        merge::merge(self.devices.iter().map(|source| &source.versions))
    }

    /// The latest date that one of the files was written at.
    fn revision_date(&self) -> Value {
        let dates = self.devices.iter().map(|source| &source.revision_date);
        let latest = dates.max_by_key(|date| date.as_str().and_then(parse_date_millis));
        latest.cloned().unwrap_or(Value::Null)
    }
}

/// What a directory of the vault folder has in its `vault.json`, or in the files that stand in
/// for it while it is replaced.
enum Content {
    /// No file that is complete.
    Nothing,
    /// A file of a local vault, with the version of its layout, or `None` if its version is not
    /// an integer, as that of no layout is.
    Vault(Option<i64>, JsonObject),
    /// The `vault.json` of an account that was deleted.
    Deleted,
    /// A file that is not a local vault.
    Unknown,
}

impl<F: FileSystem> LocalVaultStore<F> {
    /// A store on the file system, for the device with the ID.
    pub(crate) fn new(file_system: F, device_id: &str) -> Self {
        Self {
            file_system,
            device_id: device_id.to_owned(),
        }
    }

    pub(crate) fn file_system(&self) -> &F {
        &self.file_system
    }

    /// Returns every account with the email, by its ID, with its vault without its folders and
    /// items, which do not tell whose an account is (see [`Self::read_account`]). Nothing keeps a
    /// vault folder from holding more than one, as when an account is registered again on a
    /// device that the first one has not arrived on yet.
    ///
    /// The accounts are sorted by their IDs, as the order that a directory is listed in is not
    /// the same everywhere: every client that shares the folder has to take the same account to
    /// be the first. The IDs are made of ASCII only, so their order is the same as that of their
    /// UTF-16 code units, which the clients that came before sorted them by.
    ///
    /// Fails if no account has the email but the vault of an account cannot be used for now, as
    /// the email may be that of this one: one that is still on its way, or that has a layout
    /// that is not read. A client that is told that no account has the email would derive the
    /// master key the default way, take the master password to be wrong, or register the email
    /// again. The error names the first such account, as long as no account with the email is
    /// found that the request can go by.
    pub(crate) async fn find_accounts(
        &self,
        email: &str,
    ) -> Result<Vec<(String, JsonObject)>, ReadError> {
        let normalized_email = normalize_email(email);
        let mut found = Vec::new();
        // The first account that may have the email and cannot be used, if one cannot, and why.
        let mut unusable = None;
        for account_id in safe_names(&self.file_system, &[]).await? {
            // The email of an account that cannot be used is not known. Failing for it right
            // away would keep every other account from being found.
            let account = match self.read_account(&account_id).await {
                Ok(Some(account)) => account,
                Ok(None) => continue,
                Err(error @ ReadError::Unusable(..)) => {
                    unusable = unusable.or(Some(error));
                    continue;
                }
                Err(error) => return Err(error),
            };
            let account_email = obj(&account, KEY_SYNC)
                .and_then(|sync| obj(sync, "profile"))
                .and_then(|profile| string(profile, "email"))
                .map(normalize_email);
            if account_email.as_ref() == Some(&normalized_email) {
                found.push((account_id, account));
            }
        }
        match unusable {
            Some(error) if found.is_empty() => Err(error),
            _ => Ok(found),
        }
    }

    /// Returns the vault of the account, put together from the files of all devices, with what
    /// it was put together from, which a change of it is written against. Returns `None` if the
    /// account is not there: it was deleted, or the directory is not that of an account.
    ///
    /// A file of a layout that is not known keeps the whole vault from being used, and from
    /// being written: a newer client may have written it, and what it says is not known.
    ///
    /// Fails if the file that holds the record of the account, or that of its master password,
    /// has not come yet, or if a file of the account has a layout that is not known, or the
    /// earlier one, as the account may well be there: a client that is told that it is not there
    /// logs it out.
    pub(crate) async fn read_vault(
        &self,
        account_id: &str,
    ) -> Result<Option<ReadVault>, ReadError> {
        let read = self.put_together(account_id, Scope::Vault).await?;
        Ok(read.map(|(vault, base)| ReadVault { vault, base }))
    }

    /// Returns the vault of the account without its folders and items, which are left empty, or
    /// `None` if the account is not there. It has the records of the account and of its master
    /// password, which tell who the account is and how it logs in, and is all that a request
    /// that looks for an account needs. Fails as [`Self::read_vault`] does.
    pub(crate) async fn read_account(
        &self,
        account_id: &str,
    ) -> Result<Option<JsonObject>, ReadError> {
        let read = self.put_together(account_id, Scope::Account).await?;
        Ok(read.map(|(account, _)| account))
    }

    /// Puts the vault of the account together from the records in the scope of the files of all
    /// devices, and returns it with the versions that it was put together from, or `None` if the
    /// account is not there. Fails if it cannot be used for now (see [`Unusable`]).
    async fn put_together(
        &self,
        account_id: &str,
        scope: Scope,
    ) -> Result<Option<(JsonObject, Versions)>, ReadError> {
        let Some(files) = self.read_files(account_id, scope).await? else {
            return Ok(None);
        };
        let merged = files.merged();
        match merge::to_vault(&merged, files.revision_date()) {
            Some(vault) => Ok(Some((vault, merged))),
            // What is left of an account that was deleted is never read, as its `vault.json`
            // says that it was deleted. Any other file of an account comes with the records of
            // the account and of its master password in the same file or in other ones.
            None if files.has_marker || !files.devices.is_empty() => Err(ReadError::Unusable(
                account_id.to_owned(),
                Unusable::OnItsWay,
            )),
            None => Ok(None),
        }
    }

    /// Writes the change of the vault of the account from the one that was read to the vault
    /// that is given, which it comes to now, to the file of this device: a new version of every
    /// record that the two have differently, and a deletion of every record that the vault that
    /// is given no longer has. A request writes the vault that it read once.
    ///
    /// Nothing else is written, apart from the `vault.json` of the account by the device that the
    /// account first has a file of, which says that the account has this layout.
    ///
    /// The file that is replaced is kept as the backup, and an interrupted write never leaves
    /// the device without a complete file. The change stands once that file is written: a
    /// `vault.json` of the account that cannot be written after it is written with the next one,
    /// unless another device has a file of the account by then.
    pub(crate) async fn write_vault(
        &self,
        account_id: &str,
        read: &ReadVault,
        vault: &JsonObject,
        now_millis: i64,
    ) -> Result<(), IoError> {
        if !is_safe_segment(account_id) {
            return Err(IoError::new("Invalid account ID"));
        }
        let mut files = match self.read_files(account_id, Scope::Vault).await {
            Ok(Some(files)) => files,
            Ok(None) | Err(ReadError::Unusable(..)) => {
                return Err(IoError::new(NOT_WRITABLE_MESSAGE));
            }
            Err(ReadError::Io(error)) => return Err(error),
        };
        let changes = merge::changes(&read.base, vault, now_millis, &self.device_id);
        let mut own = files.take_device(&self.device_id).unwrap_or_default();
        // The content of an attachment that the change removes is deleted once nothing can bring
        // the attachment back (see `Self::tidy`).
        for ids in merge::removed_attachments(&read.base, &changes) {
            own.removed_attachments.insert(ids, now_millis);
        }
        own.versions.extend(changes);
        let others: Vec<&Source> = files.devices.iter().collect();
        merge::tidy(&mut own.versions, &others, now_millis);
        own.revision_date = vault.get(KEY_REVISION_DATE).cloned().unwrap_or(Value::Null);
        self.write_own_file(account_id, &own).await?;
        // Only the device that the account first has a file of writes it: the only one that has
        // a file, as the device that registers the account does. Another device that does not have
        // it yet gets it from that device. If it wrote it, it could do so as a device that deletes
        // the account writes there that the account was deleted, which a tool that syncs the
        // folder may resolve by keeping its file.
        //
        // The change is written by now, so that `vault.json` does not fail it when it cannot be
        // written: the client would make the change again. The next write writes it, as it is
        // still missing then, unless another device has a file of the account by then: no device
        // writes it then, and the account goes without it, which only a device that has none of
        // the files of its devices takes for an account that is not there.
        if !files.has_marker && files.devices.is_empty() {
            let _ = self.write_file(&[account_id], &marker()).await;
        }
        Ok(())
    }

    /// Leaves out of the file of this device what it no longer has to hold, and deletes the
    /// content of the attachments that it removed once nothing can bring them back. The vault
    /// stays the same: a version that is left out is replaced by one that another device holds,
    /// which every device has had time to get, one that is replaced by a deletion of another device
    /// is not in the vault either way, and a deletion that is left out is no longer needed.
    ///
    /// The content of an attachment is shared by every device, and a device that had not seen
    /// the removal yet can bring the attachment back with a change of the item, so it is only
    /// deleted as [`merge::removal`] says. Content that cannot be deleted is deleted the next
    /// time.
    ///
    /// Fails if the file of this device could not be written.
    pub(crate) async fn tidy(&self, account_id: &str, now_millis: i64) -> Result<(), IoError> {
        let mut files = match self.read_files(account_id, Scope::Vault).await {
            Ok(Some(files)) => files,
            Ok(None) | Err(ReadError::Unusable(..)) => return Ok(()),
            Err(ReadError::Io(error)) => return Err(error),
        };
        let merged = files.merged();
        let Some(mut own) = files.take_device(&self.device_id) else {
            return Ok(());
        };
        let others: Vec<&Source> = files.devices.iter().collect();
        let mut is_changed = merge::tidy(&mut own.versions, &others, now_millis);
        // The items that the vault no longer has, whose content is gone now.
        let mut gone = BTreeSet::new();
        for (ids, removed_at) in std::mem::take(&mut own.removed_attachments) {
            let is_kept = match merge::removal(&ids, removed_at, &merged, now_millis) {
                Removal::Wait => true,
                Removal::Forget => false,
                Removal::Delete => {
                    let (cipher_id, attachment_id) = &ids;
                    let deletion = self.delete_attachment(account_id, cipher_id, attachment_id);
                    let is_deleted = matches!(deletion.await, Ok(true));
                    if is_deleted && !merge::has_cipher(&merged, cipher_id) {
                        gone.insert(cipher_id.clone());
                    }
                    !is_deleted
                }
            };
            if is_kept {
                own.removed_attachments.insert(ids, removed_at);
            } else {
                is_changed = true;
            }
        }
        for cipher_id in &gone {
            self.delete_item_directory(account_id, cipher_id).await;
        }
        if is_changed {
            self.write_own_file(account_id, &own).await?;
        }
        Ok(())
    }

    /// Replaces the file of this device in the directory of the account.
    async fn write_own_file(&self, account_id: &str, own: &Source) -> Result<(), IoError> {
        let file = own.to_file();
        let directory = [account_id, DEVICES_DIRECTORY, self.device_id.as_str()];
        self.write_file(&directory, &Value::Object(file)).await
    }

    /// Deletes the vault and the attachments of the account, the files of every device
    /// included, and leaves only a `vault.json` that says that the account was deleted. Returns
    /// `true` if nothing else remains of it, and fails if the account could not be deleted.
    ///
    /// A tool that syncs the vault folder brings the deletion to another device one file at a
    /// time, and that device may write its file again in the meantime, as it does not know about
    /// the deletion yet. What is left that way is not an account, as that `vault.json` says, and
    /// not files that are still on their way. It is written first, so that a deletion that is
    /// interrupted leaves no account either.
    ///
    /// Everything else in the directory of the account is deleted, also what a tool that syncs
    /// the vault folder put there: the copies that it keeps of a `vault.json` that it had two
    /// versions of can hold a whole vault of the earlier layout, the user key encrypted with the
    /// master password of that time included. An entry whose name the file system is not handed
    /// is left behind (see [`is_entry_name`]).
    pub(crate) async fn delete_account(&self, account_id: &str) -> Result<bool, IoError> {
        if !is_safe_segment(account_id) {
            return Err(IoError::new("Invalid account ID"));
        }
        self.write_file(&[account_id], &deleted_marker()).await?;
        // The account is deleted by now, so what cannot be deleted after it is left behind.
        let Ok(names) = self.file_system.list(&[account_id]).await else {
            return Ok(false);
        };
        let mut is_deleted = true;
        for name in names.iter().filter(|name| *name != VAULT_FILE) {
            let deletion = if is_entry_name(name) {
                self.file_system.delete(&[account_id, name.as_str()]).await
            } else {
                Ok(false)
            };
            is_deleted &= matches!(deletion, Ok(true));
        }
        Ok(is_deleted)
    }

    /// Returns where the encrypted content of an attachment is kept, or `None` if one of the
    /// names could not be the name of a file.
    pub(crate) fn attachment_path(
        &self,
        account_id: &str,
        cipher_id: &str,
        attachment_id: &str,
    ) -> Option<Vec<String>> {
        let path = [account_id, ATTACHMENTS_DIRECTORY, cipher_id, attachment_id];
        path.iter()
            .all(|name| is_safe_segment(name))
            .then(|| owned_path(&path))
    }

    /// Returns where the encrypted content of an attachment is kept, or `None` if there is none.
    pub(crate) async fn attachment(
        &self,
        account_id: &str,
        cipher_id: &str,
        attachment_id: &str,
    ) -> Result<Option<Vec<String>>, IoError> {
        let Some(path) = self.attachment_path(account_id, cipher_id, attachment_id) else {
            return Ok(None);
        };
        let exists = self.file_system.exists(&as_strs(&path)).await?;
        Ok(exists.then_some(path))
    }

    /// Deletes the encrypted content of an attachment. Returns `true` if nothing remains of it,
    /// which is also the case for names that nothing is ever stored under.
    async fn delete_attachment(
        &self,
        account_id: &str,
        cipher_id: &str,
        attachment_id: &str,
    ) -> Result<bool, IoError> {
        match self.attachment_path(account_id, cipher_id, attachment_id) {
            Some(path) => self.file_system.delete(&as_strs(&path)).await,
            None => Ok(true),
        }
    }

    /// Deletes the directory that held the content of the attachments of an item, if it is
    /// empty. A directory is deleted with everything in it, so this is only for an item that the
    /// vault no longer has: the content of a new attachment of an item that it has can be on its
    /// way to the directory, from the device that added the attachment. A directory that cannot
    /// be deleted is left behind, as nothing is in it.
    async fn delete_item_directory(&self, account_id: &str, cipher_id: &str) {
        if !is_safe_segment(account_id) || !is_safe_segment(cipher_id) {
            return;
        }
        let directory = [account_id, ATTACHMENTS_DIRECTORY, cipher_id];
        let listed = self.file_system.list(&directory).await;
        if listed.is_ok_and(|names| names.is_empty()) {
            let _ = self.file_system.delete(&directory).await;
        }
    }

    /// Reads the records in the scope of the files of the vault of the account, or returns `None`
    /// if the account is not there: it was deleted, or the directory is not that of an account.
    /// Fails with [`Unusable::UnknownLayout`] if a file has a layout that is not known.
    async fn read_files(
        &self,
        account_id: &str,
        scope: Scope,
    ) -> Result<Option<AccountFiles>, ReadError> {
        if !is_safe_segment(account_id) {
            return Ok(None);
        }
        let unusable = |why| ReadError::Unusable(account_id.to_owned(), why);
        let mut files = AccountFiles::default();
        let directory = [account_id];
        match self.read_content(&directory, &ACCOUNT_READ_ORDER).await? {
            Content::Nothing => {}
            Content::Vault(Some(LOCAL_VAULT_VERSION), _) => files.has_marker = true,
            Content::Vault(Some(SINGLE_FILE_VERSION), _) => {
                return Err(unusable(Unusable::EarlierLayout));
            }
            // A newer client wrote it, so the account may well be there.
            Content::Vault(..) => return Err(unusable(Unusable::UnknownLayout)),
            // The files of the devices are what is left of the account, if anything, or the
            // directory is not that of an account at all.
            Content::Deleted | Content::Unknown => return Ok(None),
        }
        let devices_directory = [account_id, DEVICES_DIRECTORY];
        for device_id in safe_names(&self.file_system, &devices_directory).await? {
            let directory = [account_id, DEVICES_DIRECTORY, device_id.as_str()];
            match self.read_content(&directory, &DEVICE_READ_ORDER).await? {
                Content::Nothing => {}
                Content::Vault(Some(LOCAL_VAULT_VERSION), file) => {
                    let source = Source::device(device_id.clone(), &file, scope);
                    files.devices.push(source);
                }
                // Only a client that knows another layout writes anything else there.
                Content::Vault(..) | Content::Deleted | Content::Unknown => {
                    return Err(unusable(Unusable::UnknownLayout));
                }
            }
        }
        Ok(Some(files))
    }

    /// Reads the first file of the directory that is complete, of those in the order. The files
    /// after it are only there for a write that was interrupted, so they are not read in its place
    /// when it is not a vault that can be used: they hold an older one, and writing that one back
    /// would replace the one that is there.
    async fn read_content(&self, directory: &[&str], order: &[&str]) -> Result<Content, IoError> {
        for file in order {
            let bytes = self.file_system.read(&file_path(directory, file)).await?;
            // An interrupted write leaves a file that is not complete.
            let Some(value) = bytes.as_deref().and_then(json::parse) else {
                continue;
            };
            let Value::Object(content) = value else {
                return Ok(Content::Unknown);
            };
            let format = string(&content, KEY_FORMAT);
            if format == Some(DELETED_FORMAT) {
                return Ok(Content::Deleted);
            }
            if format != Some(LOCAL_VAULT_FORMAT) {
                return Ok(Content::Unknown);
            }
            let version = int(&content, KEY_VERSION);
            return Ok(Content::Vault(version, content));
        }
        Ok(Content::Nothing)
    }

    /// Replaces the `vault.json` of the directory with the content. The file that it replaces
    /// is kept as the backup, and an interrupted write never leaves the directory without a
    /// complete file.
    async fn write_file(&self, directory: &[&str], content: &Value) -> Result<(), IoError> {
        let content = json::to_pretty_bytes(content);
        let vault_path = file_path(directory, VAULT_FILE);
        let temp_path = file_path(directory, VAULT_TEMP_FILE);
        let fs = &self.file_system;
        fs.write(&temp_path, &content).await?;
        if fs.exists(&vault_path).await? {
            fs.delete(&file_path(directory, VAULT_BACKUP_FILE)).await?;
            fs.rename(&vault_path, VAULT_BACKUP_FILE).await?;
        }
        if !fs.rename(&temp_path, VAULT_FILE).await? {
            // Not every place a vault can be kept in is able to rename. The complete temporary
            // file is still there to read the vault from if this write is interrupted.
            fs.write(&vault_path, &content).await?;
            fs.delete(&temp_path).await?;
        }
        Ok(())
    }
}

/// What the `vault.json` of an account has in this layout: only that it is this layout, which a
/// client that knows only the earlier one leaves alone. It is the same on every device, so that
/// two devices that write it write the same file.
fn marker() -> Value {
    json!({"format": LOCAL_VAULT_FORMAT, "version": LOCAL_VAULT_VERSION})
}

/// What the `vault.json` of an account that was deleted has: only that it was deleted. It is the
/// same on every device, so that two devices that delete the account write the same file.
fn deleted_marker() -> Value {
    json!({"format": DELETED_FORMAT})
}

/// The path of the file in the directory.
fn file_path<'a>(directory: &[&'a str], file: &'a str) -> Vec<&'a str> {
    let mut path = directory.to_vec();
    path.push(file);
    path
}

/// Returns the accounts that the vault folder of the source has and that of the target does
/// not, sorted: what a client copies when the vault moves to another folder. An account that
/// the target has is never one of them, so copying them never replaces an account that another
/// device put there.
///
/// An account is any entry whose name the local vault could have given it. The client copies
/// each of them with everything in it, as it can do it as a stream.
pub async fn accounts_missing_in<S: FileSystem, T: FileSystem>(
    source: &S,
    target: &T,
) -> Result<Vec<String>, IoError> {
    let mut missing = Vec::new();
    for account_id in safe_names(source, &[]).await? {
        if !target.exists(&[account_id.as_str()]).await? {
            missing.push(account_id);
        }
    }
    Ok(missing)
}

/// Returns the files that a client copies of the accounts that the vault folders of both the
/// source and the target have, when the vault moves to the target, for the device with the ID:
/// the content of attachments that the target does not have, and the files of the directory of
/// the device that the target has otherwise or not at all. No other device writes that
/// directory, so the files of the source are the ones that the device wrote last: without them,
/// the changes that it made in the source would be left behind, along with the content of the
/// attachments that it added there. The files of the other devices are not copied: those of the
/// target are on their way to it, and a copy could replace a newer one of the device that wrote
/// it.
///
/// Each file is a path from the vault folder. They are copied in this order, which brings the
/// content of attachments before the file that lists them, and the `vault.json` of the device
/// last, so that a copy that is interrupted leaves the earlier file in its place.
pub async fn device_files_missing_in<S: FileSystem, T: FileSystem>(
    source: &S,
    target: &T,
    device_id: &str,
) -> Result<Vec<Vec<String>>, IoError> {
    let mut missing: Vec<Vec<String>> = Vec::new();
    if !is_safe_segment(device_id) {
        return Ok(missing);
    }
    for account_id in safe_names(source, &[]).await? {
        // An account that the target does not have is copied with everything in it.
        if !target.exists(&[account_id.as_str()]).await? {
            continue;
        }
        let attachments = [account_id.as_str(), ATTACHMENTS_DIRECTORY];
        for cipher_id in safe_names(source, &attachments).await? {
            let directory = [
                account_id.as_str(),
                ATTACHMENTS_DIRECTORY,
                cipher_id.as_str(),
            ];
            for attachment_id in safe_names(source, &directory).await? {
                let path = file_path(&directory, &attachment_id);
                if !target.exists(&path).await? {
                    missing.push(owned_path(&path));
                }
            }
        }
        let directory = [account_id.as_str(), DEVICES_DIRECTORY, device_id];
        for file in [VAULT_BACKUP_FILE, VAULT_TEMP_FILE, VAULT_FILE] {
            let path = file_path(&directory, file);
            let Some(content) = source.read(&path).await? else {
                continue;
            };
            if target.read(&path).await?.as_deref() != Some(content.as_slice()) {
                missing.push(owned_path(&path));
            }
        }
    }
    Ok(missing)
}

/// The names in the directory that the local vault could have given an entry, sorted: the order
/// that a directory is listed in is not the same everywhere.
async fn safe_names<F: FileSystem>(fs: &F, directory: &[&str]) -> Result<Vec<String>, IoError> {
    let names = fs.list(directory).await?.into_iter();
    let mut names: Vec<String> = names.filter(|name| is_safe_segment(name)).collect();
    names.sort();
    Ok(names)
}

/// The path with names of its own.
fn owned_path(path: &[&str]) -> Vec<String> {
    path.iter().map(|name| (*name).to_owned()).collect()
}

/// The path as the file system takes it.
pub(crate) fn as_strs(path: &[String]) -> Vec<&str> {
    path.iter().map(String::as_str).collect()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use crate::memory_fs::MemoryFileSystem;
    use futures::executor::block_on;

    const ID: &str = "11111111-2222-4333-8444-555555555555";
    const DEVICE: &str = "device-a";
    const OTHER_DEVICE: &str = "device-b";
    const NOW: i64 = 1_791_720_000_000;
    const INCOMPLETE: &[u8] = b"{\"format\": \"bitwarden-loc";

    fn vault(email: &str, marker: &str) -> JsonObject {
        let vault = json!({
            "format": "bitwarden-local-vault",
            "version": 2,
            "revisionDate": "2026-10-11T12:00:00.000Z",
            "account": {},
            "sync": {"profile": {"email": email}, "marker": marker, "folders": [], "ciphers": []},
        });
        json::into_object(vault)
    }

    /// A vault of the earlier layout.
    fn single_file(marker: &str) -> Vec<u8> {
        let mut vault = vault("a@example.com", marker);
        vault.insert(KEY_VERSION.to_owned(), json!(1));
        json::to_pretty_bytes(&Value::Object(vault))
    }

    fn marker_of(vault: Option<JsonObject>) -> Option<String> {
        let vault = vault?;
        let sync = obj(&vault, KEY_SYNC)?;
        string(sync, "marker").map(str::to_owned)
    }

    fn device_file<'a>(device: &'a str, name: &'a str) -> [&'a str; 4] {
        [ID, DEVICES_DIRECTORY, device, name]
    }

    fn file_marker(fs: &MemoryFileSystem, path: &[&str]) -> Option<String> {
        let value = json::parse(&fs.get(path)?)?;
        marker_of(Some(json::into_object(value)))
    }

    /// The path of the content of an attachment of the account.
    fn attachment(cipher_id: &'static str, attachment_id: &'static str) -> [&'static str; 4] {
        [ID, ATTACHMENTS_DIRECTORY, cipher_id, attachment_id]
    }

    fn store_on<F: FileSystem>(fs: F) -> LocalVaultStore<F> {
        LocalVaultStore::new(fs, DEVICE)
    }

    /// Writes the vault of the account as a change of the vault that the store reads now, or as
    /// the vault of a new account if there is none.
    fn save<F: FileSystem>(store: &LocalVaultStore<F>, id: &str, vault: &JsonObject, now: i64) {
        let read = block_on(store.read_vault(id)).unwrap().unwrap_or_default();
        block_on(store.write_vault(id, &read, vault, now)).unwrap();
    }

    fn write<F: FileSystem>(store: &LocalVaultStore<F>, id: &str, marker: &str) {
        save(store, id, &vault("a@example.com", marker), NOW);
    }

    fn read<F: FileSystem>(store: &LocalVaultStore<F>, id: &str) -> Option<JsonObject> {
        let read = block_on(store.read_vault(id)).unwrap();
        read.map(|read| read.vault)
    }

    /// What the store reads of the vault of the account, which a change of it is written against.
    fn read_for_change<F: FileSystem>(store: &LocalVaultStore<F>, id: &str) -> ReadVault {
        block_on(store.read_vault(id)).unwrap().unwrap()
    }

    /// The IDs of the accounts that the store finds with the email.
    fn find_ids<F: FileSystem>(
        store: &LocalVaultStore<F>,
        email: &str,
    ) -> Result<Vec<String>, ReadError> {
        let found = block_on(store.find_accounts(email))?;
        Ok(found.into_iter().map(|(id, _)| id).collect())
    }

    /// Every file with its content, to tell that nothing was written.
    fn snapshot(fs: &MemoryFileSystem) -> Vec<(Vec<String>, Option<Vec<u8>>)> {
        let paths = fs.paths().into_iter();
        paths
            .map(|path| {
                let content = fs.get(&as_strs(&path));
                (path, content)
            })
            .collect()
    }

    /// A file system that cannot rename, as a folder that Android reaches through the Storage
    /// Access Framework.
    struct NoRename(MemoryFileSystem);

    impl FileSystem for NoRename {
        async fn list(&self, directory: &[&str]) -> Result<Vec<String>, IoError> {
            self.0.list(directory).await
        }

        async fn exists(&self, path: &[&str]) -> Result<bool, IoError> {
            self.0.exists(path).await
        }

        async fn read(&self, path: &[&str]) -> Result<Option<Vec<u8>>, IoError> {
            self.0.read(path).await
        }

        async fn write(&self, path: &[&str], content: &[u8]) -> Result<(), IoError> {
            self.0.write(path, content).await
        }

        async fn rename(&self, _path: &[&str], _new_name: &str) -> Result<bool, IoError> {
            Ok(false)
        }

        async fn delete(&self, path: &[&str]) -> Result<bool, IoError> {
            self.0.delete(path).await
        }
    }

    /// A file system that fails the writes and the deletions of the paths that it is given, as
    /// a file that another program holds open, and does the rest.
    struct Failing {
        fs: MemoryFileSystem,
        writes: Vec<Vec<&'static str>>,
        deletions: Vec<Vec<&'static str>>,
    }

    impl Failing {
        fn check(paths: &[Vec<&str>], path: &[&str]) -> Result<(), IoError> {
            if paths.iter().any(|failing| failing == path) {
                Err(IoError::new("busy"))
            } else {
                Ok(())
            }
        }
    }

    impl FileSystem for Failing {
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
            Self::check(&self.writes, path)?;
            self.fs.write(path, content).await
        }

        async fn rename(&self, path: &[&str], new_name: &str) -> Result<bool, IoError> {
            self.fs.rename(path, new_name).await
        }

        async fn delete(&self, path: &[&str]) -> Result<bool, IoError> {
            Self::check(&self.deletions, path)?;
            self.fs.delete(path).await
        }
    }

    #[test]
    fn a_vault_is_written_to_the_file_of_the_device_as_indented_utf8_and_read_back() {
        let fs = MemoryFileSystem::new();
        let store = store_on(fs.clone());
        let written = vault("ünïcödé@example.com", "current");

        save(&store, ID, &written, NOW);

        assert_eq!(read(&store, ID), Some(written));
        let file = device_file(DEVICE, VAULT_FILE);
        let content = String::from_utf8(fs.get(&file).unwrap()).unwrap();
        let start = "{\n    \"format\": \"bitwarden-local-vault\",\n";
        assert!(content.starts_with(start));
        assert!(content.contains("ünïcödé@example.com"));
        let root = json::parse(&fs.get(&[ID, VAULT_FILE]).unwrap()).unwrap();
        assert_eq!(root, marker());
        assert_eq!(fs.paths().len(), 2);
    }

    #[test]
    fn the_file_that_is_replaced_is_kept_as_the_backup() {
        let fs = MemoryFileSystem::new();
        let store = store_on(fs.clone());

        for marker in ["first", "second", "third"] {
            write(&store, ID, marker);
        }

        let current = file_marker(&fs, &device_file(DEVICE, VAULT_FILE));
        let backup = file_marker(&fs, &device_file(DEVICE, VAULT_BACKUP_FILE));
        assert_eq!(current.as_deref(), Some("third"));
        assert_eq!(backup.as_deref(), Some("second"));
        assert_eq!(fs.get(&device_file(DEVICE, VAULT_TEMP_FILE)), None);
    }

    #[test]
    fn the_since_that_an_earlier_client_wrote_in_the_file_of_a_device_is_left_out() {
        let fs = MemoryFileSystem::new();
        let store = store_on(fs.clone());
        let path = device_file(DEVICE, VAULT_FILE);
        let file = || json::parse(&fs.get(&path).unwrap()).unwrap();
        write(&store, ID, "first");
        assert_eq!(file().get("since"), None);

        // It is not part of the record of the account, so the vault does not have it, and the next
        // write leaves it out.
        let mut earlier = file();
        earlier["since"] = json!(NOW);
        fs.put(&path, earlier.to_string());
        assert_eq!(read(&store, ID).unwrap().get("since"), None);
        save(&store, ID, &vault("a@example.com", "second"), NOW + 1);
        assert_eq!(file().get("since"), None);
    }

    #[test]
    fn a_file_is_written_in_place_where_a_file_cannot_be_renamed() {
        let fs = MemoryFileSystem::new();
        let store = store_on(NoRename(fs.clone()));

        write(&store, ID, "first");
        write(&store, ID, "second");

        let current = file_marker(&fs, &device_file(DEVICE, VAULT_FILE));
        assert_eq!(current.as_deref(), Some("second"));
        assert_eq!(fs.get(&device_file(DEVICE, VAULT_TEMP_FILE)), None);
    }

    #[test]
    fn an_interrupted_write_leaves_the_file_of_the_device_in_the_temporary_file() {
        let written = MemoryFileSystem::new();
        let store = store_on(written.clone());
        write(&store, ID, "tmp");
        let complete = written.get(&device_file(DEVICE, VAULT_FILE)).unwrap();
        for vault_file in [None, Some(INCOMPLETE)] {
            let fs = MemoryFileSystem::new();
            if let Some(content) = vault_file {
                fs.put(&device_file(DEVICE, VAULT_FILE), content);
            }
            fs.put(&device_file(DEVICE, VAULT_TEMP_FILE), complete.clone());
            fs.put(&device_file(DEVICE, VAULT_BACKUP_FILE), "{}");
            let store = store_on(fs);

            assert_eq!(marker_of(read(&store, ID)).as_deref(), Some("tmp"));
        }
    }

    #[test]
    fn a_vault_of_the_earlier_that_no_device_took_over_is_not_used_or_written() {
        let fs = MemoryFileSystem::new();
        fs.put(&[ID, VAULT_FILE], single_file("earlier"));
        let store = store_on(fs.clone());
        let other_email = vault("other@example.com", "other");
        save(&store, "account-b", &other_email, NOW);
        let files = snapshot(&fs);
        let earlier = ReadError::Unusable(ID.to_owned(), Unusable::EarlierLayout);
        let find = |email: &str| find_ids(&store, email);

        // The account is not taken to be gone, nor its email to be free, as a client from before
        // this layout wrote it, but no device takes it over anymore.
        assert_eq!(block_on(store.read_vault(ID)), Err(earlier.clone()));
        assert_eq!(block_on(store.read_account(ID)), Err(earlier.clone()));
        assert_eq!(find("a@example.com"), Err(earlier));
        assert_eq!(find("other@example.com").unwrap(), ["account-b"]);
        let changed = vault("a@example.com", "changed");
        let new = ReadVault::default();
        assert!(block_on(store.write_vault(ID, &new, &changed, NOW)).is_err());
        block_on(store.tidy(ID, NOW)).unwrap();
        assert_eq!(snapshot(&fs), files);
    }

    #[test]
    fn a_vault_of_the_earlier_layout_that_is_left_as_the_backup_is_not_read() {
        let fs = MemoryFileSystem::new();
        let store = store_on(fs.clone());
        write(&store, ID, "current");
        // A device took the vault over without deleting it after, as one that was interrupted
        // did, or one from before it was deleted.
        fs.put(&[ID, VAULT_BACKUP_FILE], single_file("earlier"));

        // Not even in place of a `vault.json` that is missing, which leaves the account to the
        // files of its devices.
        block_on(fs.delete(&[ID, VAULT_FILE])).unwrap();

        assert_eq!(marker_of(read(&store, ID)).as_deref(), Some("current"));
    }

    #[test]
    fn the_vault_is_put_together_from_the_files_of_every_device() {
        let fs = MemoryFileSystem::new();
        let store = store_on(fs.clone());
        let other = LocalVaultStore::new(fs.clone(), OTHER_DEVICE);
        write(&store, ID, "first");
        let mut changed = vault("a@example.com", "first");
        let folder = json!([{"id": "folder", "name": "2.folder"}]);
        changed.get_mut(KEY_SYNC).unwrap()["folders"] = folder.clone();

        save(&other, ID, &changed, NOW + 1);

        let vault = read(&store, ID).unwrap();
        assert_eq!(vault[KEY_SYNC]["folders"], folder);
        // The other device only wrote the folder, which is all that it changed.
        let other_file = json::parse(&fs.get(&device_file(OTHER_DEVICE, VAULT_FILE)).unwrap());
        let other_file = other_file.unwrap();
        let stamp = json!({"at": NOW + 1, "by": "device-b"});
        assert_eq!(other_file["records"], json!({"folder:folder": stamp}));
        assert_eq!(other_file[KEY_SYNC].get("profile"), None);
    }

    #[test]
    fn an_account_whose_record_is_on_its_way_is_not_taken_to_be_gone() {
        let fs = MemoryFileSystem::new();
        let store = store_on(fs.clone());
        let other = LocalVaultStore::new(fs.clone(), OTHER_DEVICE);
        write(&store, ID, "first");
        let mut changed = vault("a@example.com", "first");
        changed.get_mut(KEY_SYNC).unwrap()["folders"] = json!([{"id": "folder"}]);
        save(&other, ID, &changed, NOW + 1);
        // The file of the device that holds the record of the account has not come.
        block_on(fs.delete(&[ID, DEVICES_DIRECTORY, DEVICE])).unwrap();

        // The error names the account, which names its directory in the vault folder.
        let on_its_way = ReadError::Unusable(ID.to_owned(), Unusable::OnItsWay);
        let other_email = vault("other@example.com", "other");
        save(&store, "account-b", &other_email, NOW);
        let find = |email: &str| find_ids(&store, email);

        assert_eq!(block_on(store.read_vault(ID)), Err(on_its_way.clone()));
        assert_eq!(block_on(store.read_account(ID)), Err(on_its_way.clone()));
        // The email may be that of the account whose vault is on its way, but not one that
        // another account has.
        assert_eq!(find("a@example.com"), Err(on_its_way.clone()));
        assert_eq!(find("other@example.com").unwrap(), ["account-b"]);
        // The files of the devices can come before the `vault.json` that says that the account
        // has this layout as well.
        block_on(fs.delete(&[ID, VAULT_FILE])).unwrap();
        assert_eq!(block_on(store.read_vault(ID)), Err(on_its_way.clone()));
        assert_eq!(find("a@example.com"), Err(on_its_way));
        // Unless the `vault.json` says that the account was deleted: they are what is left of it.
        fs.put(&[ID, VAULT_FILE], deleted_marker().to_string());
        assert_eq!(read(&store, ID), None);
        assert!(find("a@example.com").unwrap().is_empty());
    }

    #[test]
    fn an_account_that_was_deleted_is_not_there_whatever_is_left_of_it() {
        let fs = MemoryFileSystem::new();
        let store = store_on(fs.clone());
        let other = LocalVaultStore::new(fs.clone(), OTHER_DEVICE);
        write(&store, ID, "first");
        let mut changed = vault("a@example.com", "first");
        changed.get_mut(KEY_SYNC).unwrap()["folders"] = json!([{"id": "folder"}]);
        save(&other, ID, &changed, NOW + 1);
        let read_by_other = read_for_change(&other, ID);
        fs.put(&attachment("cipher", "attachment"), "content");
        // What a tool that syncs the folder keeps of a `vault.json` that it had two versions of,
        // which holds a whole vault of the earlier layout.
        let conflict = "vault.sync-conflict-20261016-143107-ABCDEFG.json";
        fs.put(&[ID, conflict], single_file("conflict"));
        let file_of = |device| fs.get(&device_file(device, VAULT_FILE)).unwrap();
        let files = [
            (DEVICE, file_of(DEVICE)),
            (OTHER_DEVICE, file_of(OTHER_DEVICE)),
        ];

        assert!(block_on(store.delete_account(ID)).unwrap());

        // Only that it was deleted is left.
        assert_eq!(fs.paths(), [[ID, VAULT_FILE]]);
        assert_eq!(fs.directories(), [[ID]]);
        let root = json::parse(&fs.get(&[ID, VAULT_FILE]).unwrap()).unwrap();
        assert_eq!(root, deleted_marker());
        // Devices that the deletion had not come to write their files again, the one with the
        // record of the account as well. What is left is not an account, nor one on its way.
        for (device, content) in files {
            fs.put(&device_file(device, VAULT_FILE), content);
        }
        assert_eq!(read(&store, ID), None);
        assert!(find_ids(&store, "a@example.com").unwrap().is_empty());
        let left = snapshot(&fs);
        let written = block_on(other.write_vault(ID, &read_by_other, &changed, NOW + 2));
        assert!(written.is_err());
        block_on(other.tidy(ID, NOW + 2)).unwrap();
        assert_eq!(snapshot(&fs), left);

        // Nor is a vault of the earlier layout kept as the backup.
        let fs = MemoryFileSystem::new();
        fs.put(&[ID, VAULT_FILE], single_file("earlier"));
        assert!(block_on(store_on(fs.clone()).delete_account(ID)).unwrap());
        assert_eq!(fs.paths(), [[ID, VAULT_FILE]]);
    }

    #[test]
    fn what_cannot_be_deleted_with_an_account_is_left_behind_and_reported() {
        let fs = MemoryFileSystem::new();
        let store = store_on(fs.clone());
        write(&store, ID, "first");
        // A name that the file system is not handed, and a directory that it cannot delete.
        let copy = [ID, "vault (conflicted copy).json"];
        fs.put(&copy, single_file("conflict"));
        let deletions = vec![vec![ID, DEVICES_DIRECTORY]];
        let failing = Failing {
            fs: fs.clone(),
            writes: Vec::new(),
            deletions,
        };

        assert!(!block_on(store_on(failing).delete_account(ID)).unwrap());

        // The account is deleted all the same.
        assert_eq!(read(&store, ID), None);
        assert!(fs.get(&copy).is_some());
        assert!(fs.get(&device_file(DEVICE, VAULT_FILE)).is_some());
    }

    #[test]
    fn an_account_of_a_layout_that_is_not_known_is_not_taken_to_be_gone() {
        let fs = MemoryFileSystem::new();
        let store = store_on(fs.clone());
        write(&store, ID, "first");
        let other_email = vault("other@example.com", "other");
        save(&store, "account-b", &other_email, NOW);
        // A newer client wrote the file of another device.
        let newer = json!({"format": "bitwarden-local-vault", "version": 3});
        fs.put(&device_file(OTHER_DEVICE, VAULT_FILE), newer.to_string());
        let unknown_layout = ReadError::Unusable(ID.to_owned(), Unusable::UnknownLayout);
        let find = |email: &str| find_ids(&store, email);

        assert_eq!(block_on(store.read_vault(ID)), Err(unknown_layout.clone()));
        // The email may be that of the account, but not one that another account has.
        assert_eq!(find("a@example.com"), Err(unknown_layout.clone()));
        assert_eq!(find("nobody@example.com"), Err(unknown_layout));
        assert_eq!(find("other@example.com").unwrap(), ["account-b"]);
    }

    #[test]
    fn a_vault_json_that_cannot_be_written_does_not_fail_the_change() {
        let root_writes = vec![vec![ID, VAULT_TEMP_FILE], vec![ID, VAULT_FILE]];
        let failing_on = |fs: &MemoryFileSystem| {
            let writes = root_writes.clone();
            let failing = Failing {
                fs: fs.clone(),
                writes,
                deletions: Vec::new(),
            };
            store_on(failing)
        };

        // The device that registers the account.
        let fs = MemoryFileSystem::new();
        let failing = failing_on(&fs);
        write(&failing, ID, "first");
        assert_eq!(fs.get(&[ID, VAULT_FILE]), None);
        assert_eq!(marker_of(read(&failing, ID)).as_deref(), Some("first"));
        // The next write writes it.
        let store = store_on(fs.clone());
        write(&store, ID, "second");
        let root = json::parse(&fs.get(&[ID, VAULT_FILE]).unwrap()).unwrap();
        assert_eq!(root, marker());
    }

    #[test]
    fn only_the_device_that_an_account_first_has_a_file_of_writes_its_vault_json() {
        let fs = MemoryFileSystem::new();
        let store = store_on(fs.clone());
        let other = LocalVaultStore::new(fs.clone(), OTHER_DEVICE);
        write(&store, ID, "first");
        // The other device has the file of the first one, but not the `vault.json` of the account.
        block_on(fs.delete(&[ID, VAULT_FILE])).unwrap();
        let mut changed = vault("a@example.com", "first");
        changed.get_mut(KEY_SYNC).unwrap()["folders"] = json!([{"id": "folder"}]);
        save(&other, ID, &changed, NOW + 1);

        assert_eq!(fs.get(&[ID, VAULT_FILE]), None);

        // The only device with a file of the account writes it, as the device that registered
        // the account does if it was interrupted before it wrote it.
        let fs = MemoryFileSystem::new();
        let store = store_on(fs.clone());
        write(&store, ID, "first");
        block_on(fs.delete(&[ID, VAULT_FILE])).unwrap();
        write(&store, ID, "second");
        let root = json::parse(&fs.get(&[ID, VAULT_FILE]).unwrap()).unwrap();
        assert_eq!(root, marker());
    }

    #[test]
    fn a_complete_file_that_is_not_a_known_vault_keeps_the_vault_from_being_used() {
        let unknown_layout = Err(ReadError::Unusable(ID.to_owned(), Unusable::UnknownLayout));
        let cases = [
            json!({"format": "something-else", "version": 2}),
            json!({"format": "bitwarden-local-vault", "version": 3}),
            json!({"format": "bitwarden-local-vault"}),
            json!({"format": "bitwarden-local-vault", "version": "2"}),
            json!({"format": "bitwarden-local-vault-deleted"}),
            json!([1, 2]),
        ];
        for content in cases {
            for path in [
                device_file(DEVICE, VAULT_FILE),
                device_file(OTHER_DEVICE, VAULT_FILE),
            ] {
                let fs = MemoryFileSystem::new();
                let store = store_on(fs.clone());
                write(&store, ID, "current");
                let current = read_for_change(&store, ID);
                fs.put(&path, content.to_string());
                let files = snapshot(&fs);

                // Whatever a device wrote, the account is there: a newer client wrote it.
                let assembled = block_on(store.read_vault(ID));
                assert_eq!(assembled, unknown_layout.clone(), "{content}");
                let changed = vault("a@example.com", "x");
                let written = block_on(store.write_vault(ID, &current, &changed, NOW));
                assert!(written.is_err());
                block_on(store.tidy(ID, NOW)).unwrap();
                assert_eq!(snapshot(&fs), files);
            }
            let fs = MemoryFileSystem::new();
            fs.put(&[ID, VAULT_FILE], content.to_string());
            fs.put(&[ID, VAULT_BACKUP_FILE], single_file("bak"));

            // The backup is not read in its place. A `vault.json` of a local vault of a version
            // that is not known is an account that a newer client wrote, and any other one is
            // not an account.
            let is_local_vault = content["format"] == LOCAL_VAULT_FORMAT;
            let expected = if is_local_vault {
                unknown_layout.clone()
            } else {
                Ok(None)
            };
            let assembled = block_on(store_on(fs).read_vault(ID));
            assert_eq!(assembled, expected, "{content}");
        }
    }

    #[test]
    fn a_file_with_a_byte_order_mark_is_read() {
        let fs = MemoryFileSystem::new();
        let store = store_on(fs.clone());
        write(&store, ID, "bak");
        write(&store, ID, "current");
        let path = device_file(DEVICE, VAULT_FILE);
        let mut content = b"\xef\xbb\xbf".to_vec();
        content.extend(fs.get(&path).unwrap());
        fs.put(&path, content);

        // Not the backup, which a file that is taken to be incomplete leaves the device to.
        assert_eq!(marker_of(read(&store, ID)).as_deref(), Some("current"));
    }

    #[test]
    fn accounts_are_found_by_their_email_the_lowest_id_first() {
        let fs = MemoryFileSystem::new();
        let store = store_on(fs.clone());
        let accounts = [
            ("account-b", "same@example.com"),
            ("account-a", " Same@Example.COM "),
            ("account-c", "other@example.com"),
        ];
        for (id, email) in accounts {
            save(&store, id, &vault(email, id), NOW);
        }
        fs.put(&["account-d", VAULT_FILE], "not a vault");
        fs.put(&["not safe", VAULT_FILE], single_file("hidden"));

        let found = find_ids(&store, "SAME@example.com").unwrap();
        let nobody = find_ids(&store, "nobody@example.com").unwrap();

        assert_eq!(found, ["account-a", "account-b"]);
        assert!(nobody.is_empty());
    }

    #[test]
    fn names_that_lead_out_of_the_vault_folder_are_never_used() {
        let long = "x".repeat(129);
        for name in ["", "..", "a/b", "a.b", "a b", long.as_str()] {
            let fs = MemoryFileSystem::new();
            let store = store_on(fs.clone());
            let written = vault("a@example.com", "x");
            let new = ReadVault::default();

            assert!(block_on(store.write_vault(name, &new, &written, NOW)).is_err());
            assert_eq!(read(&store, name), None);
            assert_eq!(block_on(store.read_account(name)), Ok(None));
            assert!(block_on(store.delete_account(name)).is_err());
            assert_eq!(store.attachment_path(ID, name, "attachment"), None);
            assert_eq!(store.attachment_path(ID, "cipher", name), None);
            assert!(block_on(store.delete_attachment(ID, name, "attachment")).unwrap());
            assert!(block_on(store.delete_attachment(name, "cipher", "attachment")).unwrap());
            assert!(fs.paths().is_empty());
        }
    }

    #[test]
    fn the_accounts_that_a_folder_does_not_have_are_found_to_be_copied() {
        let source = MemoryFileSystem::new();
        let target = MemoryFileSystem::new();
        for id in ["account-b", "account-a", "account-c"] {
            source.put(&[id, VAULT_FILE], single_file(id));
        }
        source.put(&["notes.txt"], single_file("not an account"));
        source.put(&["not safe", VAULT_FILE], single_file("hidden"));
        target.put(&["account-c", VAULT_FILE], single_file("another device"));

        let missing = block_on(accounts_missing_in(&source, &target)).unwrap();

        assert_eq!(missing, ["account-a", "account-b"]);
        assert_eq!(target.paths().len(), 1);
    }

    #[test]
    fn the_account_is_read_without_its_folders_and_items() {
        let store = store_on(MemoryFileSystem::new());
        let mut written = vault("a@example.com", "current");
        let sync = written.get_mut(KEY_SYNC).unwrap();
        sync["folders"] = json!([{"id": "folder"}]);
        sync["ciphers"] = json!([{"id": "item"}]);
        save(&store, ID, &written, NOW);

        let account = block_on(store.read_account(ID)).unwrap();

        let mut without_items = written.clone();
        let sync = without_items.get_mut(KEY_SYNC).unwrap();
        sync["folders"] = json!([]);
        sync["ciphers"] = json!([]);
        assert_eq!(account, Some(without_items));
        assert_eq!(read(&store, ID), Some(written));
        assert_eq!(block_on(store.read_account("account-b")), Ok(None));
    }

    #[test]
    fn the_files_of_the_device_are_found_to_be_copied_to_a_folder_that_has_the_account() {
        let source = MemoryFileSystem::new();
        let target = MemoryFileSystem::new();
        // The target has the account from before the device last changed it in the source, and
        // the file of another device in a newer version than the source has it.
        for fs in [&source, &target] {
            fs.put(&device_file(DEVICE, VAULT_BACKUP_FILE), "older");
            fs.put(&device_file(OTHER_DEVICE, VAULT_FILE), "other");
            fs.put(&attachment("cipher-a", "attachment-1"), "content");
        }
        target.put(&device_file(DEVICE, VAULT_FILE), "earlier");
        target.put(&device_file(OTHER_DEVICE, VAULT_FILE), "newer");
        source.put(&device_file(DEVICE, VAULT_FILE), "latest");
        source.put(&attachment("cipher-b", "attachment-3"), "content");
        source.put(&attachment("cipher-a", "attachment-2"), "content");
        // Not the content of an attachment, as its name could not be the ID of one.
        source.put(&attachment("cipher-a", "not.safe"), "content");
        // An account that the target does not have is copied with everything in it.
        source.put(&["account-b", DEVICES_DIRECTORY, DEVICE, VAULT_FILE], "new");

        let missing = block_on(device_files_missing_in(&source, &target, DEVICE)).unwrap();
        let invalid = block_on(device_files_missing_in(&source, &target, "a/b"));
        let same = block_on(device_files_missing_in(&source, &source, DEVICE));

        // The content of attachments first, and the file of the device last.
        let expected = [
            attachment("cipher-a", "attachment-2").to_vec(),
            attachment("cipher-b", "attachment-3").to_vec(),
            device_file(DEVICE, VAULT_FILE).to_vec(),
        ];
        assert_eq!(missing, expected);
        // Nothing for a device whose ID could not be the name of a directory, nor for a folder
        // that has every file already.
        assert_eq!(invalid, Ok(Vec::new()));
        assert_eq!(same, Ok(Vec::new()));
    }
}
