use serde_json::Value;

use crate::fs::{FileSystem, IoError};
use crate::json::{self, JsonObject, int, is_safe_segment, normalize_email, obj, string};

/// The value of the `format` field that identifies a local vault file.
pub const LOCAL_VAULT_FORMAT: &str = "bitwarden-local-vault";

/// The version of the local vault file layout that is written.
pub const LOCAL_VAULT_VERSION: i64 = 1;

pub(crate) const KEY_FORMAT: &str = "format";
pub(crate) const KEY_VERSION: &str = "version";
pub(crate) const KEY_REVISION_DATE: &str = "revisionDate";
pub(crate) const KEY_ACCOUNT: &str = "account";
pub(crate) const KEY_SYNC: &str = "sync";

const VAULT_FILE: &str = "vault.json";
const VAULT_TEMP_FILE: &str = "vault.json.tmp";
const VAULT_BACKUP_FILE: &str = "vault.json.bak";
const ATTACHMENTS_DIRECTORY: &str = "attachments";

/// The files that can hold a complete vault, in the order they are trusted. Only an interrupted
/// write leaves the vault in anything but the first.
const VAULT_READ_ORDER: [&str; 3] = [VAULT_FILE, VAULT_TEMP_FILE, VAULT_BACKUP_FILE];

/// Reads and writes the vault of each account on top of a [`FileSystem`].
///
/// Every account has a directory named after its ID that holds a single `vault.json` and the
/// encrypted attachments of its items:
///
/// ```text
/// <account id>/vault.json
/// <account id>/attachments/<cipher id>/<attachment id>
/// ```
pub(crate) struct LocalVaultStore<F> {
    file_system: F,
}

impl<F: FileSystem> LocalVaultStore<F> {
    pub(crate) fn new(file_system: F) -> Self {
        Self { file_system }
    }

    pub(crate) fn file_system(&self) -> &F {
        &self.file_system
    }

    /// Returns the ID of the account with the email, or `None` if there is none. Of several
    /// accounts with the email, it is the first of [`Self::find_account_ids`].
    pub(crate) async fn find_account_id(&self, email: &str) -> Result<Option<String>, IoError> {
        Ok(self.find_account_ids(email).await?.into_iter().next())
    }

    /// Returns the ID of every account with the email. Nothing keeps a vault folder from holding
    /// more than one, as when an account is registered again on a device that the first one has
    /// not arrived on yet.
    ///
    /// The IDs are sorted, as the order that a directory is listed in is not the same
    /// everywhere: every client that shares the folder has to take the same account to be the
    /// first. They are made of ASCII only, so their order is the same as that of their UTF-16
    /// code units, which the clients that came before sorted them by.
    pub(crate) async fn find_account_ids(&self, email: &str) -> Result<Vec<String>, IoError> {
        let normalized_email = normalize_email(email);
        let mut account_ids: Vec<String> = self
            .file_system
            .list(&[])
            .await?
            .into_iter()
            .filter(|name| is_safe_segment(name))
            .collect();
        account_ids.sort();
        let mut found = Vec::new();
        for account_id in account_ids {
            let Some(vault) = self.read_vault(&account_id).await? else {
                continue;
            };
            let account_email = obj(&vault, KEY_SYNC)
                .and_then(|sync| obj(sync, "profile"))
                .and_then(|profile| string(profile, "email"))
                .map(normalize_email);
            if account_email.as_ref() == Some(&normalized_email) {
                found.push(account_id);
            }
        }
        Ok(found)
    }

    /// Returns the vault of the account, or `None` if there is none that can be used.
    ///
    /// The vault is the first of its files that is complete. The files after it are only there
    /// for a write that was interrupted, so they are not read in its place when it is a vault
    /// that cannot be used: they hold an older vault, and writing that one back would replace
    /// the vault that is there.
    pub(crate) async fn read_vault(&self, account_id: &str) -> Result<Option<JsonObject>, IoError> {
        if !is_safe_segment(account_id) {
            return Ok(None);
        }
        let mut complete = None;
        for file in VAULT_READ_ORDER {
            let bytes = self.file_system.read(&[account_id, file]).await?;
            // An interrupted write leaves a file that is not complete.
            complete = bytes.as_deref().and_then(json::parse);
            if complete.is_some() {
                break;
            }
        }
        let Some(Value::Object(vault)) = complete else {
            return Ok(None);
        };
        // A newer layout is left alone rather than rewritten in this one.
        let is_known = string(&vault, KEY_FORMAT) == Some(LOCAL_VAULT_FORMAT)
            && int(&vault, KEY_VERSION) == Some(LOCAL_VAULT_VERSION);
        Ok(is_known.then_some(vault))
    }

    /// Replaces the vault of the account. The vault that it replaces is kept as the backup, and
    /// an interrupted write never leaves the account without a complete vault.
    pub(crate) async fn write_vault(
        &self,
        account_id: &str,
        vault: &JsonObject,
    ) -> Result<(), IoError> {
        if !is_safe_segment(account_id) {
            return Err(IoError::new("Invalid account ID"));
        }
        let content = json::to_pretty_bytes(&Value::Object(vault.clone()));
        let vault_path = [account_id, VAULT_FILE];
        let temp_path = [account_id, VAULT_TEMP_FILE];
        let fs = &self.file_system;
        fs.write(&temp_path, &content).await?;
        if fs.exists(&vault_path).await? {
            fs.delete(&[account_id, VAULT_BACKUP_FILE]).await?;
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

    /// Deletes the vault and the attachments of the account. Returns `true` if nothing remains
    /// of it.
    pub(crate) async fn delete_account(&self, account_id: &str) -> Result<bool, IoError> {
        if !is_safe_segment(account_id) {
            return Ok(false);
        }
        self.file_system.delete(&[account_id]).await
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
            .then(|| path.iter().map(|name| (*name).to_owned()).collect())
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
    pub(crate) async fn delete_attachment(
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

    /// Deletes the encrypted content of every attachment of an item. Returns `true` if nothing
    /// remains of it, which is also the case for names that nothing is ever stored under.
    pub(crate) async fn delete_attachments(
        &self,
        account_id: &str,
        cipher_id: &str,
    ) -> Result<bool, IoError> {
        if !is_safe_segment(account_id) || !is_safe_segment(cipher_id) {
            return Ok(true);
        }
        let path = [account_id, ATTACHMENTS_DIRECTORY, cipher_id];
        self.file_system.delete(&path).await
    }

    /// Deletes the encrypted content of every attachment of the account. Returns `true` if
    /// nothing remains of it.
    pub(crate) async fn delete_all_attachments(&self, account_id: &str) -> Result<bool, IoError> {
        if !is_safe_segment(account_id) {
            return Ok(true);
        }
        self.file_system
            .delete(&[account_id, ATTACHMENTS_DIRECTORY])
            .await
    }
}

fn as_strs(path: &[String]) -> Vec<&str> {
    path.iter().map(String::as_str).collect()
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::memory_fs::MemoryFileSystem;
    use futures::executor::block_on;
    use serde_json::json;

    const ID: &str = "11111111-2222-4333-8444-555555555555";
    const INCOMPLETE: &[u8] = b"{\"format\": \"bitwarden-loc";

    fn vault(email: &str, marker: &str) -> JsonObject {
        let vault = json!({
            "format": "bitwarden-local-vault",
            "version": 1,
            "revisionDate": "2026-10-11T12:00:00.000Z",
            "account": {},
            "sync": {"profile": {"email": email}, "marker": marker},
        });
        json::into_object(vault)
    }

    fn bytes(marker: &str) -> Vec<u8> {
        json::to_pretty_bytes(&Value::Object(vault("a@example.com", marker)))
    }

    fn marker(vault: Option<JsonObject>) -> Option<String> {
        let vault = vault?;
        let sync = obj(&vault, KEY_SYNC)?;
        string(sync, "marker").map(str::to_owned)
    }

    fn file_marker(fs: &MemoryFileSystem, name: &str) -> Option<String> {
        let value = json::parse(&fs.get(&[ID, name])?)?;
        marker(Some(json::into_object(value)))
    }

    fn write<F: FileSystem>(store: &LocalVaultStore<F>, id: &str, marker: &str) {
        block_on(store.write_vault(id, &vault("a@example.com", marker))).unwrap();
    }

    fn read<F: FileSystem>(store: &LocalVaultStore<F>, id: &str) -> Option<JsonObject> {
        block_on(store.read_vault(id)).unwrap()
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

    #[test]
    fn a_vault_is_written_as_indented_utf8_and_read_back() {
        let fs = MemoryFileSystem::new();
        let store = LocalVaultStore::new(fs.clone());
        let written = vault("ünïcödé@example.com", "current");

        block_on(store.write_vault(ID, &written)).unwrap();

        assert_eq!(read(&store, ID), Some(written));
        let content = String::from_utf8(fs.get(&[ID, VAULT_FILE]).unwrap()).unwrap();
        let start = "{\n    \"format\": \"bitwarden-local-vault\",\n";
        assert!(content.starts_with(start));
        assert!(content.contains("ünïcödé@example.com"));
    }

    #[test]
    fn the_vault_that_is_replaced_is_kept_as_the_backup() {
        let fs = MemoryFileSystem::new();
        let store = LocalVaultStore::new(fs.clone());

        for marker in ["first", "second", "third"] {
            write(&store, ID, marker);
        }

        let backup = file_marker(&fs, VAULT_BACKUP_FILE);
        assert_eq!(file_marker(&fs, VAULT_FILE).as_deref(), Some("third"));
        assert_eq!(backup.as_deref(), Some("second"));
        assert_eq!(fs.get(&[ID, VAULT_TEMP_FILE]), None);
    }

    #[test]
    fn a_vault_is_written_in_place_where_a_file_cannot_be_renamed() {
        let fs = MemoryFileSystem::new();
        let store = LocalVaultStore::new(NoRename(fs.clone()));

        write(&store, ID, "first");
        write(&store, ID, "second");

        assert_eq!(file_marker(&fs, VAULT_FILE).as_deref(), Some("second"));
        assert_eq!(fs.get(&[ID, VAULT_TEMP_FILE]), None);
    }

    #[test]
    fn an_interrupted_write_leaves_the_vault_in_the_temporary_file() {
        for vault_file in [None, Some(INCOMPLETE)] {
            let fs = MemoryFileSystem::new();
            if let Some(content) = vault_file {
                fs.put(&[ID, VAULT_FILE], content);
            }
            fs.put(&[ID, VAULT_TEMP_FILE], bytes("tmp"));
            fs.put(&[ID, VAULT_BACKUP_FILE], bytes("bak"));
            let store = LocalVaultStore::new(fs);

            assert_eq!(marker(read(&store, ID)).as_deref(), Some("tmp"));
        }
    }

    #[test]
    fn the_backup_is_read_when_neither_of_the_other_files_is_complete() {
        let fs = MemoryFileSystem::new();
        fs.put(&[ID, VAULT_FILE], "");
        fs.put(&[ID, VAULT_TEMP_FILE], "{");
        fs.put(&[ID, VAULT_BACKUP_FILE], bytes("bak"));
        let store = LocalVaultStore::new(fs);

        assert_eq!(marker(read(&store, ID)).as_deref(), Some("bak"));
    }

    #[test]
    fn a_complete_file_that_is_not_a_known_vault_is_not_replaced_by_an_older_one() {
        let cases = [
            json!({"format": "something-else", "version": 1}),
            json!({"format": "bitwarden-local-vault", "version": 2}),
            json!({"format": "bitwarden-local-vault"}),
            json!({"format": "bitwarden-local-vault", "version": "1"}),
            json!([1, 2]),
        ];
        for content in cases {
            let fs = MemoryFileSystem::new();
            fs.put(&[ID, VAULT_FILE], content.to_string());
            fs.put(&[ID, VAULT_BACKUP_FILE], bytes("bak"));
            let store = LocalVaultStore::new(fs);

            assert_eq!(read(&store, ID), None, "{content}");
        }
    }

    #[test]
    fn a_vault_with_a_byte_order_mark_is_read() {
        let fs = MemoryFileSystem::new();
        let mut content = b"\xef\xbb\xbf".to_vec();
        content.extend(bytes("current"));
        fs.put(&[ID, VAULT_FILE], content);
        fs.put(&[ID, VAULT_BACKUP_FILE], bytes("bak"));
        let store = LocalVaultStore::new(fs);

        assert_eq!(marker(read(&store, ID)).as_deref(), Some("current"));
    }

    #[test]
    fn accounts_are_found_by_their_email_the_lowest_id_first() {
        let fs = MemoryFileSystem::new();
        let store = LocalVaultStore::new(fs.clone());
        let accounts = [
            ("account-b", "same@example.com"),
            ("account-a", " Same@Example.COM "),
            ("account-c", "other@example.com"),
        ];
        for (id, email) in accounts {
            block_on(store.write_vault(id, &vault(email, id))).unwrap();
        }
        fs.put(&["account-d", VAULT_FILE], "not a vault");
        fs.put(&["not safe", VAULT_FILE], bytes("hidden"));

        let found = block_on(store.find_account_ids("SAME@example.com")).unwrap();
        let first = block_on(store.find_account_id("same@example.com")).unwrap();
        let nobody = block_on(store.find_account_ids("nobody@example.com")).unwrap();

        assert_eq!(found, ["account-a", "account-b"]);
        assert_eq!(first.as_deref(), Some("account-a"));
        assert!(nobody.is_empty());
    }

    #[test]
    fn names_that_lead_out_of_the_vault_folder_are_never_used() {
        let long = "x".repeat(129);
        for name in ["", "..", "a/b", "a.b", "a b", long.as_str()] {
            let fs = MemoryFileSystem::new();
            let store = LocalVaultStore::new(fs.clone());
            let written = vault("a@example.com", "x");

            assert!(block_on(store.write_vault(name, &written)).is_err());
            assert_eq!(read(&store, name), None);
            assert!(!block_on(store.delete_account(name)).unwrap());
            assert_eq!(store.attachment_path(ID, name, "attachment"), None);
            assert_eq!(store.attachment_path(ID, "cipher", name), None);
            assert!(block_on(store.delete_attachments(ID, name)).unwrap());
            assert!(block_on(store.delete_all_attachments(name)).unwrap());
            assert!(fs.paths().is_empty());
        }
    }
}
