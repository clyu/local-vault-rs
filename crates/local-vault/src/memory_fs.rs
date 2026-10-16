use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex, MutexGuard};

use crate::fs::{FileSystem, IoError};

type Files = BTreeMap<Vec<String>, Vec<u8>>;

/// A [`FileSystem`] that keeps its files in memory, for tests. Directories are made on the way to
/// a file that is written, and stay until they are deleted, also once they are empty, as on a
/// disk.
///
/// Clones share their files, so that a test can look at what the local server wrote.
#[derive(Debug, Clone, Default)]
pub struct MemoryFileSystem {
    entries: Arc<Mutex<Entries>>,
}

#[derive(Debug, Default)]
struct Entries {
    files: Files,
    directories: BTreeSet<Vec<String>>,
}

impl Entries {
    /// Puts a file at the path, replacing any that is there, with the directories on its way.
    fn put(&mut self, path: Vec<String>, content: Vec<u8>) {
        for length in 1..path.len() {
            if let Some(directory) = path.get(..length) {
                self.directories.insert(directory.to_vec());
            }
        }
        self.files.insert(path, content);
    }
}

impl MemoryFileSystem {
    /// An empty file system.
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns the content of the file at the path, if there is one.
    pub fn get(&self, path: &[&str]) -> Option<Vec<u8>> {
        self.entries().files.get(&owned(path)).cloned()
    }

    /// Puts a file at the path, replacing any that is there, with the directories on its way.
    pub fn put(&self, path: &[&str], content: impl Into<Vec<u8>>) {
        self.entries().put(owned(path), content.into());
    }

    /// Returns the paths of all files, sorted.
    pub fn paths(&self) -> Vec<Vec<String>> {
        self.entries().files.keys().cloned().collect()
    }

    /// Returns the paths of all directories, the empty ones among them, sorted.
    pub fn directories(&self) -> Vec<Vec<String>> {
        self.entries().directories.iter().cloned().collect()
    }

    fn entries(&self) -> MutexGuard<'_, Entries> {
        // A test that failed while it held the lock leaves files that are as good as any.
        self.entries
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

fn owned(path: &[&str]) -> Vec<String> {
    path.iter().map(|name| (*name).to_owned()).collect()
}

fn is_inside(path: &[String], directory: &[&str]) -> bool {
    path.len() > directory.len() && path.iter().zip(directory).all(|(a, b)| a == b)
}

impl FileSystem for MemoryFileSystem {
    async fn list(&self, directory: &[&str]) -> Result<Vec<String>, IoError> {
        let entries = self.entries();
        let paths = entries.files.keys().chain(&entries.directories);
        let inside = paths.filter(|path| is_inside(path, directory));
        let names = inside.filter_map(|path| path.get(directory.len()));
        let names: BTreeSet<&String> = names.collect();
        Ok(names.into_iter().cloned().collect())
    }

    async fn exists(&self, path: &[&str]) -> Result<bool, IoError> {
        let entries = self.entries();
        let path = owned(path);
        // The vault folder itself is always there.
        let is_directory = path.is_empty() || entries.directories.contains(&path);
        Ok(is_directory || entries.files.contains_key(&path))
    }

    async fn read(&self, path: &[&str]) -> Result<Option<Vec<u8>>, IoError> {
        Ok(self.get(path))
    }

    async fn write(&self, path: &[&str], content: &[u8]) -> Result<(), IoError> {
        if path.is_empty() {
            return Err(IoError::new("A file name is required"));
        }
        self.put(path, content);
        Ok(())
    }

    async fn rename(&self, path: &[&str], new_name: &str) -> Result<bool, IoError> {
        let mut entries = self.entries();
        let Some(content) = entries.files.remove(&owned(path)) else {
            return Ok(false);
        };
        let mut new_path = owned(path);
        new_path.pop();
        new_path.push(new_name.to_owned());
        entries.put(new_path, content);
        Ok(true)
    }

    async fn delete(&self, path: &[&str]) -> Result<bool, IoError> {
        let target = owned(path);
        let mut entries = self.entries();
        let is_deleted = |p: &Vec<String>| *p == target || is_inside(p, path);
        entries.files.retain(|p, _| !is_deleted(p));
        entries.directories.retain(|p| !is_deleted(p));
        Ok(true)
    }
}
