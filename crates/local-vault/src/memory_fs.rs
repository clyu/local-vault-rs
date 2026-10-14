use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, MutexGuard};

use crate::fs::{FileSystem, IoError};

type Files = BTreeMap<Vec<String>, Vec<u8>>;

/// A [`FileSystem`] that keeps its files in memory, for tests. A directory exists as long as a
/// file is in it.
///
/// Clones share their files, so that a test can look at what the local server wrote.
#[derive(Debug, Clone, Default)]
pub struct MemoryFileSystem {
    files: Arc<Mutex<Files>>,
}

impl MemoryFileSystem {
    /// An empty file system.
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns the content of the file at the path, if there is one.
    pub fn get(&self, path: &[&str]) -> Option<Vec<u8>> {
        self.files().get(&owned(path)).cloned()
    }

    /// Puts a file at the path, replacing any that is there.
    pub fn put(&self, path: &[&str], content: impl Into<Vec<u8>>) {
        self.files().insert(owned(path), content.into());
    }

    /// Returns the paths of all files, sorted.
    pub fn paths(&self) -> Vec<Vec<String>> {
        self.files().keys().cloned().collect()
    }

    fn files(&self) -> MutexGuard<'_, Files> {
        // A test that failed while it held the lock leaves files that are as good as any.
        self.files
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
        let mut names: Vec<String> = Vec::new();
        for path in self.files().keys() {
            if let Some(name) = path.get(directory.len())
                && is_inside(path, directory)
                && !names.contains(name)
            {
                names.push(name.clone());
            }
        }
        Ok(names)
    }

    async fn exists(&self, path: &[&str]) -> Result<bool, IoError> {
        let files = self.files();
        let is_file = files.contains_key(&owned(path));
        Ok(is_file || files.keys().any(|p| is_inside(p, path)))
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
        let mut files = self.files();
        let Some(content) = files.remove(&owned(path)) else {
            return Ok(false);
        };
        let mut new_path = owned(path);
        new_path.pop();
        new_path.push(new_name.to_owned());
        files.insert(new_path, content);
        Ok(true)
    }

    async fn delete(&self, path: &[&str]) -> Result<bool, IoError> {
        let target = owned(path);
        self.files()
            .retain(|p, _| *p != target && !is_inside(p, path));
        Ok(true)
    }
}
