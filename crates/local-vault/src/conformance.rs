//! The rules of [`FileSystem`] as checks, which a client runs against the file system that it
//! reaches its vault folder through. The vault store only does the same on every file system
//! that keeps them, which the clients that share a vault folder count on.

use crate::fs::{FileSystem, IoError};

/// More than one message between a browser and a native application holds, so that a file
/// system that reads and writes in parts does it more than once.
const LARGE_FILE_BYTES: usize = 600 * 1024;

/// How often the content of the large file repeats, which is not a divisor of the size of a
/// part: parts that are put together in the wrong order do not give the same content.
const LARGE_FILE_PERIOD: usize = 251;

const NO_SCRATCH: &str = "The checks need a directory of their own.";
const NOTHING_REMAINS: &str = "Deleting reports that nothing remains, also of what was not there.";
const DELETED_IS_GONE: &str = "What is deleted does not exist.";
const MISSING_IS_EMPTY: &str = "A directory that does not exist is listed as empty.";
const MISSING_IS_NONE: &str = "A file that does not exist is read as none.";
const MISSING_IS_NOT_RENAMED: &str = "A file that does not exist is not renamed.";
const REPLACED: &str = "Writing a file replaces everything that it had.";
const WRITTEN_EXISTS: &str = "A file that is written exists, and so do the directories on its way.";
const LISTED: &str = "A directory lists the names of the files and the directories in it.";
const FILE_IS_NO_DIRECTORY: &str = "A file is not listed as a directory.";
const DIRECTORY_IS_NO_FILE: &str = "A directory is not read as a file.";
const EMPTY_IS_EMPTY: &str = "An empty file is read as empty, not as none.";
const BYTES_ARE_KEPT: &str = "Every value of a byte is kept.";
const LARGE_IS_KEPT: &str = "A file that is larger than one message is read as it was written.";
const RENAMED: &str = "A file is renamed within its directory.";
const RENAMED_OVER_ANOTHER: &str =
    "Renaming a file to the name of another one replaces that one, or changes nothing.";
const DELETED_WITH_ALL: &str = "A directory is deleted with everything in it.";

/// Checks that the file system keeps the rules of [`FileSystem`], in the directory at the path
/// `scratch`, which is deleted with everything in it before and after. Returns the rules that
/// it does not keep, which are none for a file system that keeps them all, and the error of an
/// operation that failed, after which nothing more is checked.
pub async fn check_file_system<F: FileSystem>(fs: &F, scratch: &[&str]) -> Vec<String> {
    if scratch.is_empty() {
        return vec![NO_SCRATCH.to_owned()];
    }
    let mut failures = Vec::new();
    let mut expect = |holds: bool, rule: &str| {
        if !holds {
            failures.push(rule.to_owned());
        }
    };
    let checked = check(fs, scratch, &mut expect).await;
    if let Err(error) = checked {
        failures.push(format!("An operation failed: {}", error.message()));
    }
    failures
}

/// Checks the rules, and tells `expect` whether each of them holds.
async fn check<F: FileSystem>(
    fs: &F,
    scratch: &[&str],
    expect: &mut impl FnMut(bool, &str),
) -> Result<(), IoError> {
    let missing = inside(scratch, &["missing.json"]);
    let directory = inside(scratch, &["directory"]);
    let file = inside(scratch, &["directory", "file.json"]);
    let renamed = inside(scratch, &["directory", "renamed.json"]);
    let other = inside(scratch, &["directory", "other.json"]);
    let empty = inside(scratch, &["empty.json"]);
    let bytes = inside(scratch, &["bytes.bin"]);
    let large = inside(scratch, &["large.bin"]);
    let tree = inside(scratch, &["tree"]);
    let leaf = inside(scratch, &["tree", "branch", "leaf.json"]);

    // What is not there.
    expect(fs.delete(scratch).await?, NOTHING_REMAINS);
    expect(!fs.exists(scratch).await?, DELETED_IS_GONE);
    expect(fs.list(scratch).await?.is_empty(), MISSING_IS_EMPTY);
    expect(fs.read(&missing).await?.is_none(), MISSING_IS_NONE);
    expect(fs.delete(&missing).await?, NOTHING_REMAINS);
    let renamed_missing = fs.rename(&missing, "renamed.json").await?;
    expect(!renamed_missing, MISSING_IS_NOT_RENAMED);

    // Writing and reading.
    fs.write(&file, b"longer content").await?;
    fs.write(&file, b"two").await?;
    expect(is(fs.read(&file).await?, b"two"), REPLACED);
    let exist = fs.exists(&directory).await? && fs.exists(&file).await?;
    expect(exist, WRITTEN_EXISTS);
    expect(fs.list(scratch).await? == ["directory"], LISTED);
    expect(fs.list(&directory).await? == ["file.json"], LISTED);
    expect(fs.list(&file).await?.is_empty(), FILE_IS_NO_DIRECTORY);
    expect(fs.read(&directory).await?.is_none(), DIRECTORY_IS_NO_FILE);
    fs.write(&empty, b"").await?;
    expect(is(fs.read(&empty).await?, b""), EMPTY_IS_EMPTY);
    let every_byte: Vec<u8> = (0..=u8::MAX).collect();
    fs.write(&bytes, &every_byte).await?;
    expect(is(fs.read(&bytes).await?, &every_byte), BYTES_ARE_KEPT);
    let pattern = (0..LARGE_FILE_BYTES).map(|i| i % LARGE_FILE_PERIOD);
    let large_content: Vec<u8> = pattern.map(|byte| byte as u8).collect();
    fs.write(&large, &large_content).await?;
    expect(is(fs.read(&large).await?, &large_content), LARGE_IS_KEPT);

    // Renaming.
    let moved = fs.rename(&file, "renamed.json").await?;
    let old = fs.read(&file).await?;
    let new = fs.read(&renamed).await?;
    expect(moved && old.is_none() && is(new, b"two"), RENAMED);
    fs.write(&other, b"other").await?;
    let replaced = fs.rename(&renamed, "other.json").await?;
    let source = fs.read(&renamed).await?;
    let target = fs.read(&other).await?;
    let kept = if replaced {
        source.is_none() && is(target, b"two")
    } else {
        is(source, b"two") && is(target, b"other")
    };
    expect(kept, RENAMED_OVER_ANOTHER);

    // Deleting.
    let deleted = fs.delete(&other).await?;
    expect(deleted && !fs.exists(&other).await?, DELETED_IS_GONE);
    fs.write(&leaf, b"leaf").await?;
    let deleted = fs.delete(&tree).await?;
    let gone = !fs.exists(&tree).await? && fs.read(&leaf).await?.is_none();
    expect(deleted && gone, DELETED_WITH_ALL);
    let deleted = fs.delete(scratch).await?;
    expect(deleted && !fs.exists(scratch).await?, DELETED_IS_GONE);
    Ok(())
}

/// The path of the names inside of the directory.
fn inside<'a>(directory: &[&'a str], names: &[&'a str]) -> Vec<&'a str> {
    directory.iter().chain(names).copied().collect()
}

/// Returns `true` if a file was read with the content.
fn is(read: Option<Vec<u8>>, content: &[u8]) -> bool {
    read.as_deref() == Some(content)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory_fs::MemoryFileSystem;
    use futures::executor::block_on;

    #[test]
    fn the_file_system_of_the_tests_keeps_every_rule() {
        let fs = MemoryFileSystem::new();
        fs.put(&["account", "vault.json"], "{}");

        let failures = block_on(check_file_system(&fs, &["check"]));

        assert!(failures.is_empty(), "{failures:?}");
        assert_eq!(fs.paths(), [["account", "vault.json"]]);
    }

    #[test]
    fn the_rules_that_a_file_system_does_not_keep_are_reported() {
        let fs = NoRename(MemoryFileSystem::new());

        let failures = block_on(check_file_system(&fs, &["check"]));
        let whole_folder = block_on(check_file_system(&fs, &[]));

        let broken = [MISSING_IS_NOT_RENAMED, RENAMED, RENAMED_OVER_ANOTHER];
        assert_eq!(failures, broken);
        assert_eq!(whole_folder, [NO_SCRATCH]);
    }

    #[test]
    fn an_operation_that_fails_ends_the_checks() {
        let failures = block_on(check_file_system(&Unreachable, &["check"]));

        assert_eq!(failures, ["An operation failed: The vault folder is gone."]);
    }

    /// A file system that says that it renames, and does not.
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
            Ok(true)
        }

        async fn delete(&self, path: &[&str]) -> Result<bool, IoError> {
            self.0.delete(path).await
        }
    }

    /// A vault folder that cannot be reached.
    struct Unreachable;

    fn gone<T>() -> Result<T, IoError> {
        Err(IoError::new("The vault folder is gone."))
    }

    impl FileSystem for Unreachable {
        async fn list(&self, _directory: &[&str]) -> Result<Vec<String>, IoError> {
            gone()
        }

        async fn exists(&self, _path: &[&str]) -> Result<bool, IoError> {
            gone()
        }

        async fn read(&self, _path: &[&str]) -> Result<Option<Vec<u8>>, IoError> {
            gone()
        }

        async fn write(&self, _path: &[&str], _content: &[u8]) -> Result<(), IoError> {
            gone()
        }

        async fn rename(&self, _path: &[&str], _new_name: &str) -> Result<bool, IoError> {
            gone()
        }

        async fn delete(&self, _path: &[&str]) -> Result<bool, IoError> {
            gone()
        }
    }
}
