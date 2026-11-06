//! Downloads: a file read into a sink, resumed with a `Range` from what the
//! sink already holds, hashed as it arrives, and committed only once its size
//! and SHA-256 are right (SPEC.md § 6.6).

use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

use crate::bytes::to_hex;
use crate::error::{Error, Result};

/// Where a download goes. A sink holds what arrived so far, so that a cut
/// connection resumes; it keeps nothing as the file until [`commit`](Self::commit).
pub trait DownloadSink {
    /// How many bytes it holds.
    ///
    /// # Errors
    ///
    /// When the sink cannot be read.
    fn held_size(&mut self) -> Result<u64>;
    /// The bytes it holds, from the start.
    ///
    /// # Errors
    ///
    /// When the sink cannot be read.
    fn held(&mut self) -> Result<Box<dyn Read + '_>>;
    /// Adds bytes.
    ///
    /// # Errors
    ///
    /// When the sink cannot be written.
    fn append(&mut self, chunk: &[u8]) -> Result<()>;
    /// Drops what it holds.
    ///
    /// # Errors
    ///
    /// When the sink cannot be cleared.
    fn reset(&mut self) -> Result<()>;
    /// Keeps what it holds as the file.
    ///
    /// # Errors
    ///
    /// When the sink cannot commit.
    fn commit(&mut self) -> Result<()>;
}

/// A sink in memory.
#[derive(Debug, Default)]
pub struct MemorySink {
    data: Vec<u8>,
    done: bool,
}

impl MemorySink {
    /// An empty sink.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// What it holds.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.data
    }

    /// Whether the download was committed.
    #[must_use]
    pub fn committed(&self) -> bool {
        self.done
    }
}

impl DownloadSink for MemorySink {
    fn held_size(&mut self) -> Result<u64> {
        Ok(self.data.len() as u64)
    }
    fn held(&mut self) -> Result<Box<dyn Read + '_>> {
        Ok(Box::new(self.data.as_slice()))
    }
    fn append(&mut self, chunk: &[u8]) -> Result<()> {
        self.data.extend_from_slice(chunk);
        Ok(())
    }
    fn reset(&mut self) -> Result<()> {
        self.data.clear();
        self.done = false;
        Ok(())
    }
    fn commit(&mut self) -> Result<()> {
        self.done = true;
        Ok(())
    }
}

/// A sink in a file: the download goes to `<path>.part`, which a cut
/// connection leaves for the next try, and is renamed to `path` on commit.
#[derive(Debug)]
pub struct FileSink {
    path: PathBuf,
    part: PathBuf,
}

impl FileSink {
    /// A sink for the file at `path`.
    #[must_use]
    pub fn new(path: impl AsRef<Path>) -> Self {
        let path = path.as_ref().to_path_buf();
        let mut part = path.clone().into_os_string();
        part.push(".part");
        Self {
            path,
            part: PathBuf::from(part),
        }
    }
}

fn io(error: &std::io::Error) -> Error {
    Error::Transport(format!("file: {error}"))
}

impl DownloadSink for FileSink {
    fn held_size(&mut self) -> Result<u64> {
        match std::fs::metadata(&self.part) {
            Ok(m) => Ok(m.len()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(0),
            Err(e) => Err(io(&e)),
        }
    }
    fn held(&mut self) -> Result<Box<dyn Read + '_>> {
        Ok(Box::new(File::open(&self.part).map_err(|e| io(&e))?))
    }
    fn append(&mut self, chunk: &[u8]) -> Result<()> {
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.part)
            .map_err(|e| io(&e))?;
        file.seek(SeekFrom::End(0)).map_err(|e| io(&e))?;
        file.write_all(chunk).map_err(|e| io(&e))
    }
    fn reset(&mut self) -> Result<()> {
        match std::fs::remove_file(&self.part) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(io(&e)),
        }
    }
    fn commit(&mut self) -> Result<()> {
        std::fs::rename(&self.part, &self.path).map_err(|e| io(&e))
    }
}

/// What a file must be.
#[derive(Debug, Clone, Copy)]
pub struct Expected<'a> {
    /// Its SHA-256, hex.
    pub sha256: &'a str,
    /// Its size.
    pub size: u64,
}

/// Checks a download as it arrives and when it ends.
pub(crate) struct Verifier<'a> {
    expected: Expected<'a>,
    what: &'a str,
}

impl<'a> Verifier<'a> {
    pub(crate) fn new(expected: Expected<'a>, what: &'a str) -> Self {
        Self { expected, what }
    }

    /// Where an answer starts (`200` from the start, `206` at `Content-Range`'s first byte).
    pub(crate) fn start(
        &self,
        status: u16,
        content_range: Option<&str>,
        offset: u64,
    ) -> Result<u64> {
        if status == 200 {
            return Ok(0);
        }
        let first = content_range
            .and_then(|r| r.strip_prefix("bytes "))
            .and_then(|r| r.split('-').next())
            .and_then(|n| n.trim().parse::<u64>().ok());
        if first == Some(offset) {
            Ok(offset)
        } else {
            Err(Error::UnexpectedResponse {
                message: format!("{}: a 206 that does not start at byte {offset}", self.what),
                status: Some(206),
            })
        }
    }

    pub(crate) fn feed(&self, hasher: &mut Sha256, size: &mut u64, chunk: &[u8]) -> Result<()> {
        *size += chunk.len() as u64;
        if *size > self.expected.size {
            return Err(Error::Integrity(format!(
                "{}: more than the {} bytes its document says",
                self.what, self.expected.size
            )));
        }
        hasher.update(chunk);
        Ok(())
    }

    pub(crate) fn finish(&self, hasher: Sha256, size: u64) -> Result<()> {
        if size != self.expected.size {
            return Err(Error::Integrity(format!(
                "{}: {size} bytes, its document says {}",
                self.what, self.expected.size
            )));
        }
        let got = to_hex(&hasher.finalize());
        if !got.eq_ignore_ascii_case(self.expected.sha256) {
            return Err(Error::Integrity(format!(
                "{}: SHA-256 {got}, its document says {}",
                self.what, self.expected.sha256
            )));
        }
        Ok(())
    }
}
