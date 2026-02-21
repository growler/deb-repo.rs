use {
    smol::io::{AsyncRead, AsyncReadExt},
    std::{io, ops::RangeBounds, pin::pin, sync::Arc},
};

/// Parsed index file content with hash and size.
pub struct IndexFile {
    inner: IndexFileInner,
}

impl Clone for IndexFile {
    fn clone(&self) -> Self {
        Self {
            inner: match &self.inner {
                IndexFileInner::Mmap { mmap, start, end } => IndexFileInner::Mmap {
                    mmap: Arc::clone(mmap),
                    start: *start,
                    end: *end,
                },
                IndexFileInner::Slice { data, start, end } => IndexFileInner::Slice {
                    data: Arc::clone(data),
                    start: *start,
                    end: *end,
                },
            },
        }
    }
}

impl std::fmt::Display for IndexFile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_ref())
    }
}

impl std::ops::Deref for IndexFile {
    type Target = str;
    fn deref(&self) -> &Self::Target {
        self.as_ref()
    }
}

impl AsRef<str> for IndexFile {
    fn as_ref(&self) -> &str {
        match &self.inner {
            IndexFileInner::Mmap { mmap, start, end } => {
                // Safety: The mmap region is guaranteed to be valid UTF-8 as it was created from a text file
                unsafe { std::str::from_utf8_unchecked(&mmap[*start..*end]) }
            }
            IndexFileInner::Slice { data, start, end } => &data.as_ref()[*start..*end],
        }
    }
}

impl IndexFile {
    pub fn as_str(&self) -> &str {
        self.as_ref()
    }
    pub fn len(&self) -> usize {
        match &self.inner {
            IndexFileInner::Mmap { start, end, .. } => end - start,
            IndexFileInner::Slice { start, end, .. } => end - start,
        }
    }
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
    pub fn as_bytes(&self) -> &[u8] {
        match &self.inner {
            IndexFileInner::Mmap { mmap, start, end } => &mmap[*start..*end],
            IndexFileInner::Slice { data, start, end } => &data.as_bytes()[*start..*end],
        }
    }
    pub async fn read<R: AsyncRead>(r: R) -> io::Result<Self> {
        let mut buf = String::new();
        pin!(r).read_to_string(&mut buf).await?;
        Ok(IndexFile {
            inner: IndexFileInner::Slice {
                start: 0,
                end: buf.len(),
                data: buf.into(),
            },
        })
    }
    pub async fn from_file<P: AsRef<std::path::Path>>(path: P) -> io::Result<Self> {
        let mut file = smol::fs::File::open(path).await?;
        let meta = file.metadata().await?;
        if meta.len() > 1024 * 1024 {
            let mmap = unsafe { memmap2::MmapOptions::new().map(&file)? };
            std::str::from_utf8(&mmap).map_err(|err| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("File is not valid UTF-8: {}", err),
                )
            })?;
            Ok(IndexFile {
                inner: IndexFileInner::Mmap {
                    start: 0,
                    end: mmap.len(),
                    mmap: Arc::new(mmap),
                },
            })
        } else {
            let mut buf = String::with_capacity(meta.len() as usize);
            file.read_to_string(&mut buf).await?;
            Ok(IndexFile {
                inner: IndexFileInner::Slice {
                    start: 0,
                    end: buf.len(),
                    data: buf.into(),
                },
            })
        }
    }
    pub fn mmap_region(mmap: Arc<memmap2::Mmap>, start: usize, end: usize) -> io::Result<Self> {
        if start > end || end > mmap.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Invalid region for mmap",
            ));
        }
        std::str::from_utf8(&mmap).map_err(|err| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("File is not valid UTF-8: {}", err),
            )
        })?;
        Ok(IndexFile {
            inner: IndexFileInner::Mmap { mmap, start, end },
        })
    }
    pub fn from_bytes(data: Vec<u8>) -> io::Result<Self> {
        let s = String::from_utf8(data).map_err(|err| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Data is not valid UTF-8: {}", err),
            )
        })?;
        Ok(IndexFile {
            inner: IndexFileInner::Slice {
                start: 0,
                end: s.len(),
                data: Arc::from(s),
            },
        })
    }
    pub fn from_string(data: String) -> Self {
        IndexFile {
            inner: IndexFileInner::Slice {
                start: 0,
                end: data.len(),
                data: Arc::from(data),
            },
        }
    }
    fn slice<R: RangeBounds<usize>>(&self, range: R) -> Self {
        let start = match range.start_bound() {
            std::ops::Bound::Included(&s) => s,
            std::ops::Bound::Excluded(&s) => s + 1,
            std::ops::Bound::Unbounded => 0,
        };
        let end = match range.end_bound() {
            std::ops::Bound::Included(&e) => e + 1,
            std::ops::Bound::Excluded(&e) => e,
            std::ops::Bound::Unbounded => self.len(),
        };
        IndexFile {
            inner: match &self.inner {
                IndexFileInner::Mmap {
                    mmap,
                    start: self_start,
                    ..
                } => IndexFileInner::Mmap {
                    mmap: Arc::clone(mmap),
                    start: start + self_start,
                    end: end + self_start,
                },
                IndexFileInner::Slice {
                    data,
                    start: self_start,
                    ..
                } => IndexFileInner::Slice {
                    data: Arc::clone(data),
                    start: start + self_start,
                    end: end + self_start,
                },
            },
        }
    }
    pub(crate) fn clear_text(&self) -> Self {
        const BEGIN: &[u8] = b"-----BEGIN PGP SIGNED MESSAGE-----\n";
        const SIG_BEGIN: &[u8] = b"\n-----BEGIN PGP SIGNATURE-----";

        let text = self.as_bytes();

        if !text.starts_with(BEGIN) {
            return self.clone();
        }
        let start = match text.windows(2).position(|w| w == b"\n\n") {
            Some(pos) => pos + 2,
            None => return self.clone(),
        };
        let end = match text.windows(SIG_BEGIN.len()).position(|w| w == SIG_BEGIN) {
            Some(pos) => pos,
            None => return self.clone(),
        };
        self.slice(start..end)
    }
}

impl<T> From<T> for IndexFile
where
    Arc<str>: From<T>,
{
    fn from(data: T) -> Self {
        let data: Arc<str> = Arc::from(data);
        IndexFile {
            inner: IndexFileInner::Slice {
                start: 0,
                end: data.len(),
                data,
            },
        }
    }
}

enum IndexFileInner {
    Mmap {
        mmap: Arc<memmap2::Mmap>,
        start: usize,
        end: usize,
    },
    Slice {
        data: Arc<str>,
        start: usize,
        end: usize,
    },
}
