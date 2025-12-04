use {
    smol::io::{AsyncRead, AsyncReadExt},
    std::{io, pin::pin, sync::Arc},
};

pub struct IndexFile {
    inner: IndexFileInner,
}

impl Clone for IndexFile {
    fn clone(&self) -> Self {
        Self {
            inner: match &self.inner {
                IndexFileInner::Mmap { mmap } => IndexFileInner::Mmap {
                    mmap: Arc::clone(mmap),
                },
                IndexFileInner::MmapReg { mmap, start, end } => IndexFileInner::MmapReg {
                    mmap: Arc::clone(mmap),
                    start: *start,
                    end: *end,
                },
                IndexFileInner::Slice { data } => IndexFileInner::Slice {
                    data: Arc::clone(data),
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
            IndexFileInner::Mmap { mmap } => {
                // Safety: The mmap is guaranteed to be valid UTF-8 as it was created from a text file
                unsafe { std::str::from_utf8_unchecked(mmap) }
            }
            IndexFileInner::MmapReg { mmap, start, end } => {
                // Safety: The mmap region is guaranteed to be valid UTF-8 as it was created from a text file
                unsafe { std::str::from_utf8_unchecked(&mmap[*start..*end]) }
            }
            IndexFileInner::Slice { data } => data.as_ref(),
        }
    }
}

impl IndexFile {
    pub fn as_str(&self) -> &str {
        self.as_ref()
    }
    pub fn len(&self) -> usize {
        match &self.inner {
            IndexFileInner::Mmap { mmap } => mmap.len(),
            IndexFileInner::MmapReg { start, end, .. } => end - start,
            IndexFileInner::Slice { data } => data.len(),
        }
    }
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
    pub fn as_bytes(&self) -> &[u8] {
        match &self.inner {
            IndexFileInner::Mmap { mmap } => &mmap[..],
            IndexFileInner::MmapReg { mmap, start, end } => &mmap[*start..*end],
            IndexFileInner::Slice { data } => data.as_bytes(),
        }
    }
    pub async fn read<R: AsyncRead>(r: R) -> io::Result<Self> {
        let mut buf = String::new();
        pin!(r).read_to_string(&mut buf).await?;
        Ok(IndexFile {
            inner: IndexFileInner::Slice { data: buf.into() },
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
                    mmap: Arc::new(mmap),
                },
            })
        } else {
            let mut buf = String::with_capacity(meta.len() as usize);
            file.read_to_string(&mut buf).await?;
            Ok(IndexFile {
                inner: IndexFileInner::Slice { data: buf.into() },
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
            inner: IndexFileInner::MmapReg { mmap, start, end },
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
            inner: IndexFileInner::Slice { data: Arc::from(s) },
        })
    }
}

impl<T> From<T> for IndexFile
where
    Arc<str>: From<T>,
{
    fn from(data: T) -> Self {
        IndexFile {
            inner: IndexFileInner::Slice {
                data: Arc::from(data),
            },
        }
    }
}

enum IndexFileInner {
    Mmap {
        mmap: Arc<memmap2::Mmap>,
    },
    MmapReg {
        mmap: Arc<memmap2::Mmap>,
        start: usize,
        end: usize,
    },
    Slice {
        data: Arc<str>,
    },
}
