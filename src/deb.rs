pub use async_tar::{
    Archive as Tarball, Entries as TarballEntries, Entry as TarballEntry,
    EntryType as TarballEntryType,
};
use {
    crate::parse_size,
    async_compression::futures::bufread::{
        BzDecoder, GzipDecoder, LzmaDecoder, XzDecoder, ZstdDecoder,
    },
    async_std::{
        io::{self, prelude::*, BufReader, Result},
        stream::Stream,
        task::{self, Context, Poll},
    },
    pin_project::pin_project,
    std::{
        ops::Range,
        pin::Pin,
        sync::{Arc, Mutex},
    },
};

macro_rules! ready_opt {
    ($e:expr $(,)?) => {
        match $e {
            async_std::task::Poll::Ready(Ok(t)) => t,
            async_std::task::Poll::Ready(Err(err)) => {
                return async_std::task::Poll::Ready(Some(Err(err)))
            }
            async_std::task::Poll::Pending => return async_std::task::Poll::Pending,
        }
    };
}
macro_rules! ready {
    ($e:expr $(,)?) => {
        match $e {
            async_std::task::Poll::Ready(Ok(t)) => t,
            async_std::task::Poll::Ready(Err(err)) => return async_std::task::Poll::Ready(Err(err)),
            async_std::task::Poll::Pending => return async_std::task::Poll::Pending,
        }
    };
}

const AR_MAGIC: &[u8; 8] = b"!<arch>\n";
const AR_MAGIC_SIZE: usize = AR_MAGIC.len();
const AR_HEADER_SIZE: usize = 60;

enum State {
    Header,
    Content,
}

#[derive(PartialEq)]
enum EntryKind {
    Control,
    Data,
}

#[pin_project]
struct DebReaderInner<R: Read + Unpin + Send> {
    // Current state
    state: State,
    // Content padding
    padding: u8,
    // Size of the current entry
    size: usize,
    // Total bytes read for the current entry
    read: usize,
    // Total bytes read for the whole file
    total: usize,
    // Deb entry header
    hdr: [u8; AR_HEADER_SIZE],
    // Source of the data
    #[pin]
    source: R,
}

impl<R: Read + Unpin + Send> DebReaderInner<R> {
    async fn new(mut r: R) -> std::io::Result<Self> {
        let mut hdr = [0u8; AR_MAGIC_SIZE];
        r.read_exact(&mut hdr).await?;
        if &hdr != AR_MAGIC {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "invalid deb header",
            ));
        }
        Ok(Self {
            state: State::Header,
            size: AR_HEADER_SIZE,
            padding: 0,
            read: 0,
            total: AR_MAGIC_SIZE,
            hdr: [0u8; AR_HEADER_SIZE],
            source: r,
        })
    }
    fn reset_for_next_chunk(&mut self, state: State, size: usize) {
        self.state = state;
        self.size = size;
        self.padding = (size & 1) as u8;
        self.read = 0;
    }
    fn size_with_padding(&self) -> usize {
        self.size + (self.padding as usize)
    }
    fn poll_read_header(self: Pin<&mut Self>, ctx: &mut Context<'_>) -> Poll<Result<usize>> {
        let this = self.project();
        let buf = this.hdr.as_mut();
        let remain = (*this.size + *this.padding as usize) - *this.read;
        if remain == 0 {
            return Poll::Ready(Ok(0));
        }
        match ready!(this.source.poll_read(ctx, &mut buf[*this.read..*this.size])) {
            0 => Poll::Ready(Ok(0)),
            n => {
                *this.read += n;
                *this.total += n;
                Poll::Ready(Ok(if n < remain {
                    n
                } else {
                    n - *this.padding as usize
                }))
            }
        }
    }
}

impl<R: Read + Unpin + Send> Read for DebReaderInner<R> {
    fn poll_read(
        self: Pin<&mut Self>,
        ctx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<std::io::Result<usize>> {
        let mut this = self.project();
        let remain = (*this.size + *this.padding as usize) - *this.read;
        if remain == 0 {
            return Poll::Ready(Ok(0));
        };
        let size = std::cmp::min(remain, buf.len());
        match ready!(this.source.as_mut().poll_read(ctx, &mut buf[0..size])) {
            0 => Poll::Ready(Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "unexpected EOF while reading package entry",
            ))),
            n => {
                *this.read += n;
                *this.total += n;
                Poll::Ready(Ok(if n < remain {
                    n
                } else {
                    n - *this.padding as usize
                }))
            }
        }
    }
}

impl<R: Read + Unpin + Send> Stream for DebReaderInner<R> {
    type Item = Result<(EntryKind, Range<usize>)>;
    fn poll_next(mut self: Pin<&mut Self>, ctx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        loop {
            match self.state {
                // skip the rest of the unread body if necessary
                State::Content => {
                    if self.read < self.size_with_padding() {
                        let mut buf = [0u8; 8192];
                        while self.read < self.size_with_padding() {
                            if ready_opt!(self.as_mut().poll_read(ctx, &mut buf[..])) == 0 {
                                return Poll::Ready(Some(Err(io::Error::new(
                                    io::ErrorKind::UnexpectedEof,
                                    "unexpected EOF while reading entry content",
                                ))));
                            }
                        }
                    }
                    self.reset_for_next_chunk(State::Header, AR_HEADER_SIZE);
                }
                // read the header
                State::Header => {
                    while self.read < AR_HEADER_SIZE {
                        match ready_opt!(self.as_mut().poll_read_header(ctx)) {
                            0 if self.read == 0 => return Poll::Ready(None),
                            0 => {
                                return Poll::Ready(Some(Err(io::Error::new(
                                    io::ErrorKind::UnexpectedEof,
                                    "unexpected EOF while reading entry header",
                                ))))
                            }
                            _ => continue,
                        }
                    }
                    let size = parse_size(&self.hdr[48..58])?;
                    self.reset_for_next_chunk(State::Content, size);
                    let name = std::str::from_utf8(&self.hdr[0..16]).map_err(|_| {
                        io::Error::new(
                            io::ErrorKind::InvalidData,
                            format!("invalid header: {:?}", &self.hdr),
                        )
                    })?;
                    let name = name.find(' ').map(|n| &name[..n]).ok_or(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("error parsing deb entry name {}", name),
                    ))?;
                    if name == "debian-binary" {
                        // a minor optimization to avoid allocating buffer when skipping version
                        if size <= AR_HEADER_SIZE {
                            match ready_opt!(self.as_mut().poll_read_header(ctx)) {
                                0 => {
                                    return Poll::Ready(Some(Err(io::Error::new(
                                        io::ErrorKind::UnexpectedEof,
                                        "unexpected EOF while reading entry content",
                                    ))))
                                }
                                n if n == size => {
                                    self.reset_for_next_chunk(State::Header, AR_HEADER_SIZE);
                                }
                                _ => {} // skip as content
                            }
                        }
                        continue;
                    } else if name.starts_with("control.tar") {
                        let ext_range = "control.tar".len()..name.len();
                        return Poll::Ready(Some(Ok((EntryKind::Control, ext_range))));
                    } else if name.starts_with("data.tar") {
                        let ext_range = "data.tar".len()..name.len();
                        return Poll::Ready(Some(Ok((EntryKind::Data, ext_range))));
                    } else {
                        return Poll::Ready(Some(Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            format!("unexpected debian package entry {:?}", &name),
                        ))));
                    }
                }
            }
        }
    }
}

/// Asynchronous debian package reader
/// # Example
///
/// ```
/// let mut deb = Deb::new(input).await?;
/// while let Some(entry) = deb.next().await {
///     match entry? {
///         DebEntry::Control(f) => {
///             f.entries()?.map(|file| -> Result<()> Ok(process_control_file(file?)?))
///                 .try_collect()
///                 .await?;
///         }
///         DebEntry::Data(f) => {
///             f.entries()?.map(|file| -> Result<()> Ok(process_data_file(file?)?))
///                 .try_collect()
///                 .await?;
///         }
///         DebEntry::Version(_) => { }
///     }
/// }
/// ```
pub struct DebReader<
    'a,
    R: Read + Unpin + Send + 'a,
> {
    inner: Arc<Mutex<DebReaderInner<R>>>,
    _marker: std::marker::PhantomData<&'a ()>,
}

struct DebEntryReaderInner<
    'a,
    R: Read + Unpin + Send + 'a,
> {
    inner: Arc<Mutex<DebReaderInner<R>>>,
    _marker: std::marker::PhantomData<&'a ()>,
}

impl<'a, R: Read + Unpin + Send + 'a> Read
    for DebEntryReaderInner<'a, R>
{
    fn poll_read(
        self: Pin<&mut Self>,
        ctx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<std::io::Result<usize>> {
        let mut reader = self.inner.lock().map_err(|err| {
            io::Error::new(
                io::ErrorKind::Other,
                format!("unexpected mutex error {}", err),
            )
        })?;
        Pin::new(&mut *reader).poll_read(ctx, buf)
    }
}

impl<'a, R: Read + Unpin + Send + 'a> DebReader<'a, R> {
    /// Creates a new asynchronous Debian archive reader from the given reader `R`.
    ///
    /// # Arguments
    ///
    /// * `reader` - The input source that implements the asynchronous read trait and provides the Debian archive data.
    ///
    /// # Returns
    ///
    /// * Result<Self> - An instance of `Deb` wrapped in a `Result`, containing
    ///     - `Ok`: A successfully initialized reader
    ///     - `Err`: An error if the reader initialization fails.
    ///
    /// # Examples
    ///
    /// ```
    /// use deb_repo::deb::Deb;
    /// use anyhow::Result;
    ///
    /// async fn example() -> Result<()> {
    ///     let reader = tokio::fs::File::open("path/to/debian/archive.deb").await?;
    ///     let deb = Deb::new(reader).await?;
    ///     Ok(())
    /// }
    /// ```
    pub async fn new(reader: R) -> Result<Self> {
        Ok(DebReader {
            inner: Arc::new(Mutex::new(DebReaderInner::new(reader).await?)),
            _marker: std::marker::PhantomData,
        })
    }
    fn entry_reader_for_ext(&self, ext: &str) -> Result<Pin<Box<dyn Read + Unpin + Send + 'a>>> {
        let r = DebEntryReaderInner {
            inner: Arc::clone(&self.inner),
            _marker: std::marker::PhantomData,
        };
        Ok(match ext {
            ".xz" => Box::pin(XzDecoder::new(BufReader::new(r))),
            ".gz" => Box::pin(GzipDecoder::new(BufReader::new(r))),
            ".bz2" => Box::pin(BzDecoder::new(BufReader::new(r))),
            ".lzma" => Box::pin(LzmaDecoder::new(BufReader::new(r))),
            ".zstd" => Box::pin(ZstdDecoder::new(BufReader::new(r))),
            _ => Box::pin(r),
        })
    }
}

impl<'a, R: Read + Unpin + Send + 'a> Stream
    for DebReader<'a, R>
{
    type Item = Result<DebEntry<'a>>;
    fn poll_next(self: Pin<&mut Self>, ctx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let mut reader = self.inner.lock().map_err(|err| {
            io::Error::new(
                io::ErrorKind::Other,
                format!("unexpected mutex error {}", err),
            )
        })?;
        match task::ready!(Pin::new(&mut *reader).poll_next(ctx)) {
            None => Poll::Ready(None),
            Some(Err(err)) => Poll::Ready(Some(Err(err))),
            Some(Ok((entry_kind, ext_range))) => Poll::Ready(Some(match entry_kind {
                EntryKind::Control => {
                    Ok(DebEntry::Control(Tarball::new(self.entry_reader_for_ext(
                        unsafe { std::str::from_utf8_unchecked(&reader.hdr[ext_range]) },
                    )?)))
                }
                EntryKind::Data => Ok(DebEntry::Data(Tarball::new(self.entry_reader_for_ext(
                    unsafe { std::str::from_utf8_unchecked(&reader.hdr[ext_range]) },
                )?))),
            })),
        }
    }
}

pub struct DebEntryReader {
    inner: Pin<Box<dyn Read + Unpin + Send>>,
}

impl Read for DebEntryReader {
    fn poll_read(
        mut self: Pin<&mut Self>,
        ctx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<std::io::Result<usize>> {
        self.inner.as_mut().poll_read(ctx, buf)
    }
}

pub enum DebEntry<'a> {
    Control(Tarball<Pin<Box<dyn Read + Unpin + Send + 'a>>>),
    Data(Tarball<Pin<Box<dyn Read + Unpin + Send + 'a>>>),
}

impl<'a> DebEntry<'a> {
    pub fn into_inner(self) -> Tarball<Pin<Box<dyn Read + Unpin + Send + 'a>>> {
        match self {
            DebEntry::Control(tar) | DebEntry::Data(tar) => tar,
        }
    }
    pub fn entries(self) -> Result<TarballEntries<Pin<Box<dyn Read + Unpin + Send + 'a>>>> {
        match self {
            DebEntry::Control(tar) | DebEntry::Data(tar) => tar.entries(),
        }
    }
}
