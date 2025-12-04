//! Minimal async tar reader/writer used for Debian packages and OCI layers.
//!
//! The implementation only supports the GNU and POSIX (ustar/pax) variants that
//! those artifacts rely on. It purposefully omits rarer extensions (for example
//! sparse files) but does understand GNU long names and POSIX extended
//! attributes well enough to round-trip path metadata and device information.
//! Reading is done through a streaming state machine so the archive never needs
//! to be fully buffered, while writing leverages a compact staging buffer plus
//! backpressure via `Sink`.
use {
    async_lock::Mutex,
    futures::Sink,
    futures_lite::{
        io::{AsyncRead, AsyncWrite},
        Stream,
    },
    pin_project_lite::pin_project,
    std::{
        future::Future,
        io::{Error, ErrorKind, Result},
        pin::{pin, Pin},
        str::from_utf8,
        sync::Arc,
        task::{self, Context, Poll},
    },
};

const BLOCK_SIZE: usize = 512;
const SKIP_BUFFER_SIZE: usize = 64 * 1024;
const PATH_MAX: usize = 4096;
const PAX_HEADER_MAX_SIZE: usize = 1024 * 1024;

macro_rules! ready {
    ($e:expr $(,)?) => {
        match $e {
            Poll::Ready(Ok(t)) => t,
            Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
            Poll::Pending => return Poll::Pending,
        }
    };
}

macro_rules! ready_opt {
    ($e:expr $(,)?) => {
        match $e {
            Poll::Ready(Ok(t)) => t,
            Poll::Ready(Err(err)) => return Poll::Ready(Some(Err(err))),
            Poll::Pending => return Poll::Pending,
        }
    };
}

#[repr(C)]
#[allow(missing_docs)]
struct Header {
    record: [u8; BLOCK_SIZE],
}

enum HeaderKind<'a> {
    Gnu(&'a GnuHeader),
    Ustar(&'a UstarHeader),
    Old(&'a OldHeader),
}

trait HeaderVariant {}

impl Header {
    fn new() -> Self {
        Self {
            record: [0u8; BLOCK_SIZE],
        }
    }
    unsafe fn cast<U: HeaderVariant>(&self) -> &U {
        &*(self as *const Self as *const U)
    }
    fn buf_mut<I>(&mut self, range: I) -> &mut [u8]
    where
        I: core::slice::SliceIndex<[u8], Output = [u8]>,
    {
        &mut self.record[range]
    }
    fn buf<I>(&self, range: I) -> &[u8]
    where
        I: core::slice::SliceIndex<[u8], Output = [u8]>,
    {
        &self.record[range]
    }
    fn as_str<I>(&self, range: I) -> Result<Box<str>>
    where
        I: core::slice::SliceIndex<[u8], Output = [u8]>,
    {
        from_utf8(self.buf(range))
            .map_err(|_| Error::new(ErrorKind::InvalidData, "invalid UTF-8"))
            .map(|p| p.to_string().into_boxed_str())
    }
    fn as_null_terminated_str<I>(&self, range: I) -> Result<Box<str>>
    where
        I: core::slice::SliceIndex<[u8], Output = [u8]>,
    {
        from_utf8(null_terminated(self.buf(range)))
            .map_err(|_| Error::new(ErrorKind::InvalidData, "invalid UTF-8"))
            .map(|p| p.to_string().into_boxed_str())
    }
    fn kind(&self) -> HeaderKind<'_> {
        let gnu = unsafe { self.cast::<GnuHeader>() };
        if gnu.magic == *b"ustar " && gnu.version == *b" \0" {
            HeaderKind::Gnu(gnu)
        } else if gnu.magic == *b"ustar\0" && gnu.version == *b"00" {
            HeaderKind::Ustar(unsafe { self.cast::<UstarHeader>() })
        } else {
            HeaderKind::Old(unsafe { self.cast::<OldHeader>() })
        }
    }
    fn entry_type(&self) -> std::result::Result<Kind, u8> {
        Kind::from_byte(unsafe { self.cast::<GnuHeader>() }.typeflag[0])
    }
    fn is_gnu(&self) -> bool {
        let gnu = unsafe { self.cast::<GnuHeader>() };
        gnu.magic == *b"ustar " && gnu.version == *b" \0"
    }
    #[allow(dead_code)]
    fn is_ustar(&self) -> bool {
        let ustar = unsafe { self.cast::<UstarHeader>() };
        ustar.magic == *b"ustar\0" && ustar.version == *b"00"
    }
    fn is_old(&self) -> bool {
        let gnu = unsafe { self.cast::<GnuHeader>() };
        gnu.magic[..5] != *b"ustar"
    }
    #[inline]
    fn mode(&self) -> Result<u32> {
        parse_octal(&unsafe { self.cast::<GnuHeader>() }.mode)
            .map(|r| r as u32)
            .map_err(|err| {
                Error::new(
                    ErrorKind::InvalidData,
                    format!("invalid octal digit: {:?}", String::from_utf8_lossy(err)),
                )
            })
    }
    #[inline]
    fn mtime(&self) -> Result<u32> {
        parse_octal(&unsafe { self.cast::<GnuHeader>() }.mtime)
            .map(|r| r as u32)
            .map_err(|err| {
                Error::new(
                    ErrorKind::InvalidData,
                    format!("invalid octal digit: {:?}", String::from_utf8_lossy(err)),
                )
            })
    }
    #[inline]
    fn size(&self) -> Result<u64> {
        parse_octal(&unsafe { self.cast::<GnuHeader>() }.size).map_err(|err| {
            Error::new(
                ErrorKind::InvalidData,
                format!("invalid octal digit: {:?}", String::from_utf8_lossy(err)),
            )
        })
    }
    #[inline]
    fn uid(&self) -> Result<u32> {
        parse_octal(&unsafe { self.cast::<GnuHeader>() }.uid)
            .map(|r| r as u32)
            .map_err(|err| {
                Error::new(
                    ErrorKind::InvalidData,
                    format!("invalid octal digit: {:?}", String::from_utf8_lossy(err)),
                )
            })
    }
    #[inline]
    fn gid(&self) -> Result<u32> {
        parse_octal(&unsafe { self.cast::<GnuHeader>() }.gid)
            .map(|r| r as u32)
            .map_err(|err| {
                Error::new(
                    ErrorKind::InvalidData,
                    format!("invalid octal digit: {:?}", String::from_utf8_lossy(err)),
                )
            })
    }
    #[inline]
    fn dev_major(&self) -> Result<u32> {
        parse_octal(&unsafe { self.cast::<GnuHeader>() }.dev_major)
            .map(|r| r as u32)
            .map_err(|err| {
                Error::new(
                    ErrorKind::InvalidData,
                    format!("invalid octal digit: {:?}", String::from_utf8_lossy(err)),
                )
            })
    }
    #[inline]
    fn dev_minor(&self) -> Result<u32> {
        parse_octal(&unsafe { self.cast::<GnuHeader>() }.dev_minor)
            .map(|r| r as u32)
            .map_err(|err| {
                Error::new(
                    ErrorKind::InvalidData,
                    format!("invalid octal digit: {:?}", String::from_utf8_lossy(err)),
                )
            })
    }
    fn is_zero(&self) -> bool {
        self.record.iter().all(|b| *b == b'\0')
    }
}

#[derive(Debug, PartialEq, Eq)]
#[repr(u8)]
enum Kind {
    File0 = b'\0',
    File = b'0',
    Link = b'1',
    Symlink = b'2',
    CharDevice = b'3',
    BlockDevice = b'4',
    Directory = b'5',
    Fifo = b'6',
    #[allow(dead_code)]
    Continous = b'7',
    GNULongLink = b'K',
    GNULongName = b'L',
    PAXLocal = b'x',
    PAXGlobal = b'g',
}
impl std::fmt::Display for Kind {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.write_str(match self {
            Self::File | Self::File0 | Self::Continous => "regular file",
            Self::Link => "link",
            Self::Symlink => "symlink",
            Self::CharDevice => "character device",
            Self::BlockDevice => "block device",
            Self::Directory => "directory",
            Self::Fifo => "FIFO",
            Self::GNULongName => "GNU long name extension",
            Self::GNULongLink => "GNU long link extension",
            Self::PAXLocal => "PAX next file extension",
            Self::PAXGlobal => "PAX global extension",
        })
    }
}

impl Kind {
    fn byte(self) -> u8 {
        self as u8
    }
    fn from_byte(b: u8) -> std::result::Result<Self, u8> {
        match b {
            v if v == Kind::File0.byte() => Ok(Kind::File0),
            v if v == Kind::File.byte() => Ok(Kind::File),
            v if v == Kind::Link.byte() => Ok(Kind::Link),
            v if v == Kind::Symlink.byte() => Ok(Kind::Symlink),
            v if v == Kind::Directory.byte() => Ok(Kind::Directory),
            v if v == Kind::GNULongName.byte() => Ok(Kind::GNULongName),
            v if v == Kind::GNULongLink.byte() => Ok(Kind::GNULongLink),
            v if v == Kind::PAXLocal.byte() => Ok(Kind::PAXLocal),
            v if v == Kind::PAXGlobal.byte() => Ok(Kind::PAXGlobal),
            v if v == Kind::CharDevice.byte() => Ok(Kind::CharDevice),
            v if v == Kind::BlockDevice.byte() => Ok(Kind::BlockDevice),
            v if v == Kind::Fifo.byte() => Ok(Kind::Fifo),
            v if v == Kind::Continous.byte() => Ok(Kind::Continous),
            v => Err(v),
        }
    }
}

#[repr(C)]
#[allow(missing_docs)]
struct OldHeader {
    name: [u8; 100],
    mode: [u8; 8],
    uid: [u8; 8],
    gid: [u8; 8],
    size: [u8; 12],
    mtime: [u8; 12],
    cksum: [u8; 8],
    linkflag: [u8; 1],
    linkname: [u8; 100],
    pad: [u8; 255],
}
impl HeaderVariant for OldHeader {}
impl OldHeader {
    fn path_name(&self) -> Result<Box<str>> {
        path_name(&self.name).map(|p| p.to_string().into_boxed_str())
    }
    fn link_name(&self) -> Result<Box<str>> {
        path_name(&self.linkname).map(|p| p.to_string().into_boxed_str())
    }
}

const NAME_LEN: usize = 100;
const PREFIX_LEN: usize = 155;

#[repr(C)]
#[allow(missing_docs)]
struct UstarHeader {
    name: [u8; NAME_LEN],
    mode: [u8; 8],
    uid: [u8; 8],
    gid: [u8; 8],
    size: [u8; 12],
    mtime: [u8; 12],
    cksum: [u8; 8],
    typeflag: [u8; 1],
    linkname: [u8; NAME_LEN],
    magic: [u8; 6],
    version: [u8; 2],
    uname: [u8; 32],
    gname: [u8; 32],
    dev_major: [u8; 8],
    dev_minor: [u8; 8],
    prefix: [u8; PREFIX_LEN],
    pad: [u8; 12],
}
impl HeaderVariant for UstarHeader {}
impl UstarHeader {
    fn path_name(&self) -> Result<Box<str>> {
        ustar_path_name(&self.name, &self.prefix)
    }
    fn link_name(&self) -> Result<Box<str>> {
        path_name(&self.linkname).map(|p| p.to_string().into_boxed_str())
    }
    unsafe fn from_buf(buf: &mut [u8]) -> &mut Self {
        buf[..BLOCK_SIZE].fill(0);
        let hdr = &mut *(buf.as_mut_ptr() as *mut Self);
        hdr.magic = *b"ustar\0";
        hdr.version = *b"00";
        hdr
    }
    unsafe fn from_buf_no_init(buf: &mut [u8]) -> &mut Self {
        &mut *(buf.as_mut_ptr() as *mut Self)
    }
    fn set_dev_major(&mut self, major: u32) -> std::io::Result<()> {
        format_octal(major as u64, &mut self.dev_major)
    }
    fn set_dev_minor(&mut self, minor: u32) -> std::io::Result<()> {
        format_octal(minor as u64, &mut self.dev_minor)
    }
    fn set_uid(&mut self, uid: u32) -> std::io::Result<()> {
        format_octal(uid as u64, &mut self.uid)
    }
    fn set_gid(&mut self, gid: u32) -> std::io::Result<()> {
        format_octal(gid as u64, &mut self.gid)
    }
    fn set_mode(&mut self, mode: u32) -> std::io::Result<()> {
        format_octal(mode as u64, &mut self.mode)
    }
    fn set_mtime(&mut self, mtime: u32) -> std::io::Result<()> {
        format_octal(mtime as u64, &mut self.mtime)
    }
    fn set_size(&mut self, size: u64) -> std::io::Result<()> {
        format_octal(size, &mut self.size)
    }
    fn set_typeflag(&mut self, kind: Kind) {
        self.typeflag[0] = kind.byte();
    }
    fn path_split_point(&mut self, path: &str) -> Option<usize> {
        let bytes = path.as_bytes();
        if bytes.len() <= self.name.len() {
            return None;
        }
        bytes
            .iter()
            .enumerate()
            .rfind(|(i, b)| **b == b'/' && i <= &self.prefix.len())
            .map(|(i, _)| i)
    }
    fn set_path(&mut self, path: &str, split_pos: Option<usize>) {
        if let Some(pos) = split_pos {
            self.prefix[..pos].copy_from_slice(&path.as_bytes()[..pos]);
            copy_utf8_truncate(&mut self.name, unsafe {
                // SAFETY: the source string was an str, and a break, if any, was made at '/',
                // which is a valid codepoint
                std::str::from_utf8_unchecked(&path.as_bytes()[pos+1..])
            });
        } else {
            copy_utf8_truncate(&mut self.name, path);
        }
    }
    fn set_link_path(&mut self, name: &str) {
        copy_utf8_truncate(&mut self.linkname, name);
    }
    fn finalize(&mut self) -> std::io::Result<()> {
        self.cksum.fill(b' ');
        let buf =
            unsafe { std::slice::from_raw_parts(self as *const Self as *const u8, BLOCK_SIZE) };
        let checksum: u32 = buf.iter().map(|b| *b as u32).sum();
        format_octal(checksum as u64, &mut self.cksum)
    }
}

fn copy_utf8_truncate(field: &mut [u8], bytes: &str) {
    if bytes.len() <= field.len() {
        field[..bytes.len()].copy_from_slice(bytes.as_bytes());
        return;
    }
    let mut cut = 0;
    for (i, c) in bytes.char_indices() {
        if i <= field.len() {
            if c != '/' {
                cut = i;
            }
        } else {
            break;
        }
    }
    field[..cut].copy_from_slice(&bytes.as_bytes()[..cut]);
}

#[repr(C)]
#[allow(missing_docs)]
struct GnuHeader {
    name: [u8; 100],
    mode: [u8; 8],
    uid: [u8; 8],
    gid: [u8; 8],
    size: [u8; 12],
    mtime: [u8; 12],
    cksum: [u8; 8],
    typeflag: [u8; 1],
    linkname: [u8; 100],
    magic: [u8; 6],
    version: [u8; 2],
    uname: [u8; 32],
    gname: [u8; 32],
    dev_major: [u8; 8],
    dev_minor: [u8; 8],
    atime: [u8; 12],
    ctime: [u8; 12],
    offset: [u8; 12],
    longnames: [u8; 4],
    unused: [u8; 1],
    sparse: [u8; 96],
    isextended: [u8; 1],
    realsize: [u8; 12],
    pad: [u8; 17],
}
impl HeaderVariant for GnuHeader {}
impl GnuHeader {
    fn path_name(&self) -> Result<Box<str>> {
        path_name(&self.name).map(|p| p.to_string().into_boxed_str())
    }
    fn link_name(&self) -> Result<Box<str>> {
        path_name(&self.linkname).map(|p| p.to_string().into_boxed_str())
    }
}

enum Entry {
    File {
        path_name: Box<str>,
        size: u64,
        eof: u64,
        mode: u32,
        mtime: u32,
        uid: u32,
        gid: u32,
    },
    Link(TarLink),
    Symlink(TarSymlink),
    Directory(TarDirectory),
    Device(TarDevice),
    Fifo(TarFifo),
}

#[derive(Debug, PartialEq, Eq)]
enum State {
    Header,
    Extension((u32, Kind)),
    Entry,
    SkipEntry,
    Padding,
    Eof,
    Eoff,
}
use State::*;

struct PosixExtension {
    inner: Box<str>,
}
impl PosixExtension {
    fn iter(&self) -> PaxExtensionIter<'_> {
        PaxExtensionIter { ext: &self.inner }
    }
}
struct PaxExtensionIter<'a> {
    ext: &'a str,
}
impl<'a> Iterator for PaxExtensionIter<'a> {
    type Item = (&'a str, &'a str);
    fn next(&mut self) -> Option<Self::Item> {
        if self.ext.is_empty() {
            return None;
        }
        let space_pos = self.ext.find(' ')?;
        let len: usize = self.ext[..space_pos].parse().ok()?;
        let record = &self.ext[..len];
        self.ext = &self.ext[len..];
        let eq_pos = record.find('=')?;
        Some((&record[space_pos + 1..eq_pos], &record[eq_pos + 1..len - 1]))
    }
}

impl From<Box<str>> for PosixExtension {
    fn from(s: Box<str>) -> Self {
        Self { inner: s }
    }
}
impl std::ops::Deref for PosixExtension {
    type Target = str;
    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

enum ExtensionHeader {
    LongName(Box<str>),
    LongLink(Box<str>),
    PosixExtension(PosixExtension),
}

impl std::ops::Deref for ExtensionHeader {
    type Target = str;
    fn deref(&self) -> &Self::Target {
        match self {
            ExtensionHeader::LongName(name) => name,
            ExtensionHeader::LongLink(name) => name,
            ExtensionHeader::PosixExtension(pax) => pax,
        }
    }
}

struct ExtensionBuffer {
    buf: Vec<u8>,
}

impl ExtensionBuffer {
    fn new(size: usize) -> Self {
        ExtensionBuffer {
            buf: Vec::<u8>::with_capacity(size),
        }
    }
    fn as_str<I>(&self, range: I) -> Result<Box<str>>
    where
        I: core::slice::SliceIndex<[u8], Output = [u8]>,
    {
        from_utf8(&self.buf[range])
            .map_err(|_| Error::new(ErrorKind::InvalidData, "invalid UTF-8"))
            .map(|p| p.to_string().into_boxed_str())
    }
    fn as_null_terminated_str<I>(&self, range: I) -> Result<Box<str>>
    where
        I: core::slice::SliceIndex<[u8], Output = [u8]>,
    {
        from_utf8(null_terminated(&self.buf[range]))
            .map_err(|_| Error::new(ErrorKind::InvalidData, "invalid UTF-8"))
            .map(|p| p.to_string().into_boxed_str())
    }
    unsafe fn upto(&mut self, n: usize) -> &mut [u8] {
        std::slice::from_raw_parts_mut(self.buf.as_mut_ptr(), n)
    }
    unsafe fn remaining_buf(&mut self) -> &mut [u8] {
        let remaining = self.buf.spare_capacity_mut();
        std::slice::from_raw_parts_mut(remaining.as_mut_ptr() as *mut u8, remaining.len())
    }
    unsafe fn advance(&mut self, n: usize) {
        self.buf.set_len(self.buf.len() + n)
    }
}

pin_project! {
    /// Core state machine that walks the tar stream block-by-block.
    ///
    /// `pos` tracks how much of the current block has been consumed while
    /// `nxt` marks the boundary at which the next transition happens (end of
    /// header, file body, padding, etc.). The `state` enum plus the optional
    /// `ext` buffer describe what the reader is currently expecting: extension
    /// payloads, entry data that must be skipped, or archive EOF.
    struct TarReaderInner<'a, R> {
        // current position in the stream
        pos: u64,
        // end of the current record being processed
        nxt: u64,
        // current state
        state: State,
        // the buffer for the current extended header or for skipping a entry
        ext: Option<ExtensionBuffer>,
        // list of the current extended headers
        exts: Vec<ExtensionHeader>,
        // list of the global extended headers
        globs: Vec<PosixExtension>,
        // the current record buffer
        header: Header,
        #[pin]
        reader: R,
        marker: std::marker::PhantomData<&'a ()>,
    }
}

/// Async reader pointing at the body of the current file entry.
///
/// Instances are produced by [`TarReader`] and keep a handle to the shared
/// reader state so that dropping them early transparently skips the remaining
/// payload bytes.
pub struct TarRegularFileReader<'a, R: AsyncRead + 'a> {
    eof: u64,
    inner: Arc<Mutex<Pin<Box<TarReaderInner<'a, R>>>>>,
}

impl<R: AsyncRead> Drop for TarRegularFileReader<'_, R> {
    fn drop(&mut self) {
        let inner = self.inner.clone();
        let eof = self.eof;
        let mut g = inner.lock_blocking();
        let this_pin = g.as_mut();
        let this = this_pin.project();
        if *this.pos < eof {
            *this.state = SkipEntry;
        }
    }
}

impl<'a, R: AsyncRead> AsyncRead for TarRegularFileReader<'a, R> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        ctx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<Result<usize>> {
        let this = self.as_mut();
        let eof = this.eof;
        let fut = this.inner.lock();
        let mut g = task::ready!(pin!(fut).poll(ctx));
        let inner_pin: Pin<&mut TarReaderInner<'a, R>> = g.as_mut();
        let inner = inner_pin.project();
        tracing::trace!(
            target: "tar",
            "file.poll_read: buf.len={} pos={} eof={}",
            buf.len(),
            *inner.pos,
            eof
        );
        if *inner.pos >= eof {
            return Poll::Ready(Ok(0));
        }
        let remain = *inner.nxt - *inner.pos;
        let n = if remain > 0 {
            let size = std::cmp::min(remain, buf.len() as u64);
            let n = ready!(pin!(inner.reader).poll_read(ctx, &mut buf[0..size as usize]));
            if n == 0 {
                return Poll::Ready(Err(Error::new(
                    ErrorKind::UnexpectedEof,
                    "unexpected EOF while reading archie file",
                )));
            }
            n
        } else {
            0
        };
        *inner.pos += n as u64;
        Poll::Ready(Ok(if (n as u64) < remain {
            n
        } else {
            ctx.waker().wake_by_ref();
            let nxt = padded_size(*inner.nxt);
            if *inner.pos == nxt {
                *inner.nxt = nxt + BLOCK_SIZE as u64;
                *inner.state = Header;
            } else {
                *inner.nxt = nxt;
                *inner.state = Padding;
            }
            n
        }))
    }
}

/// Stream tar entries from an `AsyncRead` source.
pub struct TarReader<'a, R: AsyncRead + 'a> {
    inner: Arc<Mutex<Pin<Box<TarReaderInner<'a, R>>>>>,
}

impl<'a, R: AsyncRead + 'a> TarReader<'a, R> {
    /// Construct a streaming reader that yields [`TarEntry`] values.
    pub fn new(r: R) -> Self {
        Self {
            inner: Arc::new(Mutex::new(Box::pin(TarReaderInner::new(r)))),
        }
    }
}

/// Hard-link metadata entry.
pub struct TarLink {
    path_name: Box<str>,
    link_name: Box<str>,
}
impl<R: AsyncRead> From<TarLink> for TarEntry<'_, R> {
    fn from(link: TarLink) -> Self {
        Self::Link(link)
    }
}
impl TarLink {
    /// Create a hard-link entry.
    pub fn new<N: Into<Box<str>>, L: Into<Box<str>>>(path_name: N, link_name: L) -> TarLink {
        TarLink {
            path_name: path_name.into(),
            link_name: link_name.into(),
        }
    }
    pub fn path(&'_ self) -> &'_ str {
        &self.path_name
    }
    pub fn link(&'_ self) -> &'_ str {
        &self.link_name
    }
    fn write_header(&self, buffer: &mut [u8]) -> std::io::Result<usize> {
        write_header(
            buffer,
            self.path_name.as_ref(),
            Some(self.link_name.as_ref()),
            Kind::Link,
            0,    // size
            0,    // mode
            0,    // uid
            0,    // gid
            0,    // mtime
            None, // device
        )
    }
}
pub enum DeviceKind {
    Char,
    Block,
}

/// Block/char device metadata entry.
pub struct TarDevice {
    path_name: Box<str>,
    mode: u32,
    mtime: u32,
    uid: u32,
    gid: u32,
    kind: DeviceKind,
    major: u32,
    minor: u32,
}
impl<R: AsyncRead> From<TarDevice> for TarEntry<'_, R> {
    fn from(device: TarDevice) -> Self {
        Self::Device(device)
    }
}
impl TarDevice {
    /// Create a character device entry.
    pub fn new_char<N: Into<Box<str>>>(
        path_name: N,
        major: u32,
        minor: u32,
        uid: u32,
        gid: u32,
        mode: u32,
        mtime: u32,
    ) -> TarDevice {
        TarDevice {
            path_name: path_name.into(),
            mode,
            mtime,
            uid,
            gid,
            major,
            minor,
            kind: DeviceKind::Char,
        }
    }
    /// Create a block device entry.
    pub fn new_block<N: Into<Box<str>>>(
        path_name: N,
        major: u32,
        minor: u32,
        uid: u32,
        gid: u32,
        mode: u32,
        mtime: u32,
    ) -> TarDevice {
        TarDevice {
            path_name: path_name.into(),
            mode,
            mtime,
            uid,
            gid,
            major,
            minor,
            kind: DeviceKind::Block,
        }
    }
    pub fn path(&'_ self) -> &'_ str {
        &self.path_name
    }
    pub fn mode(&self) -> u32 {
        self.mode
    }
    pub fn mtime(&self) -> u32 {
        self.mtime
    }
    pub fn uid(&self) -> u32 {
        self.uid
    }
    pub fn gid(&self) -> u32 {
        self.gid
    }
    pub fn is_char(&self) -> bool {
        matches!(self.kind, DeviceKind::Char)
    }
    pub fn is_block(&self) -> bool {
        matches!(self.kind, DeviceKind::Block)
    }
    pub fn major(&self) -> u32 {
        self.major
    }
    pub fn minor(&self) -> u32 {
        self.minor
    }
    fn write_header(&self, buffer: &mut [u8]) -> std::io::Result<usize> {
        write_header(
            buffer,
            self.path_name.as_ref(),
            None,
            match self.kind {
                DeviceKind::Char => Kind::CharDevice,
                DeviceKind::Block => Kind::BlockDevice,
            },
            0, // size
            self.mode,
            self.uid,
            self.gid,
            self.mtime,
            Some((self.major, self.minor)),
        )
    }
}

/// FIFO (named pipe) entry.
pub struct TarFifo {
    path_name: Box<str>,
    mode: u32,
    mtime: u32,
    uid: u32,
    gid: u32,
}
impl<R: AsyncRead> From<TarFifo> for TarEntry<'_, R> {
    fn from(fifo: TarFifo) -> Self {
        Self::Fifo(fifo)
    }
}
impl TarFifo {
    /// Create a FIFO entry.
    pub fn new<N: Into<Box<str>>>(
        path_name: N,
        uid: u32,
        gid: u32,
        mode: u32,
        mtime: u32,
    ) -> TarFifo {
        TarFifo {
            path_name: path_name.into(),
            mode,
            mtime,
            uid,
            gid,
        }
    }
    pub fn path(&'_ self) -> &'_ str {
        &self.path_name
    }
    pub fn mode(&self) -> u32 {
        self.mode
    }
    pub fn mtime(&self) -> u32 {
        self.mtime
    }
    pub fn uid(&self) -> u32 {
        self.uid
    }
    pub fn gid(&self) -> u32 {
        self.gid
    }
    fn write_header(&self, buffer: &mut [u8]) -> std::io::Result<usize> {
        write_header(
            buffer,
            self.path_name.as_ref(),
            None,
            Kind::Fifo,
            0, // size
            self.mode,
            self.uid,
            self.gid,
            self.mtime,
            None, // device
        )
    }
}

/// Symbolic link entry containing its own metadata.
pub struct TarSymlink {
    path_name: Box<str>,
    link_name: Box<str>,
    mode: u32,
    mtime: u32,
    uid: u32,
    gid: u32,
}
impl<R: AsyncRead> From<TarSymlink> for TarEntry<'_, R> {
    fn from(symlink: TarSymlink) -> Self {
        Self::Symlink(symlink)
    }
}
impl TarSymlink {
    /// Create a symbolic link entry.
    pub fn new<N: Into<Box<str>>, L: Into<Box<str>>>(
        path_name: N,
        link_name: L,
        uid: u32,
        gid: u32,
        mode: u32,
        mtime: u32,
    ) -> TarSymlink {
        TarSymlink {
            path_name: path_name.into(),
            link_name: link_name.into(),
            mode,
            mtime,
            uid,
            gid,
        }
    }
    pub fn path(&'_ self) -> &'_ str {
        &self.path_name
    }
    pub fn link(&'_ self) -> &'_ str {
        &self.link_name
    }
    pub fn mode(&self) -> u32 {
        self.mode
    }
    pub fn mtime(&self) -> u32 {
        self.mtime
    }
    pub fn uid(&self) -> u32 {
        self.uid
    }
    pub fn gid(&self) -> u32 {
        self.gid
    }
    fn write_header(&self, buffer: &mut [u8]) -> std::io::Result<usize> {
        write_header(
            buffer,
            self.path_name.as_ref(),
            Some(self.link_name.as_ref()),
            Kind::Symlink,
            0, // size
            self.mode,
            self.uid,
            self.gid,
            self.mtime,
            None, // device
        )
    }
}

/// Directory metadata entry.
pub struct TarDirectory {
    path_name: Box<str>,
    mode: u32,
    mtime: u32,
    uid: u32,
    gid: u32,
    size: u64,
}
impl<R: AsyncRead> From<TarDirectory> for TarEntry<'_, R> {
    fn from(dir: TarDirectory) -> Self {
        Self::Directory(dir)
    }
}
impl TarDirectory {
    /// Create a directory entry.
    pub fn new<N: Into<Box<str>>>(
        path_name: N,
        uid: u32,
        gid: u32,
        mode: u32,
        mtime: u32,
    ) -> TarDirectory {
        TarDirectory {
            path_name: path_name.into(),
            size: 0,
            mode,
            mtime,
            uid,
            gid,
        }
    }
    pub fn path(&'_ self) -> &'_ str {
        &self.path_name
    }
    pub fn size(&self) -> u64 {
        self.size
    }
    pub fn mode(&self) -> u32 {
        self.mode
    }
    pub fn mtime(&self) -> u32 {
        self.mtime
    }
    pub fn uid(&self) -> u32 {
        self.uid
    }
    pub fn gid(&self) -> u32 {
        self.gid
    }
    fn write_header(&self, buffer: &mut [u8]) -> std::io::Result<usize> {
        write_header(
            buffer,
            self.path_name.as_ref(),
            None,
            Kind::Directory,
            self.size,
            self.mode,
            self.uid,
            self.gid,
            self.mtime,
            None, // device
        )
    }
}

pin_project! {
    /// Regular file entry paired with the reader that yields its payload.
    pub struct TarRegularFile<'a, R> {
        path_name: Box<str>,
        size: u64,
        mode: u32,
        mtime: u32,
        uid: u32,
        gid: u32,
        #[pin]
        inner: R,
        marker: std::marker::PhantomData<&'a ()>,
    }
}
impl<'a, R: AsyncRead + 'a> TarRegularFile<'a, R> {
    /// Build a regular file entry with the provided body reader.
    pub fn new<N: Into<Box<str>>>(
        path_name: N,
        size: u64,
        uid: u32,
        gid: u32,
        mode: u32,
        mtime: u32,
        inner: R,
    ) -> TarRegularFile<'a, R> {
        TarRegularFile {
            path_name: path_name.into(),
            size,
            mode,
            mtime,
            uid,
            gid,
            inner,
            marker: std::marker::PhantomData,
        }
    }
    pub fn size(&self) -> u64 {
        self.size
    }
    pub fn path(&'_ self) -> &'_ str {
        &self.path_name
    }
    pub fn mode(&self) -> u32 {
        self.mode
    }
    pub fn mtime(&self) -> u32 {
        self.mtime
    }
    pub fn uid(&self) -> u32 {
        self.uid
    }
    pub fn gid(&self) -> u32 {
        self.gid
    }
    fn write_header(&self, buffer: &mut [u8]) -> std::io::Result<usize> {
        write_header(
            buffer,
            self.path_name.as_ref(),
            None,
            Kind::File,
            self.size,
            self.mode,
            self.uid,
            self.gid,
            self.mtime,
            None, // device
        )
    }
}
impl<'a, R: AsyncRead + 'a> From<TarRegularFile<'a, R>> for TarEntry<'a, R> {
    fn from(file: TarRegularFile<'a, R>) -> Self {
        Self::File(file)
    }
}
/// High-level representation of an entry yielded by [`TarReader`].
pub enum TarEntry<'a, R: AsyncRead + 'a> {
    File(TarRegularFile<'a, R>),
    Link(TarLink),
    Symlink(TarSymlink),
    Directory(TarDirectory),
    Device(TarDevice),
    Fifo(TarFifo),
}

impl<'a, R: AsyncRead + 'a> TarEntry<'a, R> {
    fn write_header(&self, buffer: &mut [u8]) -> std::io::Result<usize> {
        match self {
            Self::Directory(dir) => dir.write_header(buffer),
            Self::Device(device) => device.write_header(buffer),
            Self::Fifo(fifo) => fifo.write_header(buffer),
            Self::File(file) => file.write_header(buffer),
            Self::Link(link) => link.write_header(buffer),
            Self::Symlink(symlink) => symlink.write_header(buffer),
        }
    }
}

impl<'a, R: AsyncRead + 'a> std::fmt::Debug for TarEntry<'a, R> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::File(file) => f
                .debug_struct("TarEntry::File")
                .field("path_name", &file.path_name)
                .field("size", &file.size)
                .field("mode", &file.mode)
                .field("mtime", &file.mtime)
                .field("uid", &file.uid)
                .field("gid", &file.gid)
                .finish(),
            Self::Device(device) => f
                .debug_struct("TarEntry::Device")
                .field("path_name", &device.path_name)
                .field("mode", &device.mode)
                .field("mtime", &device.mtime)
                .field("uid", &device.uid)
                .field("gid", &device.gid)
                .field(
                    "kind",
                    match device.kind {
                        DeviceKind::Char => &"char",
                        DeviceKind::Block => &"block",
                    },
                )
                .field("major", &device.major)
                .field("minor", &device.minor)
                .finish(),
            Self::Fifo(fifo) => f
                .debug_struct("TarEntry::Fifo")
                .field("path_name", &fifo.path_name)
                .field("mode", &fifo.mode)
                .field("mtime", &fifo.mtime)
                .field("uid", &fifo.uid)
                .field("gid", &fifo.gid)
                .finish(),
            Self::Link(link) => f
                .debug_struct("TarEntry::Link")
                .field("path_name", &link.path_name)
                .field("link_name", &link.link_name)
                .finish(),
            Self::Symlink(symlink) => f
                .debug_struct("TarEntry::Symlink")
                .field("path_name", &symlink.path_name)
                .field("link_name", &symlink.link_name)
                .field("mode", &symlink.mode)
                .field("mtime", &symlink.mtime)
                .field("uid", &symlink.uid)
                .field("gid", &symlink.gid)
                .finish(),
            Self::Directory(dir) => f
                .debug_struct("TarEntry::Directory")
                .field("path_name", &dir.path_name)
                .field("size", &dir.size)
                .field("mode", &dir.mode)
                .field("mtime", &dir.mtime)
                .field("uid", &dir.uid)
                .field("gid", &dir.gid)
                .finish(),
        }
    }
}

fn entry_name(hdr: &Header, exts: &mut Vec<ExtensionHeader>) -> Result<Box<str>> {
    let long_path = exts.drain(..).fold(None, |p, e| match e {
        ExtensionHeader::LongName(name) => Some(name),
        ExtensionHeader::PosixExtension(ext) => {
            for (key, val) in ext.iter() {
                tracing::trace!(target: "tar", "PAX ext key={} val={}", key, val);
                if key == "path" {
                    return Some(val.to_string().into_boxed_str());
                }
            }
            p
        }
        _ => p,
    });
    tracing::trace!(target: "tar", "long_path={:?}", long_path);
    match hdr.kind() {
        HeaderKind::Gnu(hdr) => Ok(long_path.map_or_else(|| hdr.path_name(), Ok)?),
        HeaderKind::Ustar(hdr) => Ok(long_path.map_or_else(|| hdr.path_name(), Ok)?),
        HeaderKind::Old(hdr) => hdr.path_name(),
    }
}
fn entry_name_link(hdr: &Header, exts: &mut Vec<ExtensionHeader>) -> Result<(Box<str>, Box<str>)> {
    let (long_path, long_link) = exts.drain(..).fold((None, None), |(p, l), e| match e {
        ExtensionHeader::LongName(name) => (Some(name), l),
        ExtensionHeader::LongLink(name) => (p, Some(name)),
        ExtensionHeader::PosixExtension(ext) => {
            let mut np = p;
            let mut nl = l;
            for (key, val) in ext.iter() {
                if key == "path" {
                    np = Some(val.to_string().into_boxed_str());
                } else if key == "linkpath" {
                    nl = Some(val.to_string().into_boxed_str());
                }
            }
            (np, nl)
        }
    });
    match hdr.kind() {
        HeaderKind::Gnu(hdr) => Ok((
            long_path.map_or_else(|| hdr.path_name(), Ok)?,
            long_link.map_or_else(|| hdr.link_name(), Ok)?,
        )),
        HeaderKind::Ustar(hdr) => Ok((
            long_path.map_or_else(|| hdr.path_name(), Ok)?,
            long_link.map_or_else(|| hdr.link_name(), Ok)?,
        )),
        HeaderKind::Old(hdr) => Ok((hdr.path_name()?, hdr.link_name()?)),
    }
}

fn ext_as_path(hdr: &Header, size: usize, ext: &Option<ExtensionBuffer>) -> Result<Box<str>> {
    if size <= BLOCK_SIZE {
        hdr.as_null_terminated_str(..size)
    } else {
        ext.as_ref().unwrap().as_null_terminated_str(..size)
    }
}
fn ext_as_str(hdr: &Header, size: usize, ext: &Option<ExtensionBuffer>) -> Result<Box<str>> {
    if size <= BLOCK_SIZE {
        hdr.as_str(..size)
    } else {
        ext.as_ref().unwrap().as_str(..size)
    }
    .map(|p| p.to_string().into_boxed_str())
}

impl<'a, R: AsyncRead + 'a> TarReaderInner<'a, R> {
    fn new(r: R) -> Self {
        Self {
            state: Header,
            pos: 0,
            nxt: BLOCK_SIZE as u64,
            ext: None,
            exts: Vec::new(),
            globs: Vec::new(),
            header: Header::new(),
            reader: r,
            marker: std::marker::PhantomData,
        }
    }
    /// Advance the state machine until the next entry or EOF marker is decoded.
    fn poll_read_header(
        self: Pin<&mut Self>,
        ctx: &mut Context<'_>,
    ) -> Poll<Option<Result<Entry>>> {
        let mut this = self.project();
        loop {
            tracing::trace!(
                target: "tar",
                "tar.poll_read_header: state={:?} pos={} nxt={}",
                *this.state, *this.pos, *this.nxt
            );
            match this.state {
                Header => {
                    let remaining = *this.nxt - *this.pos;
                    let n = {
                        let filled = BLOCK_SIZE - remaining as usize;
                        let (hdr, reader) = (&mut this.header, &mut this.reader);
                        let n = ready_opt!(pin!(reader).poll_read(ctx, hdr.buf_mut(filled..)));
                        if n == 0 {
                            Err(Error::new(
                                ErrorKind::UnexpectedEof,
                                "Unexpected EOF while reading tar header",
                            ))
                        } else {
                            Ok(n)
                        }
                    }?;
                    *this.pos += n as u64;
                    if remaining != n as u64 {
                        continue;
                    }
                    if this.header.is_zero() {
                        *this.nxt += BLOCK_SIZE as u64;
                        *this.state = Eof;
                        continue;
                    }
                    let kind = this.header.entry_type().map_err(|t| {
                        Error::new(
                            ErrorKind::InvalidData,
                            format!("header type {} is not supported", t),
                        )
                    })?;
                    return Poll::Ready(Some(match kind {
                        Kind::File | Kind::File0 | Kind::Continous => {
                            let size = this.header.size()?;
                            let path_name = entry_name(this.header, this.exts)?;
                            Ok(if path_name.ends_with('/') && this.header.is_old() {
                                *this.nxt += BLOCK_SIZE as u64;
                                *this.state = Header;
                                Entry::Directory(TarDirectory {
                                    size,
                                    mode: this.header.mode()?,
                                    mtime: this.header.mtime()?,
                                    uid: this.header.uid()?,
                                    gid: this.header.gid()?,
                                    path_name,
                                })
                            } else {
                                *this.nxt += size;
                                *this.state = Entry;
                                Entry::File {
                                    size,
                                    mode: this.header.mode()?,
                                    mtime: this.header.mtime()?,
                                    uid: this.header.uid()?,
                                    gid: this.header.gid()?,
                                    eof: *this.nxt,
                                    path_name,
                                }
                            })
                        }
                        Kind::Directory => {
                            let size = this.header.size()?;
                            *this.nxt += BLOCK_SIZE as u64;
                            *this.state = Header;
                            let path_name = entry_name(this.header, this.exts)?;
                            Ok(Entry::Directory(TarDirectory {
                                size,
                                mode: this.header.mode()?,
                                mtime: this.header.mtime()?,
                                uid: this.header.uid()?,
                                gid: this.header.gid()?,
                                path_name,
                            }))
                        }
                        Kind::Fifo => {
                            *this.nxt += BLOCK_SIZE as u64;
                            *this.state = Header;
                            let path_name = entry_name(this.header, this.exts)?;
                            Ok(Entry::Fifo(TarFifo {
                                path_name,
                                mode: this.header.mode()?,
                                mtime: this.header.mtime()?,
                                uid: this.header.uid()?,
                                gid: this.header.gid()?,
                            }))
                        }
                        Kind::CharDevice | Kind::BlockDevice => {
                            *this.nxt += BLOCK_SIZE as u64;
                            *this.state = Header;
                            let path_name = entry_name(this.header, this.exts)?;
                            Ok(Entry::Device(TarDevice {
                                path_name,
                                mode: this.header.mode()?,
                                mtime: this.header.mtime()?,
                                uid: this.header.uid()?,
                                gid: this.header.gid()?,
                                kind: match kind {
                                    Kind::CharDevice => DeviceKind::Char,
                                    Kind::BlockDevice => DeviceKind::Block,
                                    _ => unreachable!(),
                                },
                                major: this.header.dev_major()?,
                                minor: this.header.dev_minor()?,
                            }))
                        }
                        Kind::Link => {
                            *this.nxt += BLOCK_SIZE as u64;
                            *this.state = Header;
                            let (path_name, link_name) = entry_name_link(this.header, this.exts)?;
                            Ok(Entry::Link(TarLink {
                                path_name,
                                link_name,
                            }))
                        }
                        Kind::Symlink => {
                            *this.nxt += BLOCK_SIZE as u64;
                            *this.state = Header;
                            let (path_name, link_name) = entry_name_link(this.header, this.exts)?;
                            Ok(Entry::Symlink(TarSymlink {
                                mode: this.header.mode()?,
                                mtime: this.header.mtime()?,
                                uid: this.header.uid()?,
                                gid: this.header.gid()?,
                                path_name,
                                link_name,
                            }))
                        }
                        Kind::PAXLocal | Kind::PAXGlobal if this.header.is_ustar() => {
                            let size = this.header.size().and_then(|size| {
                                if size as usize > PAX_HEADER_MAX_SIZE {
                                    Err(Error::new(
                                        ErrorKind::InvalidData,
                                        format!(
                                            "PAX extnesion exceeds {PAX_HEADER_MAX_SIZE} bytes"
                                        ),
                                    ))
                                } else {
                                    Ok(size as usize)
                                }
                            })?;
                            *this.state = Extension((size as u32, kind));
                            let padded = padded_size(size as u64);
                            *this.nxt += padded;
                            if size > BLOCK_SIZE {
                                this.ext.replace(ExtensionBuffer::new(padded as usize));
                            }
                            continue;
                        }
                        Kind::GNULongName | Kind::GNULongLink if this.header.is_gnu() => {
                            let size = this.header.size().and_then(|size| {
                                if size as usize > PATH_MAX {
                                    Err(Error::new(
                                        ErrorKind::InvalidData,
                                        format!("long filename exceeds {PATH_MAX} bytes"),
                                    ))
                                } else {
                                    Ok(size as usize)
                                }
                            })?;
                            *this.state = Extension((size as u32, kind));
                            let padded = padded_size(size as u64);
                            *this.nxt += padded;
                            if size > BLOCK_SIZE {
                                this.ext.replace(ExtensionBuffer::new(padded as usize));
                            }
                            continue;
                        }
                        kind => Err(Error::new(
                            ErrorKind::InvalidData,
                            format!("invalid tar entry header {}", kind),
                        )),
                    }));
                }
                Extension((size, kind)) => {
                    let (ext, reader) = (&mut this.ext, &mut this.reader);
                    let n = if *size as usize <= BLOCK_SIZE {
                        let remaining = *this.nxt - *this.pos;
                        let filled = BLOCK_SIZE - remaining as usize;
                        let (hdr, reader) = (&mut this.header, &mut this.reader);
                        ready_opt!(pin!(reader).poll_read(ctx, hdr.buf_mut(filled..)))
                    } else {
                        let buf = ext.as_mut().unwrap();
                        let n =
                            ready_opt!(pin!(reader).poll_read(ctx, unsafe { buf.remaining_buf() }));
                        unsafe { buf.advance(n) };
                        n
                    };
                    *this.pos += if n == 0 {
                        Err(Error::new(
                            ErrorKind::UnexpectedEof,
                            "unexpected end of tar file",
                        ))
                    } else {
                        Ok(n as u64)
                    }?;
                    if *this.pos == *this.nxt {
                        match kind {
                            Kind::GNULongName => this.exts.push(ExtensionHeader::LongName(
                                ext_as_path(this.header, *size as usize, ext)?,
                            )),
                            Kind::GNULongLink => this.exts.push(ExtensionHeader::LongLink(
                                ext_as_path(this.header, *size as usize, ext)?,
                            )),
                            Kind::PAXLocal => this.exts.push(ExtensionHeader::PosixExtension(
                                ext_as_str(this.header, *size as usize, ext)?.into(),
                            )),
                            Kind::PAXGlobal => this
                                .globs
                                .push(ext_as_str(this.header, *size as usize, ext)?.into()),
                            _ => unreachable!(),
                        };
                        *this.nxt += BLOCK_SIZE as u64;
                        *this.state = Header;
                    }
                    continue;
                }
                Padding => {
                    let remaining = *this.nxt - *this.pos;
                    let (hdr, reader) = (&mut this.header, &mut this.reader);
                    let n = match ready_opt!(
                        pin!(reader).poll_read(ctx, hdr.buf_mut(..remaining as usize))
                    ) {
                        0 => Err(Error::new(
                            ErrorKind::UnexpectedEof,
                            "unexpected end of tar file",
                        )),
                        n => Ok(n as u64),
                    }?;
                    *this.pos += n;
                    if remaining == n {
                        *this.nxt = *this.pos + BLOCK_SIZE as u64;
                        *this.state = Header;
                    }
                    continue;
                }
                Entry => {
                    // there is a file entry that must be either dropped or
                    // read fully to move further
                    return Poll::Pending;
                }
                SkipEntry => {
                    // skipping a entry
                    let nxt = padded_size(*this.nxt);
                    let remaining =
                        std::cmp::min(SKIP_BUFFER_SIZE as u64, nxt - *this.pos) as usize;
                    let n = if remaining > 0 {
                        let buf = if let Some(buf) = this.ext.as_mut() {
                            buf
                        } else {
                            this.ext.replace(ExtensionBuffer::new(SKIP_BUFFER_SIZE));
                            this.ext.as_mut().unwrap()
                        };
                        let reader = &mut this.reader;
                        match ready_opt!(pin!(reader).poll_read(ctx, unsafe { buf.upto(remaining) }))
                        {
                            0 => Err(Error::new(
                                ErrorKind::UnexpectedEof,
                                "unexpected end of tar file",
                            )),

                            n => Ok(n as u64),
                        }
                    } else {
                        Ok(0)
                    }?;
                    *this.pos += n;
                    if *this.pos == nxt {
                        this.ext.take();
                        *this.nxt = *this.pos + BLOCK_SIZE as u64;
                        *this.state = Header;
                    }
                    continue;
                }
                Eof => {
                    let remaining = *this.nxt - *this.pos;
                    let filled = BLOCK_SIZE - remaining as usize;
                    let (hdr, reader) = (&mut this.header, &mut this.reader);
                    let n = match ready_opt!(pin!(reader).poll_read(ctx, hdr.buf_mut(filled..))) {
                        0 => Err(Error::new(
                            ErrorKind::UnexpectedEof,
                            "unexpected end of tar file",
                        )),
                        n => Ok(n as u64),
                    }?;
                    *this.pos += n;
                    if remaining > n {
                        continue;
                    }
                    return Poll::Ready(if hdr.is_zero() {
                        *this.state = Eoff;
                        None
                    } else {
                        *this.state = Eoff;
                        Some(Err(Error::new(
                            ErrorKind::InvalidData,
                            "unexpected data after first zero block",
                        )))
                    });
                }
                Eoff => {
                    return Poll::Ready(Some(Err(Error::new(
                        ErrorKind::InvalidData,
                        "unexpected read after EOF",
                    ))));
                }
            }
        }
    }
}

impl<'a, R: AsyncRead + 'a> Stream for TarReader<'a, R> {
    type Item = Result<TarEntry<'a, TarRegularFileReader<'a, R>>>;
    fn poll_next(mut self: Pin<&mut Self>, ctx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.as_mut();
        let fut = this.inner.lock();
        let mut g = task::ready!(pin!(fut).poll(ctx));
        let inner: Pin<&mut TarReaderInner<R>> = g.as_mut();
        let entry = {
            match inner.poll_next(ctx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(None) => return Poll::Ready(None),
                Poll::Ready(Some(Err(err))) => return Poll::Ready(Some(Err(err))),
                Poll::Ready(Some(Ok(data))) => data,
            }
        };
        Poll::Ready(Some(Ok(match entry {
            Entry::File {
                size,
                mode,
                mtime,
                uid,
                gid,
                eof,
                path_name,
            } => TarEntry::File(TarRegularFile {
                path_name,
                size,
                mode,
                mtime,
                uid,
                gid,
                inner: TarRegularFileReader {
                    eof,
                    inner: Arc::clone(&this.inner),
                },
                marker: std::marker::PhantomData,
            }),
            Entry::Directory(d) => TarEntry::Directory(d),
            Entry::Link(l) => TarEntry::Link(l),
            Entry::Symlink(l) => TarEntry::Symlink(l),
            Entry::Device(d) => TarEntry::Device(d),
            Entry::Fifo(f) => TarEntry::Fifo(f),
        })))
    }
}

impl<'a, R: AsyncRead + 'a> Stream for TarReaderInner<'a, R> {
    type Item = Result<Entry>;
    fn poll_next(mut self: Pin<&mut Self>, ctx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.as_mut().poll_read_header(ctx)
    }
}
impl<'a, R: AsyncRead + 'a> TarEntry<'a, R> {
    /// Path of the entry regardless of concrete variant.
    pub fn path(&'_ self) -> &'_ str {
        match self {
            Self::File(f) => &f.path_name,
            Self::Link(l) => &l.path_name,
            Self::Symlink(l) => &l.path_name,
            Self::Directory(d) => &d.path_name,
            Self::Device(d) => &d.path_name,
            Self::Fifo(f) => &f.path_name,
        }
    }
}

impl<'a, R: AsyncRead + 'a> AsyncRead for TarRegularFile<'a, R> {
    fn poll_read(
        self: Pin<&mut Self>,
        ctx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<std::io::Result<usize>> {
        let this = self.project();
        pin!(this.inner).poll_read(ctx, buf)
    }
}

fn null_terminated(bytes: &[u8]) -> &[u8] {
    &bytes[..bytes
        .iter()
        .position(|b| *b == b'\0')
        .unwrap_or(bytes.len())]
}

fn ustar_path_name(name: &[u8; 100], prefix: &[u8; 155]) -> Result<Box<str>> {
    let (mut size, prefix) = if prefix[0] != b'\0' {
        let prefix = path_name(prefix)?;
        (prefix.len() + 1, Some(prefix))
    } else {
        (0, None)
    };
    let name = path_name(name)?;
    size += name.len();
    let mut path = String::with_capacity(size);
    if let Some(prefix) = prefix {
        path.push_str(prefix);
        path.push('/');
    }
    path.push_str(name);
    Ok(path.into_boxed_str())
}
fn path_name(name: &'_ [u8]) -> Result<&'_ str> {
    from_utf8(null_terminated(name))
        .map_err(|_| Error::new(ErrorKind::InvalidData, "invalid utf8 in file path"))
}

fn parse_octal(field: &'_ [u8]) -> std::result::Result<u64, &'_ [u8]> {
    let mut n = 0u64;
    let mut rest = field;
    while let [d, r @ ..] = rest {
        if d == &0 || d == &b' ' {
            break;
        }
        if !(&b'0'..=&b'7').contains(&d) {
            return Err(field);
        }
        rest = r;
        if d == &b'0' && n == 0 {
            continue;
        }
        n = (n << 3) | (u64::from(*d) - u64::from(b'0'));
    }
    Ok(n)
}

const fn padded_size(n: u64) -> u64 {
    if n == 0 {
        0
    } else {
        n.saturating_add(511) & !511
    }
}

#[allow(clippy::too_many_arguments)]
/// Write a single header (plus optional PAX prefix) into `buffer`.
///
/// The function encodes metadata using the ustar layout and, if either the path
/// or link name is too long, prepends a minimal PAX header that stores the full
/// value before duplicating the original header so downstream tools can still
/// read the entry.
fn write_header(
    buffer: &mut [u8],
    name: &str,
    link_name: Option<&str>,
    kind: Kind,
    size: u64,
    mode: u32,
    uid: u32,
    gid: u32,
    mtime: u32,
    device: Option<(u32, u32)>,
) -> std::io::Result<usize> {
    if buffer.len() < BLOCK_SIZE {
        return Err(std::io::Error::other("buffer too small for tar header"));
    }
    let (header_buf, data_buf) = buffer.split_at_mut(BLOCK_SIZE);
    let header = unsafe { UstarHeader::from_buf(header_buf) };
    let mut total = BLOCK_SIZE;

    let split_pos = header.path_split_point(name);
    tracing::trace!(
        target: "tar",
        "write_header: name={} split_pos={:?}",
        name,
        split_pos
    );
    let path_truncated = if let Some(pos) = split_pos {
        name.len() - pos - 1 > NAME_LEN
    } else {
        name.len() > NAME_LEN
    };
    let link_path_truncated = link_name
        .as_ref()
        .is_some_and(|link_name| link_name.len() > NAME_LEN);

    if !path_truncated && !link_path_truncated {
        header.set_uid(uid)?;
        header.set_gid(gid)?;
        header.set_mode(mode)?;
        header.set_mtime(mtime)?;
        header.set_size(size)?;
        header.set_path(name, split_pos);
        if let Some(link_name) = link_name {
            header.set_link_path(link_name);
        }
        if let Some((major, minor)) = device {
            header.set_dev_major(major)?;
            header.set_dev_minor(minor)?;
        }
        header.set_typeflag(kind);
        header.finalize()?;
    } else {
        use std::io::Write;
        header.set_typeflag(Kind::PAXLocal);
        header.set_path("././@PaxHeader", None);
        header.set_uid(0)?;
        header.set_gid(0)?;
        header.set_mode(0)?;
        header.set_mtime(0)?;
        let mut ext_size = 0;
        if path_truncated {
            let rec_len = pax_record_len("path", name.len());
            if data_buf.len() < rec_len {
                return Err(std::io::Error::other("buffer too small for pax header"));
            }
            writeln!(
                &mut data_buf[ext_size..rec_len],
                "{} path={}",
                rec_len,
                name
            )?;
            ext_size += rec_len;
        }
        if link_path_truncated {
            let name = link_name.unwrap();
            let rec_len = pax_record_len("linkpath", name.len());
            if data_buf.len() < ext_size + rec_len {
                return Err(std::io::Error::other("buffer too small for pax header"));
            }
            writeln!(
                &mut data_buf[ext_size..ext_size + rec_len],
                "{} linkpath={}",
                rec_len,
                name
            )?;
            ext_size += rec_len;
        }
        header.set_size(ext_size as u64)?;
        header.finalize()?;
        let padded = padded_size(ext_size as u64);
        if data_buf.len() < padded as usize {
            return Err(std::io::Error::other("buffer too small for pax header"));
        }
        data_buf[ext_size..padded as usize].fill(0);
        total += padded as usize;
        if data_buf.len() < padded as usize + BLOCK_SIZE {
            return Err(std::io::Error::other("buffer too small for pax header"));
        }
        let header = unsafe {
            UstarHeader::from_buf(
                &mut data_buf[padded as usize..padded as usize + BLOCK_SIZE],
            )
        };
        total += BLOCK_SIZE;
        header.set_uid(uid)?;
        header.set_gid(gid)?;
        header.set_mode(mode)?;
        header.set_mtime(mtime)?;
        header.set_size(size)?;
        header.set_typeflag(kind);
        header.set_size(size)?;
        header.set_path(name, split_pos);
        if let Some(link_name) = link_name {
            header.set_link_path(link_name);
        }
        if let Some((major, minor)) = device {
            header.set_dev_major(major)?;
            header.set_dev_minor(minor)?;
        }
        header.finalize()?;
    }
    Ok(total)
}

fn pax_record_len(key: &str, val_len: usize) -> usize {
    // <LEN> SP <KEY>=<VALUE>\n
    let payload_len = key.len() + 1 + val_len + 1;
    let mut len = payload_len + 1 + 1;
    loop {
        let d = num_decimal_digits(len);
        let new_len = payload_len + 1 + d;

        if new_len == len {
            return len;
        }
        len = new_len;
    }
}
#[inline]
fn num_decimal_digits(mut n: usize) -> usize {
    let mut c = 1;
    while n >= 10 {
        n /= 10;
        c += 1;
    }
    c
}

fn format_octal(val: u64, field: &mut [u8]) -> std::io::Result<()> {
    let mut value = val;
    let mut len = field.len() - 1;
    field[len] = 0; // null terminator
    while len > 0 {
        len -= 1;
        field[len] = b'0' + (value & 0o7) as u8;
        value >>= 3;
    }
    if value != 0 {
        return Err(std::io::Error::other(format!(
            "value {} too large to fit in octal field of len {}",
            val,
            field.len()
        )));
    }
    Ok(())
}

pin_project! {
    /// Streaming tar writer that implements `Sink<TarEntry>`.
    ///
    /// Headers and file payloads are staged inside `buf` until downstream I/O
    /// makes progress, which keeps memory usage predictable while preserving
    /// proper block alignment.
    pub struct TarWriter<'a, 'b, W, R> {
        // internal buffer for writing headers and file data
        buf: [u8; BLOCK_SIZE * 32],
        // length of valid data in the buffer
        len: usize,
        // current position in the buffer
        pos: usize,
        // current global position (number of bytes written)
        total: u64,
        // the end position of the current entry being written
        eof: u64,
        // closed
        closed: bool,
        // reader for the current file being written
        reader: Option<R>,
        marker_: std::marker::PhantomData<&'b ()>,
        // the underlying writer
        #[pin]
        writer: W,
        marker: std::marker::PhantomData<&'a ()>,
    }
}

impl<'a, 'b, W: AsyncWrite + 'a, R: AsyncRead + Unpin + 'b> TarWriter<'a, 'b, W, R> {
    /// Create a writer that targets the provided `AsyncWrite`.
    pub fn new(writer: W) -> Self {
        Self {
            buf: [0; BLOCK_SIZE * 32],
            len: 0,
            pos: 0,
            total: 0,
            eof: 0,
            closed: false,
            reader: None,
            marker_: std::marker::PhantomData,
            writer,
            marker: std::marker::PhantomData,
        }
    }

    /// Drain internal buffer and current file reader to the underlying writer.
    ///
    /// The method alternates between flushing buffered headers, consuming the
    /// reader for the active file, and emitting zero padding so the next entry
    /// always starts on a block boundary.
    fn poll_drain(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let mut this = self.project();
        loop {
            tracing::trace!(
                target: "tar",
                "tar_writer.poll_drain, len = {}, pos = {}, total = {}, eof = {}, reader is {}",
                *this.len,
                *this.pos,
                *this.total,
                *this.eof,
                if this.reader.is_some() {
                    "Some"
                } else {
                    "None"
                }
            );
            while *this.pos < *this.len {
                let n = task::ready!(this
                    .writer
                    .as_mut()
                    .poll_write(cx, &this.buf[*this.pos..*this.len]))?;
                if n == 0 {
                    return Poll::Ready(Err(std::io::Error::new(
                        std::io::ErrorKind::WriteZero,
                        "error writing buffer",
                    )));
                }
                *this.pos += n;
                *this.total += n as u64;
            }

            *this.pos = 0;
            *this.len = 0;

            if let Some(reader) = this.reader.as_mut() {
                let remain = this.eof.saturating_sub(*this.total);
                if remain == 0 {
                    *this.reader = None;
                    let padded = padded_size(*this.eof);
                    let padding = padded.saturating_sub(*this.eof);
                    tracing::trace!(
                        target: "tar",
                        "tar_writer.poll_drain: reader EOF reached, total = {}, eof = {}, padding = {}",
                        *this.total, *this.eof, padding
                    );
                    if padding > 0 {
                        *this.len = padding as usize;
                        this.buf[..*this.len].fill(0);
                        *this.eof = padded;
                        continue;
                    } else {
                        return Poll::Ready(Ok(()));
                    }
                }
                let buf_len = std::cmp::min(this.buf.len() as u64, remain) as usize;
                let n = task::ready!(pin!(reader).poll_read(cx, &mut this.buf[..buf_len]))?;
                if n == 0 {
                    return Poll::Ready(Err(std::io::Error::new(
                        std::io::ErrorKind::UnexpectedEof,
                        "unexpected EOF while reading file",
                    )));
                }
                *this.pos = 0;
                *this.len = n;
                continue;
            } else {
                return Poll::Ready(Ok(()));
            }
        }
    }
}

impl<'a, 'b, W: AsyncWrite + 'a, R: AsyncRead + Unpin + 'b> Sink<TarEntry<'b, R>>
    for TarWriter<'a, 'b, W, R>
{
    type Error = std::io::Error;

    fn poll_ready(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        self.poll_drain(cx)
    }

    fn start_send(self: Pin<&mut Self>, item: TarEntry<'b, R>) -> std::io::Result<()> {
        let this = self.project();

        if *this.len != 0 || this.reader.is_some() {
            return Err(std::io::Error::other(
                "start_send called while previous entry still in progress",
            ));
        }

        let header_len = item.write_header(this.buf)?;
        *this.len = header_len;

        if let TarEntry::File(file) = item {
            this.reader.replace(file.inner);
            *this.eof = *this.total + (header_len as u64) + file.size;
        }

        Ok(())
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        task::ready!(self.as_mut().poll_drain(cx))?;
        let mut this = self.project();
        task::ready!(this.writer.as_mut().poll_flush(cx))?;
        Poll::Ready(Ok(()))
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        task::ready!(self.as_mut().poll_drain(cx))?;
        {
            let this = self.as_mut().project();
            if !*this.closed {
                this.buf[..BLOCK_SIZE * 2].fill(0);
                *this.len = BLOCK_SIZE * 2;
                *this.closed = true;
            }
        }
        task::ready!(self.as_mut().poll_drain(cx))?;
        let mut this = self.project();
        this.writer.as_mut().poll_close(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use static_assertions::{assert_eq_align, assert_eq_size, assert_impl_all, assert_obj_safe};

    assert_impl_all!(TarReader<smol::fs::File>: Send, Sync);
    assert_impl_all!(TarEntry<smol::fs::File>: Send, Sync);
    assert_obj_safe!(TarReader<smol::fs::File>);
    assert_obj_safe!(TarEntry<smol::fs::File>);

    assert_eq_align!(Header, GnuHeader);
    assert_eq_size!(Header, GnuHeader);
    assert_eq_align!(Header, UstarHeader);
    assert_eq_size!(Header, UstarHeader);
    assert_eq_align!(Header, OldHeader);
    assert_eq_size!(Header, OldHeader);
}
