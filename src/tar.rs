use {
    async_lock::Mutex,
    futures_lite::{io::AsyncRead, Stream},
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
    Directory = b'5',
    GNULongLink = b'K',
    GNULongName = b'L',
    PAXLocal = b'x',
    PAXGlobal = b'g',
}
impl std::fmt::Display for Kind {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.write_str(match self {
            Self::File | Self::File0 => "regular file",
            Self::Link => "link",
            Self::Symlink => "symlink",
            Self::Directory => "directory",
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
            v if v == Kind::GNULongLink.byte() => Ok(Kind::GNULongName),
            v if v == Kind::PAXLocal.byte() => Ok(Kind::PAXLocal),
            v if v == Kind::PAXGlobal.byte() => Ok(Kind::PAXGlobal),
            v => Err(v),
        }
    }
}

/// Representation of the header of an entry in an archive
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

/// Representation of the header of an entry in an archive
#[repr(C)]
#[allow(missing_docs)]
struct UstarHeader {
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
    prefix: [u8; 155],
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
}

/// Representation of the header of an entry in an archive
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
}

#[derive(Debug, PartialEq, Eq)]
enum State {
    Header,
    Extension((u32, Kind)),
    Entry,
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

pub struct TarReader<'a, R: AsyncRead + Send + 'a> {
    inner: Arc<Mutex<Pin<Box<TarReaderInner<'a, R>>>>>,
}

impl<'a, R: AsyncRead + Send + 'a> TarReader<'a, R> {
    pub fn new(r: R) -> Self {
        Self {
            inner: Arc::new(Mutex::new(Box::pin(TarReaderInner::new(r)))),
        }
    }
}
pub struct TarLink {
    path_name: Box<str>,
    link_name: Box<str>,
}
pub struct TarSymlink {
    path_name: Box<str>,
    link_name: Box<str>,
    mode: u32,
    mtime: u32,
    uid: u32,
    gid: u32,
}
pub struct TarDirectory {
    path_name: Box<str>,
    mode: u32,
    mtime: u32,
    uid: u32,
    gid: u32,
    size: u64,
}
pub struct TarRegularFile<'a, R: AsyncRead + Send + 'a> {
    path_name: Box<str>,
    size: u64,
    mode: u32,
    mtime: u32,
    uid: u32,
    gid: u32,
    eof: u64,
    inner: Arc<Mutex<Pin<Box<TarReaderInner<'a, R>>>>>,
}
pub enum TarEntry<'a, R: AsyncRead + Send + 'a> {
    File(TarRegularFile<'a, R>),
    Link(TarLink),
    Symlink(TarSymlink),
    Directory(TarDirectory),
}

fn entry_name(hdr: &Header, exts: &mut Vec<ExtensionHeader>) -> Result<Box<str>> {
    let long_path = exts.drain(..).fold(None, |p, e| match e {
        ExtensionHeader::LongName(name) => Some(name),
        ExtensionHeader::PosixExtension(ext) => {
            for (key, val) in ext.iter() {
                if key == "path" {
                    return Some(val.to_string().into_boxed_str());
                }
            }
            p
        }
        _ => p,
    });
    match hdr.kind() {
        HeaderKind::Gnu(hdr) => Ok(long_path.map_or_else(|| hdr.path_name(), Ok)?),
        HeaderKind::Ustar(hdr) => hdr.path_name(),
        HeaderKind::Old(hdr) => hdr.link_name(),
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
        HeaderKind::Ustar(hdr) => Ok((hdr.path_name()?, hdr.link_name()?)),
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

impl<'a, R: AsyncRead + Send + 'a> TarReaderInner<'a, R> {
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
    fn poll_read_header(
        self: Pin<&mut Self>,
        ctx: &mut Context<'_>,
    ) -> Poll<Option<Result<Entry>>> {
        let mut this = self.project();
        loop {
            // println!("st={:?} pos={} nxt={}", *this.state, *this.pos, *this.nxt);
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
                        Kind::File | Kind::File0 => {
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
                        Kind::Directory if !this.header.is_old() => {
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
                        Kind::Link => {
                            *this.nxt += BLOCK_SIZE as u64;
                            *this.state = Header;
                            let (path_name, link_name) = entry_name_link(this.header, this.exts)?;
                            Ok(Entry::Link(TarLink {
                                path_name,
                                link_name,
                            }))
                        }
                        Kind::Symlink if !this.header.is_old() => {
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
                                    Ok(n)
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
                                    Ok(n)
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
                        _ => Err(Error::new(
                            ErrorKind::InvalidData,
                            "invalid tar entry header",
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

impl<'a, R: AsyncRead + Send + 'a> Stream for TarReader<'a, R> {
    type Item = Result<TarEntry<'a, R>>;
    fn poll_next(mut self: Pin<&mut Self>, ctx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.as_mut();
        let mut fut = this.inner.lock();
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
                eof,
                inner: Arc::clone(&this.inner),
            }),
            Entry::Directory(d) => TarEntry::Directory(d),
            Entry::Link(l) => TarEntry::Link(l),
            Entry::Symlink(l) => TarEntry::Symlink(l),
        })))
    }
}

impl<'a, R: AsyncRead + Send + 'a> Stream for TarReaderInner<'a, R> {
    type Item = Result<Entry>;
    fn poll_next(mut self: Pin<&mut Self>, ctx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.as_mut().poll_read_header(ctx)
    }
}
impl<'a, R: AsyncRead + Send + 'a> TarEntry<'a, R> {
    pub fn path(&'_ self) -> &'_ str {
        match self {
            Self::File(f) => &f.path_name,
            Self::Link(l) => &l.path_name,
            Self::Symlink(l) => &l.path_name,
            Self::Directory(d) => &d.path_name,
        }
    }
}

impl<'a, R: AsyncRead + Send + 'a> TarRegularFile<'a, R> {
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
}
impl TarLink {
    pub fn path(&'_ self) -> &'_ str {
        &self.path_name
    }
    pub fn link(&'_ self) -> &'_ str {
        &self.link_name
    }
}
impl TarSymlink {
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
}
impl TarDirectory {
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
}

impl<'a, R: AsyncRead + Send + 'a> AsyncRead for TarRegularFile<'a, R> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        ctx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<std::io::Result<usize>> {
        let eof = self.eof;
        let this = self.as_mut();
        let mut fut = this.inner.lock();
        let mut g = task::ready!(pin!(fut).poll(ctx));
        let inner_pin: Pin<&mut TarReaderInner<R>> = g.as_mut();
        let inner = inner_pin.project();
        if *inner.pos >= eof {
            return Poll::Ready(Ok(0));
        }
        let remain = eof - *inner.pos;
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
        (n + 511) & !511
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
