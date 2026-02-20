use {
    crate::tar::TarReader,
    async_compression::futures::bufread::{
        BzDecoder, GzipDecoder, Lz4Decoder, XzDecoder, ZstdDecoder,
    },
    smol::io::{self, AsyncRead, BufReader},
    std::pin::Pin,
};

fn ends_with_ignore_case(s: &[u8], suffix: &[u8]) -> bool {
    if suffix.len() > s.len() {
        return false;
    }
    let mut i = s.len();
    let mut j = suffix.len();
    while j > 0 {
        i -= 1;
        j -= 1;
        if !s[i].eq_ignore_ascii_case(&suffix[j]) {
            return false;
        }
    }
    true
}

macro_rules! match_ext_int {
    ($lbl:lifetime $var:ident { $lit:literal $( | $cont:literal )* => $block:expr,  $($rest:tt)+ }) => {{
        if ends_with_ignore_case($var, concat!(".", $lit).as_bytes())
            $( || ends_with_ignore_case($var, concat!(".", $cont).as_bytes()) )* {
            break $lbl $block
        }
        match_ext_int!($lbl $var { $($rest)* })
    }};
    ($lbl:lifetime $var:ident { None => $none_block:expr $(,)? }) => {{
        { $none_block }
    }};
}
macro_rules! match_ext {
    ($expr:expr, { $($rest:tt)* }) => {{
        let s: &[u8] = $expr;
        'matcher: {
            match_ext_int!('matcher s { $($rest)* })
        }
    }};
}
fn buffered<R: AsyncRead + Send>(reader: R) -> BufReader<R> {
    const BUFSIZE: usize = 64 * 1024;
    BufReader::with_capacity(BUFSIZE, reader)
}

pub fn strip_comp_ext(s: &str) -> &str {
    match_ext!(s.as_bytes(), {
        "gz" | "xz" => &s[..s.len() - 3],
        "bz2" | "zst" | "lz4" => &s[..s.len() - 4],
        "zstd" => &s[..s.len() - 5],
        None => s,
    })
}

pub fn is_comp_ext<P: AsRef<[u8]>>(uri: P) -> bool {
    match_ext!(uri.as_ref(), { "gz" | "xz" | "bz2" | "zstd" | "zst" | "lz4" => true, None => false})
}

pub fn comp_reader<'a, R: AsyncRead + Send + 'a>(
    uri: &str,
    reader: R,
) -> Pin<Box<dyn AsyncRead + Send + 'a>> {
    match_ext!(uri.as_bytes(), {
        "gz" => Box::pin(GzipDecoder::new(buffered(reader))),
        "xz" => Box::pin(XzDecoder::new(buffered(reader))),
        "bz2" => Box::pin(BzDecoder::new(buffered(reader))),
        "lz4" => Box::pin(Lz4Decoder::new(buffered(reader))),
        "zstd" | "zst" => Box::pin(ZstdDecoder::new(buffered(reader))),
        None => Box::pin(buffered(reader)),
    })
}

pub fn is_tar_ext<P: AsRef<[u8]>>(path: P) -> bool {
    match_ext!(path.as_ref(), {
        "tar" | "tar.gz" | "tgz" |
        "tar.xz" | "txz" |
        "tar.bz2" | "tbz" | "tbz2" |
        "tar.zstd" | "tar.zst" | "tzst" => true,
        None => false,
    })
}

pub fn tar_reader<'a, R: AsyncRead + Send + 'a>(
    uri: &str,
    reader: R,
) -> io::Result<TarReader<'a, Pin<Box<dyn AsyncRead + Send + 'a>>>> {
    match_ext!(uri.as_bytes(), {
        "tar" => Ok(TarReader::new(Box::pin(buffered(reader)))),
        "tar.gz" | "tgz" => Ok(TarReader::new(Box::pin(GzipDecoder::new(buffered(reader))))),
        "tar.xz" | "txz" => Ok(TarReader::new(Box::pin(XzDecoder::new(buffered(reader))))),
        "tar.bz2" | "tbz" | "tbz2" => Ok(TarReader::new(Box::pin(BzDecoder::new(buffered(reader))))),
        "tar.zstd" | "tar.zst" | "tzst" => Ok(TarReader::new(Box::pin(ZstdDecoder::new(buffered(reader))))),
        None => Err(io::Error::other(format!("unsupported archive format {}", uri))),
    })
}
