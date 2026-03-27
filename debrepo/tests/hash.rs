use {
    base64::Engine,
    debrepo::hash::{
        self, AsyncHashingRead, Hash, HashAlgo, HashOutput, Hashable, HashingReader, HashingWriter,
        InnerHash, SyncHashingWriter,
    },
    digest::{FixedOutputReset, Update},
    serde::{Deserialize, Serialize},
    smol::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, Cursor},
    std::{
        collections::VecDeque,
        io,
        path::PathBuf,
        pin::Pin,
        sync::{Arc, Mutex},
        task::{Context, Poll},
    },
};

fn hash_output_for<D: HashAlgo>(data: &[u8]) -> HashOutput<D> {
    let mut hasher = D::default();
    data.hash_into(&mut hasher);
    hasher.finalize_fixed_reset()
}

fn hash_for<D: HashAlgo>(data: &[u8]) -> Hash {
    Hash::new_from_hash::<D>(hash_output_for::<D>(data))
}

#[derive(Clone, Copy)]
struct AlgorithmCase {
    hash_name: &'static str,
    sri_name: &'static str,
    size: usize,
}

const ALGORITHMS: &[AlgorithmCase] = &[
    AlgorithmCase {
        hash_name: "MD5sum",
        sri_name: "md5",
        size: 16,
    },
    AlgorithmCase {
        hash_name: "SHA1",
        sri_name: "sha1",
        size: 20,
    },
    AlgorithmCase {
        hash_name: "SHA256",
        sri_name: "sha256",
        size: 32,
    },
    AlgorithmCase {
        hash_name: "SHA512",
        sri_name: "sha512",
        size: 64,
    },
    AlgorithmCase {
        hash_name: "Blake3",
        sri_name: "blake3",
        size: 32,
    },
];

fn sample_hash(case: AlgorithmCase, data: &[u8]) -> Hash {
    match case.hash_name {
        "MD5sum" => hash_for::<md5::Md5>(data),
        "SHA1" => hash_for::<sha1::Sha1>(data),
        "SHA256" => hash_for::<sha2::Sha256>(data),
        "SHA512" => hash_for::<sha2::Sha512>(data),
        "Blake3" => hash_for::<blake3::Hasher>(data),
        other => panic!("unsupported algorithm case: {other}"),
    }
}

#[test]
fn hash_roundtrips_for_every_supported_algorithm() {
    let data = b"hash coverage fixture";

    for case in ALGORITHMS {
        let hash = sample_hash(*case, data);
        assert_eq!(hash.name(), case.hash_name);
        assert_eq!(hash.sri_name(), case.sri_name);
        assert_eq!(hash.size(), case.size);
        assert_eq!(hash.as_bytes().len(), case.size);

        let from_hex = Hash::from_hex(case.hash_name, hash.to_hex()).unwrap();
        assert_eq!(from_hex, hash);

        let from_b64 = Hash::from_base64(case.hash_name, hash.to_base64()).unwrap();
        assert_eq!(from_b64, hash);

        let from_sri = Hash::from_sri(hash.to_sri()).unwrap();
        assert_eq!(from_sri, hash);

        let via_try_from = Hash::try_from(hash.to_sri().as_str()).unwrap();
        assert_eq!(via_try_from, hash);

        let owned_sri: String = hash.clone().into();
        let borrowed_sri: String = (&hash).into();
        assert_eq!(owned_sri, hash.to_sri());
        assert_eq!(borrowed_sri, hash.to_sri());
    }
}

#[test]
fn hashalgo_helpers_and_innerhash_conversions_work() {
    let data = b"typed hash helpers";

    let mut sha1 = sha1::Sha1::default();
    data.hash_into(&mut sha1);
    let sha1_hash = <sha1::Sha1 as HashAlgo>::into_hash(sha1);
    assert_eq!(sha1_hash, hash_for::<sha1::Sha1>(data));

    let sha1_hex = sha1_hash.to_hex();
    let sha1_out = <sha1::Sha1 as HashAlgo>::from_hex(&sha1_hex).unwrap();
    let inner: InnerHash<sha1::Sha1> = sha1_out.into();
    assert_eq!(inner.as_bytes(), sha1_hash.as_bytes());
    assert_eq!(inner.hash(), sha1_hash);
    assert_eq!(format!("{inner:?}"), format!("SHA1({sha1_hex})"));

    let roundtrip_out: HashOutput<sha1::Sha1> = inner.clone().into();
    assert_eq!(roundtrip_out, sha1_out);
    assert_eq!(inner.as_ref(), sha1_hash.as_bytes());
}

#[test]
fn parser_error_paths_are_reported_through_public_api() {
    let md5_hash = hash_for::<md5::Md5>(b"md5 data");
    let short_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([0u8; 8]);

    let err = Hash::from_hex("SHA1", "abcd").unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    assert!(err.to_string().contains("invalid hex digest length"));

    let err = Hash::from_hex("SHA1", "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz").unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    assert!(err.to_string().contains("error decoding hex digest"));

    let err = Hash::from_hex("sha999", md5_hash.to_hex()).unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    assert!(err.to_string().contains("invalid digest length sha999"));

    let err = Hash::from_base64("SHA1", &short_b64).unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    assert!(err.to_string().contains("expected 20 bytes, got 8"));

    let err = Hash::from_base64("SHA1", "***").unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    assert!(err.to_string().contains("error decoding base64 digest"));

    let err = Hash::from_base64("sha999", md5_hash.to_base64()).unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    assert!(err.to_string().contains("invalid digest length sha999"));

    let err = Hash::from_sri("sha1").unwrap_err();
    assert!(err.to_string().contains("missing base64 digest"));

    let err = Hash::from_sri("sha999-AAAA").unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    assert!(err.to_string().contains("hash sha999 not supported"));

    let err = Hash::from_sri("sha1-***").unwrap_err();
    assert!(err.to_string().contains("error decoding base64 digest"));

    let short_sri = format!(
        "sha1-{}",
        base64::engine::general_purpose::STANDARD.encode([0u8; 8])
    );
    let err = Hash::from_sri(short_sri).unwrap_err();
    assert!(err.to_string().contains("error decoding base64 digest"));

    let err = match Hash::hashing_reader_for("sha999", Cursor::new(b"data")) {
        Ok(_) => panic!("unsupported hash unexpectedly succeeded"),
        Err(err) => err,
    };
    assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    assert!(err.to_string().contains("hash sha999 not supported"));
}

#[test]
fn store_name_builds_expected_paths() {
    let md5 = Hash::from_hex("MD5sum", "000102030405060708090a0b0c0d0e0f").unwrap();

    assert_eq!(
        md5.store_name::<&str>(None, None, 0),
        PathBuf::from("md5/000102030405060708090a0b0c0d0e0f")
    );
    assert_eq!(
        md5.store_name(Some("cache"), Some("deb"), 2),
        PathBuf::from("cache/md5/00/01/02030405060708090a0b0c0d0e0f.deb")
    );
    assert_eq!(
        md5.store_name::<&str>(None, None, 32),
        PathBuf::from("md5/00/01/02/03/04/05/06/07/08/09/0a/0b/0c/0d/0e/0f")
    );
}

#[test]
fn hashing_reader_public_api_tracks_size_and_hash() {
    smol::block_on(async {
        let data = b"reader payload";

        let mut reader = Box::pin(HashingReader::<sha1::Sha1, _>::new(Cursor::new(data)));
        assert_eq!(reader.as_mut().size(), 0);

        let mut prefix = [0u8; 6];
        let read = reader.read(&mut prefix).await.unwrap();
        assert_eq!(read, 6);
        assert_eq!(reader.as_mut().size(), 6);
        assert_eq!(reader.as_mut().hash(), hash_for::<sha1::Sha1>(&data[..6]));

        let mut suffix = Vec::new();
        reader.read_to_end(&mut suffix).await.unwrap();
        assert_eq!([prefix.as_slice(), suffix.as_slice()].concat(), data);
        assert_eq!(reader.as_mut().size(), data.len() as u64);
        assert_eq!(reader.as_mut().hash(), hash_for::<sha1::Sha1>(&suffix));
        assert_eq!(reader.as_mut().hash(), hash_for::<sha1::Sha1>(b""));
    });
}

#[test]
fn hashing_reader_constructors_and_consumers_work() {
    smol::block_on(async {
        let data = b"tail";
        let mut seeded = sha2::Sha256::default();
        "head".hash_into(&mut seeded);

        let mut reader =
            HashingReader::<sha2::Sha256, _>::new_with_digester(seeded, Cursor::new(data));
        let mut buf = Vec::new();
        reader.read_to_end(&mut buf).await.unwrap();
        assert_eq!(buf, data);
        assert_eq!(reader.into_hash(), hash_for::<sha2::Sha256>(b"headtail"));

        let mut out_reader = HashingReader::<sha2::Sha256, _>::new(Cursor::new(b"abc"));
        let mut discard = Vec::new();
        out_reader.read_to_end(&mut discard).await.unwrap();
        let out = out_reader.into_hash_output();
        assert_eq!(
            Hash::new_from_hash::<sha2::Sha256>(out),
            hash_for::<sha2::Sha256>(b"abc")
        );

        let mut sized_reader = HashingReader::<blake3::Hasher, _>::new(Cursor::new(b"size"));
        let mut discard = Vec::new();
        sized_reader.read_to_end(&mut discard).await.unwrap();
        let (hash, size) = sized_reader.into_hash_and_size();
        assert_eq!(hash, hash_for::<blake3::Hasher>(b"size"));
        assert_eq!(size, 4);
    });
}

#[test]
fn hash_dispatchers_return_working_readers() {
    smol::block_on(async {
        let data = b"dispatch me";

        for case in ALGORITHMS {
            let expected = sample_hash(*case, data);

            let mut hasher = Hash::hashing_reader_for(case.hash_name, Cursor::new(data)).unwrap();
            assert_eq!(hasher.as_mut().size(), 0);
            let mut buf = Vec::new();
            hasher.read_to_end(&mut buf).await.unwrap();
            assert_eq!(buf, data);
            assert_eq!(hasher.as_mut().size(), data.len() as u64);
            assert_eq!(hasher.as_mut().hash(), expected);
        }
    });
}

#[test]
fn hash_reader_and_verifying_reader_cover_success_and_errors() {
    smol::block_on(async {
        let data = b"verified payload";
        let hash = hash_for::<sha2::Sha256>(data);

        let mut reader = hash.reader(data.len() as u64, Cursor::new(data));
        let mut read_back = Vec::new();
        reader.read_to_end(&mut read_back).await.unwrap();
        assert_eq!(read_back, data);

        let mut verifying = hash.verifying_reader(data.len() as u64, Cursor::new(data));
        assert_eq!(verifying.as_mut().size(), data.len() as u64);
        assert_eq!(verifying.as_mut().hash(), hash);
        let mut verified = Vec::new();
        verifying.read_to_end(&mut verified).await.unwrap();
        assert_eq!(verified, data);

        let wrong_digest = Hash::from_hex("SHA256", "00".repeat(32)).unwrap();
        let err = wrong_digest
            .verifying_reader(data.len() as u64, Cursor::new(data))
            .read_to_end(&mut Vec::new())
            .await
            .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(err.to_string().contains("error verifying stream by SHA256"));

        let err = hash
            .verifying_reader((data.len() - 1) as u64, Cursor::new(data))
            .read_to_end(&mut Vec::new())
            .await
            .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(err.to_string().contains("expected 15, got 16 bytes"));
    });
}

#[test]
fn hashing_reader_propagates_inner_read_errors() {
    smol::block_on(async {
        let mut reader = HashingReader::<sha2::Sha256, _>::new(ErrorAsyncRead {
            err: Some(io::Error::other("boom")),
        });
        let mut buf = [0u8; 8];
        let err = reader.read(&mut buf).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::Other);
        assert_eq!(err.to_string(), "boom");
    });
}

#[test]
fn sync_hashing_writer_covers_partial_zero_error_and_flush() {
    let state = Arc::new(Mutex::new(SyncWriteState::default()));
    let mut writer = SyncHashingWriter::<sha1::Sha1, _>::new(ScriptedWrite::new(
        [
            SyncWriteStep::Write(3),
            SyncWriteStep::Zero,
            SyncWriteStep::Error(io::ErrorKind::BrokenPipe, "sync boom"),
        ],
        state.clone(),
    ));

    assert_eq!(std::io::Write::write(&mut writer, b"abcdef").unwrap(), 3);
    assert_eq!(std::io::Write::write(&mut writer, b"xyz").unwrap(), 0);
    let err = std::io::Write::write(&mut writer, b"zzz").unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::BrokenPipe);
    std::io::Write::flush(&mut writer).unwrap();
    assert_eq!(writer.into_hash(), hash_for::<sha1::Sha1>(b"abc"));

    let state = state.lock().unwrap();
    assert_eq!(state.bytes, b"abc");
    assert_eq!(state.flushes, 1);
}

#[test]
fn async_hashing_writer_covers_pending_zero_error_flush_and_close() {
    smol::block_on(async {
        let state = Arc::new(Mutex::new(AsyncWriteState::default()));
        let inner = ScriptedAsyncWrite::new(
            [
                AsyncWriteStep::Pending,
                AsyncWriteStep::Write(2),
                AsyncWriteStep::Zero,
                AsyncWriteStep::Error(io::ErrorKind::BrokenPipe, "async boom"),
            ],
            state.clone(),
        );
        let mut writer = HashingWriter::<sha1::Sha1, _>::new(inner);

        assert_eq!(writer.write(b"abcd").await.unwrap(), 2);
        assert_eq!(writer.write(b"zz").await.unwrap(), 0);
        let err = writer.write(b"qq").await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::BrokenPipe);

        writer.flush().await.unwrap();
        writer.close().await.unwrap();
        assert_eq!(writer.into_hash(), hash_for::<sha1::Sha1>(b"ab"));

        let state = state.lock().unwrap();
        assert_eq!(state.bytes, b"ab");
        assert_eq!(state.flushes, 1);
        assert_eq!(state.closes, 1);
    });
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
struct SriWire {
    #[serde(with = "hash::serde::sri")]
    value: Hash,
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
struct SriOptWire {
    #[serde(with = "hash::serde::sri::opt")]
    value: Option<Hash>,
}

#[derive(Debug, Serialize, PartialEq)]
struct HexWire {
    #[serde(with = "hash::serde::hex")]
    value: Hash,
}

#[derive(Debug, Serialize, PartialEq)]
struct HexOptWire {
    #[serde(with = "hash::serde::hex::opt")]
    value: Option<Hash>,
}

#[derive(Debug, Serialize, PartialEq)]
struct Base64Wire {
    #[serde(with = "hash::serde::base64")]
    value: Hash,
}

#[derive(Debug, Serialize, PartialEq)]
struct Base64OptWire {
    #[serde(with = "hash::serde::base64::opt")]
    value: Option<Hash>,
}

#[test]
fn serde_helpers_cover_sri_hex_base64_and_option_wrappers() {
    let hash = hash_for::<sha2::Sha256>(b"serde");
    let sri = hash.to_sri();

    assert_eq!(serde_json::to_string(&hash).unwrap(), format!("\"{sri}\""));
    assert_eq!(
        serde_json::from_str::<Hash>(&format!("\"{sri}\"")).unwrap(),
        hash
    );

    let sri_wire = SriWire {
        value: hash.clone(),
    };
    assert_eq!(
        serde_json::to_string(&sri_wire).unwrap(),
        format!("{{\"value\":\"{sri}\"}}")
    );
    assert_eq!(
        serde_json::from_str::<SriWire>(&format!("{{\"value\":\"{sri}\"}}")).unwrap(),
        sri_wire
    );

    let some_wire = SriOptWire {
        value: Some(hash.clone()),
    };
    assert_eq!(
        serde_json::to_string(&some_wire).unwrap(),
        format!("{{\"value\":\"{sri}\"}}")
    );
    assert_eq!(
        serde_json::from_str::<SriOptWire>(&format!("{{\"value\":\"{sri}\"}}")).unwrap(),
        some_wire
    );
    assert_eq!(
        serde_json::from_str::<SriOptWire>("{\"value\":null}").unwrap(),
        SriOptWire { value: None }
    );

    assert_eq!(
        serde_json::to_string(&HexWire {
            value: hash.clone()
        })
        .unwrap(),
        format!("{{\"value\":\"{}\"}}", hash.to_hex())
    );
    assert_eq!(
        serde_json::to_string(&HexOptWire {
            value: Some(hash.clone()),
        })
        .unwrap(),
        format!("{{\"value\":\"{}\"}}", hash.to_hex())
    );
    assert_eq!(
        serde_json::to_string(&HexOptWire { value: None }).unwrap(),
        "{\"value\":null}"
    );

    let padded_b64 = base64::engine::general_purpose::URL_SAFE.encode(hash.as_bytes());
    assert_eq!(
        serde_json::to_string(&Base64Wire {
            value: hash.clone()
        })
        .unwrap(),
        format!("{{\"value\":\"{padded_b64}\"}}")
    );
    assert_eq!(
        serde_json::to_string(&Base64OptWire {
            value: Some(hash.clone()),
        })
        .unwrap(),
        format!("{{\"value\":\"{padded_b64}\"}}")
    );
    assert_eq!(
        serde_json::to_string(&Base64OptWire { value: None }).unwrap(),
        "{\"value\":null}"
    );

    let err = serde_json::from_str::<Hash>("123").unwrap_err();
    assert!(err.to_string().contains("an SRI digest"));
}

#[test]
fn hashable_impls_cover_primitives() {
    let bytes = b"bytes";
    let text = "text";
    let count_usize = 9usize;
    let count_u64 = 10u64;
    let count_u32 = 11u32;
    let flag = true;

    let mut via_trait = sha2::Sha256::default();
    bytes.as_slice().hash_into(&mut via_trait);
    text.hash_into(&mut via_trait);
    count_usize.hash_into(&mut via_trait);
    count_u64.hash_into(&mut via_trait);
    count_u32.hash_into(&mut via_trait);
    flag.hash_into(&mut via_trait);
    let via_trait = Hash::new_from_hash::<sha2::Sha256>(via_trait.finalize_fixed_reset());

    let mut manual = sha2::Sha256::default();
    manual.update(bytes);
    manual.update(text.as_bytes());
    manual.update(&count_usize.to_le_bytes());
    manual.update(&count_u64.to_le_bytes());
    manual.update(&count_u32.to_le_bytes());
    manual.update(&[1]);
    let manual = Hash::new_from_hash::<sha2::Sha256>(manual.finalize_fixed_reset());

    assert_eq!(via_trait, manual);
}

struct ErrorAsyncRead {
    err: Option<io::Error>,
}

impl AsyncRead for ErrorAsyncRead {
    fn poll_read(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        _buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        Poll::Ready(Err(self
            .err
            .take()
            .unwrap_or_else(|| io::Error::other("eof"))))
    }
}

#[derive(Default)]
struct SyncWriteState {
    bytes: Vec<u8>,
    flushes: usize,
}

enum SyncWriteStep {
    Write(usize),
    Zero,
    Error(io::ErrorKind, &'static str),
}

struct ScriptedWrite {
    steps: VecDeque<SyncWriteStep>,
    state: Arc<Mutex<SyncWriteState>>,
}

impl ScriptedWrite {
    fn new(
        steps: impl IntoIterator<Item = SyncWriteStep>,
        state: Arc<Mutex<SyncWriteState>>,
    ) -> Self {
        Self {
            steps: steps.into_iter().collect(),
            state,
        }
    }
}

impl io::Write for ScriptedWrite {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self.steps.pop_front().expect("write step") {
            SyncWriteStep::Write(size) => {
                self.state
                    .lock()
                    .unwrap()
                    .bytes
                    .extend_from_slice(&buf[..size]);
                Ok(size)
            }
            SyncWriteStep::Zero => Ok(0),
            SyncWriteStep::Error(kind, msg) => Err(io::Error::new(kind, msg)),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        self.state.lock().unwrap().flushes += 1;
        Ok(())
    }
}

#[derive(Default)]
struct AsyncWriteState {
    bytes: Vec<u8>,
    flushes: usize,
    closes: usize,
}

enum AsyncWriteStep {
    Pending,
    Write(usize),
    Zero,
    Error(io::ErrorKind, &'static str),
}

struct ScriptedAsyncWrite {
    steps: VecDeque<AsyncWriteStep>,
    state: Arc<Mutex<AsyncWriteState>>,
}

impl ScriptedAsyncWrite {
    fn new(
        steps: impl IntoIterator<Item = AsyncWriteStep>,
        state: Arc<Mutex<AsyncWriteState>>,
    ) -> Self {
        Self {
            steps: steps.into_iter().collect(),
            state,
        }
    }
}

impl AsyncWrite for ScriptedAsyncWrite {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match self.steps.pop_front().expect("write step") {
            AsyncWriteStep::Pending => {
                cx.waker().wake_by_ref();
                Poll::Pending
            }
            AsyncWriteStep::Write(size) => {
                self.state
                    .lock()
                    .unwrap()
                    .bytes
                    .extend_from_slice(&buf[..size]);
                Poll::Ready(Ok(size))
            }
            AsyncWriteStep::Zero => Poll::Ready(Ok(0)),
            AsyncWriteStep::Error(kind, msg) => Poll::Ready(Err(io::Error::new(kind, msg))),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.state.lock().unwrap().flushes += 1;
        Poll::Ready(Ok(()))
    }

    fn poll_close(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.state.lock().unwrap().closes += 1;
        Poll::Ready(Ok(()))
    }
}
