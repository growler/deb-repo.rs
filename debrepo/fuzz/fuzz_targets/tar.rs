#![no_main]
extern crate debrepo;
use libfuzzer_sys::fuzz_target;
use smol::{io::BufReader, stream::StreamExt};

fuzz_target!(|data: &[u8]| {
        smol::block_on(async {
            let r = BufReader::new(data);
            let mut ar = debrepo::tar::TarReader::new(r);
            while let Some(file) = ar.next().await {
                if let Ok(f) = file {
                    if let debrepo::tar::TarEntry::File(mut f) = f {
                        if smol::io::copy(&mut f, &mut smol::io::sink()).await.is_err() {
                            return;
                        }
                    }
                } else {
                    return;
                }
            }
        })
});
