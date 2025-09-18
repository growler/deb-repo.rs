use debrepo::tar::*;
use smol::{
    io::{copy, sink},
    prelude::*,
    Async,
};

fn main() {
    smol::block_on(async {
        let mut ar = TarReader::new(Async::new(std::io::stdin()).unwrap());
        while let Some(file) = ar.next().await {
            let f = file.unwrap();
            let path = f.path().to_string();
            println!("{} {}", path, path.len());
            if let TarEntry::File(mut f) = f {
                copy(&mut f, &mut sink()).await.unwrap();
            }
        }
    });
}
