use {debrepo::tar::*, futures::StreamExt, smol::Async, tracing_subscriber::fmt};

fn main() {
    let filter = tracing_subscriber::EnvFilter::builder()
        .with_default_directive(tracing::level_filters::LevelFilter::TRACE.into())
        .from_env_lossy();

    let base_format = fmt::format()
        .without_time()
        .with_level(false)
        .with_target(true);

    fmt()
        .with_env_filter(filter)
        .event_format(base_format)
        .with_thread_ids(true)
        .with_thread_names(true)
        .with_file(true)
        .with_line_number(true)
        .with_writer(std::io::stderr)
        .try_init()
        .unwrap();

    smol::block_on(async {
        let mut rd = TarReader::new(Async::new(std::io::stdin()).unwrap());
        while let Some(entry) = rd.next().await {
            match entry {
                Ok(entry) => {
                    tracing::trace!(target: "tar-cmd", " entry: {:?}", &entry);
                    if let TarEntry::File(mut f) = entry {
                        if let Err(e) = smol::io::copy(&mut f, &mut smol::io::sink()).await {
                            tracing::error!(target: "tar-cmd", " copy error: {:?}", &e);
                        }
                    }
                }
                Err(e) => {
                    tracing::error!(target: "tar-cmd", " error: {:?}", &e);
                }
            }
        }
        // let mut wr = TarWriter::new(Async::new(std::io::stdout()).unwrap());
        // let fwd = rd
        //     .map(|e| {
        //         if let Ok(entry) = e {
        //             tracing::trace!(target: "tar-cmd", " entry: {:?}", &entry);
        //             Ok(entry)
        //         } else {
        //             e
        //         }
        //     })
        //     .forward(&mut wr);
        // fwd.await.unwrap();
    });
}
