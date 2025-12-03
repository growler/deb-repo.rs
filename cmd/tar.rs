use {debrepo::tar::*, futures::StreamExt, smol::Async, tracing_subscriber::fmt};

fn main() {
    let filter = tracing_subscriber::EnvFilter::builder()
        .with_default_directive(tracing::level_filters::LevelFilter::TRACE.into())
        .from_env_lossy();

    let base_format = fmt::format()
        .without_time()
        .with_level(true)
        .with_target(true);

    fmt()
        .with_env_filter(filter)
        .event_format(base_format)
        .with_thread_ids(true) // include thread IDs only in debug mode
        .with_thread_names(true) // include thread names only in debug mode
        .with_file(true) // include file path only in debug mode
        .with_line_number(true) // include line number only in debug mode
        .with_writer(std::io::stderr)
        .try_init()
        .unwrap();

    tracing::trace!(target: "tar-test", "About to create TarReader and TarWriter");

    smol::block_on(async {
        let rd = TarReader::new(Async::new(std::io::stdin()).unwrap());
        let mut wr = TarWriter::new(Async::new(std::io::stdout()).unwrap());
        let fwd = rd
            .map(|e| {
                if let Ok(entry) = e {
                    eprintln!(" entry: {:?}", &entry);
                    Ok(entry)
                } else {
                    e
                }
            })
            .forward(&mut wr);
        fwd.await.unwrap();
    });
}
