///
/// Initialize the fern logger
///
pub fn init_logger() {
    match fern::Dispatch::new()
        .chain(
            fern::Dispatch::new()
                .level(log::LevelFilter::Debug)
                .format(|out, message, record| {
                    out.finish(format_args!(
                        "{}:{}:{}:{}",
                        chrono::Local::now().format("%Y-%m-%d-%H:%M:%S"),
                        record.target(),
                        record.level(),
                        message
                    ))
                })
                .chain(std::io::stdout()),
        )
        .apply()
    {
        Ok(()) => println!("logger created"),
        Err(e) => {
            println!("failed to create logger: {:?}", e);
        }
    };
}
