/// Options for the ClamAV client
pub type ClamAvClientOptions {
  ClamAvClientOptions(
    host: String,
    port: Int,
    max_chunk_size: Int,
    connection_timeout: Int,
    reply_timeout: Int,
    logger: Logger,
  )
}

/// Logger interface for the ClamAV client to use.
/// To disable logging, pass in the `nil_logger`
pub type Logger {
  Logger(
    log_error: fn(String) -> Nil,
    log_warning: fn(String) -> Nil,
    log_info: fn(String) -> Nil,
  )
}

/// Logger which does not log anything
pub const nil_logger = Logger(
  log_error: nil_log,
  log_warning: nil_log,
  log_info: nil_log,
)

fn nil_log(_) {
  Nil
}
