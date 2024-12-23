import clamav.{VirusDetected}
import client_options as clamavc
import gleam/bit_array
import gleam/io
import gleam/string
import gleeunit
import gleeunit/should

pub fn main() {
  gleeunit.main()
}

const eicar_string = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"

const options = clamavc.ClamAvClientOptions(
  host: "localhost",
  port: 3310,
  connection_timeout: 1000,
  reply_timeout: 1000,
  logger: logger,
)

pub fn ping_test() {
  let assert Ok(_) = clamav.ping(options)
}

pub fn instream_test() {
  let assert Ok(VirusDetected([infected_file, ..])) =
    clamav.instream(options, eicar_string |> bit_array.from_string)

  should.be_true(infected_file.file_name |> string.length > 0)
  should.equal(infected_file.virus_name, "Win.Test.EICAR_HDB-1")
}

const logger = clamavc.Logger(
  log_error: log_error,
  log_warning: log_warning,
  log_info: clamavc.nil_log,
)

fn log_warning(msg) {
  io.print("[WARNING] " <> msg)
}

fn log_error(msg) {
  io.print("[ERROR] " <> msg)
}
