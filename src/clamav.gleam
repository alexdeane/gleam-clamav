import client_options.{type ClamAvClientOptions, type Logger}
import common/internal
import common/tcp
import gleam/bit_array
import gleam/int
import gleam/list
import gleam/result
import gleam/string
import mug

// Bytes that indicate the end of the file upload
const file_end = <<0:little-size(32)>>

// ------------- RESULT TYPES --------------- //
pub type ClamScanResult {
  Clean
  VirusDetected(infected_files: List(InfectedFile))
}

pub type InfectedFile {
  InfectedFile(file_name: String, virus_name: String)
}

pub type ClamError {
  ScanError(error: String)
  CannotParseResponse(ClamResponseParsingError)
  ConnectionError(error: mug.Error)
}

pub type ClamResponseParsingError {
  UnexpectedResponse(raw_response: String)
  InvalidBinaryData
}

// ------------- COMMON --------------- //

fn execute_adhoc_command(
  options: ClamAvClientOptions,
  command: String,
) -> Result(BitArray, ClamError) {
  {
    use socket <- internal.execute_command(options, command)
    use res <- tcp.receive_bytes(socket, options)
    Ok(res)
  }
  |> result.try_recover(with: fn(e) { Error(ConnectionError(e)) })
}

// ------------- PING --------------- //

/// Send a PING command to the ClamAV server
pub fn ping(options: ClamAvClientOptions) -> Result(Nil, ClamError) {
  let res = execute_adhoc_command(options, "PING")

  case res {
    Ok(bits) -> {
      let response_text = bits |> bit_array.to_string()
      case response_text {
        Ok("PONG") -> Ok(Nil)
        Ok(text) -> Error(CannotParseResponse(UnexpectedResponse(text)))
        _ -> Error(CannotParseResponse(InvalidBinaryData))
      }
    }
    Error(error) -> Error(error)
  }
}

// ------------- VERSION --------------- //
pub type ClamVersionResponse {
  ClamVersionResponse(version: String, database_version: String)
}

pub fn version(
  options: ClamAvClientOptions,
) -> Result(ClamVersionResponse, ClamError) {
  let res = execute_adhoc_command(options, "VERSION")

  case res {
    Ok(bits) -> {
      let response_text = bits |> bit_array.to_string()
      case response_text {
        Ok(text) -> parse_version_response(text)
        _ -> Error(CannotParseResponse(InvalidBinaryData))
      }
    }
    Error(error) -> Error(error)
  }
}

// ------------- STATS --------------- //
pub fn stats(options: ClamAvClientOptions) -> Result(String, ClamError) {
  let res = execute_adhoc_command(options, "STATS")

  case res {
    Ok(bits) ->
      case bits |> bit_array.to_string() {
        Ok(text) -> Ok(text)
        _ -> Error(CannotParseResponse(InvalidBinaryData))
      }
    Error(error) -> Error(error)
  }
}

fn parse_version_response(
  response_text: String,
) -> Result(ClamVersionResponse, ClamError) {
  let split = response_text |> string.split("/")

  case split {
    [version, database_version, _date] ->
      Ok(ClamVersionResponse(
        version: version |> string.trim(),
        database_version: database_version |> string.trim(),
      ))
    _ -> Error(CannotParseResponse(UnexpectedResponse(response_text)))
  }
}

// ------------- INSTREAM --------------- //

/// Scan a file in memory
pub fn instream(
  options: ClamAvClientOptions,
  file_content: BitArray,
) -> Result(ClamScanResult, ClamError) {
  // Pad the file contents to the nearest byte to be safe
  let padded_file_content = bit_array.pad_to_bytes(file_content)

  // Perform the scan
  case tcp_instream(options, padded_file_content) {
    Ok(response) -> {
      case bit_array.to_string(response) {
        Ok(response_text) -> {
          // Convert to string and parse
          use scan_result <- parse_scan_result(response_text, options.logger)
          Ok(scan_result)
        }
        Error(_) -> {
          Error(CannotParseResponse(InvalidBinaryData))
        }
      }
    }
    Error(error) -> {
      Error(ConnectionError(error))
    }
  }
}

fn tcp_instream(
  options: ClamAvClientOptions,
  file_content: BitArray,
) -> Result(BitArray, mug.Error) {
  // Initialize socket with a command
  use socket <- internal.execute_command(options, "INSTREAM")

  options.logger.log_info(":: Socket acquired")

  // Send the file contents
  use <- send_file(socket, file_content, options)

  options.logger.log_info(":: File upload complete")

  // Receive the response
  use response_bytes <- tcp.receive_bytes(socket, options)

  options.logger.log_info(":: Received response")

  Ok(response_bytes)
}

fn send_file(
  socket: mug.Socket,
  file_contents: BitArray,
  options: ClamAvClientOptions,
  callback: fn() -> Result(a, mug.Error),
) -> Result(a, mug.Error) {
  let byte_size = bit_array.byte_size(file_contents)

  let packet =
    byte_size
    |> get_length_indicator()
    |> bit_array.append(file_contents)
    |> bit_array.append(file_end)

  options.logger.log_info(
    ":: Uploading file of size "
    <> byte_size |> int.to_string()
    <> "B. (Total packet size "
    <> packet |> bit_array.byte_size() |> int.to_string()
    <> "B)",
  )

  use <- tcp.send_bytes(socket, packet, options)

  callback()
}

fn get_length_indicator(length: Int) -> BitArray {
  // Length indicator shall be 4 bytes in network byte order (Big Endian)
  <<length:big-size(32)>>
}

fn parse_scan_result(
  response: String,
  logger: Logger,
  callback: fn(ClamScanResult) -> Result(ClamScanResult, ClamError),
) -> Result(ClamScanResult, ClamError) {
  let formatted_lower = response |> string.lowercase

  case formatted_lower |> string.ends_with("ok") {
    True -> callback(Clean)
    False -> {
      case formatted_lower |> string.ends_with("error") {
        True -> Error(ScanError(response))
        False -> {
          case formatted_lower |> string.ends_with("found") {
            True -> {
              use virus_detected <- parse_virus_detected(response, logger)
              callback(virus_detected)
            }
            False -> {
              Error(CannotParseResponse(UnexpectedResponse(response)))
            }
          }
        }
      }
    }
  }
}

fn parse_virus_detected(
  response: String,
  logger: Logger,
  callback,
) -> Result(ClamScanResult, ClamError) {
  let files =
    response
    |> string.split("FOUND")
    |> list.filter(fn(x) { x |> string.trim() != "" })
    |> list.map(fn(file_result) {
      let file_parts = file_result |> string.split(":")
      case file_parts {
        [file_name, virus_name] -> {
          InfectedFile(
            file_name: file_name |> string.trim(),
            virus_name: virus_name |> string.trim(),
          )
        }
        _ -> {
          logger.log_error("Could not parse file result")
          InfectedFile(file_name: "UNKNOWN", virus_name: "UNKNOWN")
        }
      }
    })

  callback(VirusDetected(files))
}
