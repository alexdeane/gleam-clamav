# clamav_client

[![Package Version](https://img.shields.io/hexpm/v/clamav_client)](https://hex.pm/packages/clamav_client)
[![Hex Docs](https://img.shields.io/badge/hex-docs-ffaff3)](https://hexdocs.pm/clamav_client/)
[![Latest CI](https://github.com/alexdeane/gleam-clamav/actions/workflows/release.yml/badge.svg)](https://github.com/alexdeane/gleam-clamav/actions/workflows/release.yml)

Gleam client for interacting with a [ClamAV](https://www.clamav.net/) instance

```sh
gleam add clamav_client@1
```
```gleam
import clamav_client/clamav

pub fn main() {
  let data = "some data, probably a file" |> bit_array.from_string

  let clamav_options =
    clamav.new("<host>")
    |> clamav.port(3310)

  case clamav.instream(clamav_options, data) {
    Ok(Clean) -> "Clean!"
    Ok(VirusDetected(infected_files)) -> {
      let infected_file =
        infected_files |> list.first

      "VirusDetected: " <> infected_file.file_name <> " | " <> infected_file.virus_name
    }
    Error(error) -> "Error: " <> error |> string.inspect
  }
}
```

Further documentation can be found at <https://hexdocs.pm/clamav_client>.
