# Libre:Match SocketSpy

Trace an Age of Empires: Definitive Edition client's TLS traffic and export it as
structured JSON, for reverse-engineering the RelicLink (RLink) lobby and relay
protocol.

The client sends traffic over three TLS stacks. SocketSpy attaches to the running
game as a debugger. It hooks each stack at its own boundary: OpenSSL's
`SSL_write`/`SSL_read`, libcurl's `curl_easy_setopt`, and the WinHTTP request
API. Each hook reads the plaintext on the send side and the receive side.
SocketSpy does not decrypt anything and stores no keys.

SocketSpy runs on **Linux** (the game under Proton/Wine) and on **Windows** (the
game native). It is one binary. You start SocketSpy, and then you start the game.
When the game exits, SocketSpy writes the capture to JSON.

The CPU has only four debug registers. So SocketSpy hooks OpenSSL and libcurl in
separate runs. The `--capture` option selects the stack for a run:

- **OpenSSL** carries the WebSocket traffic: the presence socket and the
  battle-server relay (the multiplayer game API). With `--capture wss`,
  SocketSpy writes this traffic to `wss.json`.
- **libcurl** carries the RLink REST API (`aoe-api.worldsedgelink.com`,
  `POST /game/...`) over SChannel. The OpenSSL hooks do not see this traffic.
  With `--capture rest`, SocketSpy hooks `curl_easy_setopt` and writes the
  requests to `rest.json`.
- **WinHTTP** carries the Xbox, PlayFab, and telemetry traffic. SocketSpy hooks
  WinHTTP in every run and writes its requests to `rest.json`.

## How it works

1. **Wait and attach.** SocketSpy polls for the game process (`AoE2DE_s.exe` by
   default) and attaches to it. It uses `ptrace` on Linux and the Debug API on
   Windows.
2. **Locate OpenSSL.** The client decrypts its code only in memory, so the
   OpenSSL functions have no fixed address. The SocketSpy locator finds them by
   their structure. It uses the `ssl\ssl_lib.c` source string, the
   `ERR_put_error` call sites that reference it, and the OpenSSL function codes
   at those sites. The `.pdata` table then maps each call site to the start of
   its function. The locator uses no hardcoded offsets. If the game stays on
   OpenSSL 1.1, the locator still works after game patches.
3. **Capture OpenSSL (`--capture wss`) with hardware breakpoints.**
   `ssl_write_internal` (send) and `SSL_read` (receive) are in the game's
   integrity-protected code. If SocketSpy patches that code, the integrity
   check stops the game. So SocketSpy sets hardware breakpoints on these
   functions. Hardware breakpoints use the CPU debug registers and change no
   code. SocketSpy parses each buffer as HTTP or WebSocket.
4. **Capture libcurl REST (`--capture rest`) with hardware breakpoints.** The
   locator also finds `curl_easy_setopt` by its structure. It scans `.text` for
   `mov edx, 10002` followed by a `call`. The value 10002 is `CURLOPT_URL`,
   which is stable across builds. The locator uses the call target that most
   matches agree on. Here too, it uses no hardcoded offsets.

   At a hardware breakpoint on `curl_easy_setopt`, SocketSpy reads the URL,
   method, headers, and body of each request. If the request sets
   `CURLOPT_WRITEFUNCTION`, SocketSpy reads the callback address from the same
   call. It sets a second hardware breakpoint on that callback. When libcurl
   delivers the response body, SocketSpy captures it at this breakpoint.
5. **Capture WinHTTP.** SocketSpy reads the addresses of `WinHttpConnect`,
   `WinHttpOpenRequest`, `WinHttpSendRequest`, and `WinHttpReadData` from the
   game's own import table. The loader binds this table at load time, so
   SocketSpy does not need to look up the module. SocketSpy hooks the entry
   point of each function with `0xCC`. This is safe because these functions are
   in the OS `winhttp.dll`, not in the protected game code. The hooks give the
   host, method, path, headers, and form parameters of each request.

   When `WinHttpReadData` returns, its buffer holds the response. The return
   address is in protected game code. So SocketSpy reads the response at a hardware
   breakpoint (`DR3`).
6. **Export.** When the game exits, SocketSpy writes `wss.json` and `rest.json`
   to the output directory.

## Build

Build the Linux binary on a Linux host:

```
cargo build --release
```

Cross-build the Windows binary from Linux with [`cargo-zigbuild`]:

```
cargo zigbuild --release --target x86_64-pc-windows-gnu
```

[`cargo-zigbuild`]: https://github.com/rust-cross/cargo-zigbuild

## Use

Start SocketSpy first, with one `--capture` value:

```
# Linux (needs ptrace permission: run as the same user with
# `sysctl kernel.yama.ptrace_scope=0`, or with sudo)
socketspy --dir ./capture --capture wss    # WebSocket / battle relay
socketspy --dir ./capture --capture rest   # RLink REST (aoe-api /game/...)
```

On Windows, run SocketSpy elevated or with `SeDebugPrivilege`. Without these
rights, SocketSpy cannot attach to the game.

Then start the game. When the game exits, SocketSpy writes `capture/wss.json`
and `capture/rest.json`. OpenSSL and libcurl cannot share the four debug
registers. So run SocketSpy once for each `--capture` value.

Options:

- `--capture <wss|rest>` — the stack to hook: `wss` for OpenSSL, `rest` for
  libcurl (default `rest`).
- `--dir <dir>` — output directory (default `.`). SocketSpy writes `wss.json`
  and `rest.json` there.
- `--exe <name>` — executable to wait for (default `AoE2DE_s.exe`).
- `--pid <id>` — attach to an already-running process instead of polling.
- `--poll-ms <n>` — poll interval while waiting (default 200 ms).
- `--no-breakpoints` — diagnostic: attach and locate, but set no breakpoints.

`RUST_LOG=debug` raises the log level.

## Output

**`rest.json`** — one record per HTTP request, from libcurl (the RLink REST API)
and from WinHTTP (Xbox, PlayFab, telemetry):

```json
{
  "pid": 4242,
  "requests": [
    {
      "seq": 1, "ts_ms": 5310,
      "method": "POST",
      "host": "aoe-api.worldsedgelink.com",
      "path": "/game/automatch2/polling",
      "query": [],
      "request_headers": [{ "name": "Content-Type", "value": "application/x-www-form-urlencoded" }],
      "request_params": [{ "name": "relayRegion", "value": "eastus" }],
      "response_body": "[0, ...]"
    }
  ]
}
```

**`wss.json`** — one record per OpenSSL/WebSocket buffer. The `decoded` field has
one of four values:

- `http` — an HTTP/1.x request or response, including the WebSocket upgrade.
- `http2_preface` — the HTTP/2 connection preface.
- `text` — a JSON operation in a WebSocket frame.
- `binary` — a WebSocket frame, kept whole as hex.

## Limitations

- **This is a debugger.** SocketSpy attaches to the game. In tests, a plain
  attach caused no problems for a full game session. Software breakpoints on
  the game's own (Themida-protected) code stop the game. So SocketSpy hooks
  OpenSSL and libcurl with hardware breakpoints. It patches only the OS
  `winhttp.dll`. Under Proton, this DLL comes from Wine.
- **Runtime testing needs the game.** Unit tests cover the parsing, locator,
  REST-correlation, JSON, and bookkeeping logic. End-to-end tests also check
  the locator against a real decrypted client image (see [Tests](#tests)). Only
  a test against the running game can exercise the attach-and-hook loop.
- **The Windows backend is not yet field-tested.** The Linux backend ran full
  game sessions. Both backends share the same hooks and pure logic. The Windows
  Debug API path is only cross-compiled and reviewed. It is not yet tested
  against the game.
- SocketSpy targets only the AoE2 OpenSSL build. Other titles share the engine
  but are not yet verified.

## Tests

```
cargo test
```

The locator has end-to-end tests against a real decrypted `AoE2DE_s.exe` image.
That image is not in the repository. To run these tests, set
`SOCKETSPY_TEST_DUMP` to the path of such an image. If the variable is not set,
the tests skip.

```
SOCKETSPY_TEST_DUMP=/path/to/decrypted-AoE2DE_s.exe cargo test
```

## License

AGPL-3.0-or-later. See [LICENSE](./LICENSE).
