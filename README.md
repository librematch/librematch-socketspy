# Libre:Match SocketSpy

Trace an Age of Empires: Definitive Edition client's TLS traffic and export it as
structured JSON, for reverse-engineering the RelicLink lobby and relay protocol.

The client sends over three TLS stacks. SocketSpy attaches to the running game
as a debugger and hooks each stack at its own boundary — OpenSSL's
`SSL_write`/`SSL_read`, libcurl's `curl_easy_setopt`, and the WinHTTP request
API — recording the cleartext each side sees. It reads the plaintext; it does
not decrypt anything and stores no keys.

It runs on **Linux** (the game under Proton/Wine) and on **Windows** (the game
native). One binary: start it, launch the game, stop the game — the capture is
written to JSON.

The client sends traffic over **three** stacks, so SocketSpy hooks each at the
right layer. Only four CPU debug registers exist, so the two heavy stacks are
captured in separate runs, chosen with `--capture`:

- **OpenSSL** carries the WebSocket traffic — the presence socket and the
  battle-server relay (the multiplayer game API). `--capture wss` → `wss.json`.
- **libcurl** carries the RLink REST API (`aoe-api.worldsedgelink.com`,
  `POST /game/...`) over SChannel, invisible to OpenSSL. `--capture rest` hooks
  `curl_easy_setopt` → `rest.json`.
- **WinHTTP** carries Xbox/PlayFab/telemetry. Captured in both modes →
  `rest.json`.

## How it works

1. **Wait and attach.** The binary polls for the game process (`AoE2DE_s.exe` by
   default) and attaches: `ptrace` on Linux, the Debug API on Windows.
2. **Locate OpenSSL.** The client's code is decrypted only in memory, so the
   functions have no fixed address. SocketSpy finds them by structure: the
   `ssl\ssl_lib.c` source string, the `ERR_put_error` call sites that reference
   it, the OpenSSL function codes at those sites, and the `.pdata` table that
   maps a site to its function start. No hardcoded offsets, so it survives game
   patches as long as the OpenSSL build stays 1.1-shaped.
3. **Capture OpenSSL (`--capture wss`) with hardware breakpoints.**
   `ssl_write_internal` (send) and `SSL_read` (receive) live in the game's
   integrity-protected code, which kills the game if patched. So they are hooked
   with the CPU debug registers, which modify no code. Each buffer is parsed as
   HTTP or WebSocket.
3b. **Capture libcurl REST (`--capture rest`) with hardware breakpoints.**
   `curl_easy_setopt` is located structurally — scan `.text` for
   `mov edx, 10002` (`CURLOPT_URL`, stable across builds) followed by the `call`,
   and take the consensus target. A debug-register breakpoint there reads each
   request's URL, method, headers, and body. When the request sets
   `CURLOPT_WRITEFUNCTION`, its callback address is read from that same call and
   given a second debug-register breakpoint, so the response body is captured as
   libcurl delivers it. No hardcoded address.
4. **Capture WinHTTP.** The addresses of `WinHttpConnect`,
   `WinHttpOpenRequest`, `WinHttpSendRequest`, and `WinHttpReadData` are read
   from the game's own import table (bound at load), so no module lookup is
   needed. The entries are hooked with `0xCC` — safe because they are in the OS
   `winhttp.dll`, not the game's protected code — giving the host, method, path,
   headers, and form parameters of each request. `WinHttpReadData` fills its
   buffer on return, and that return address is in protected game code, so the
   response is read at a hardware breakpoint (`DR3`).
5. **Export.** On game exit, `wss.json` and `rest.json` are written to the output
   directory.

## Build

Native (Linux host, for the Linux tracer):

```
cargo build --release
```

Cross-build the Windows binary from Linux with [`cargo-zigbuild`]:

```
cargo zigbuild --release --target x86_64-pc-windows-gnu
```

[`cargo-zigbuild`]: https://github.com/rust-cross/cargo-zigbuild

## Use

Start SocketSpy **before** launching the game, then start the game:

```
# Linux (needs ptrace permission: run as the same user with
# `sysctl kernel.yama.ptrace_scope=0`, or with sudo)
socketspy --dir ./capture --capture wss    # WebSocket / battle relay
socketspy --dir ./capture --capture rest   # RLink REST (aoe-api /game/...)
```

Run once per stack (they can't share the four debug registers). Each run writes
`capture/wss.json` and `capture/rest.json` when the game exits.

Options:

- `--capture <wss|rest>` — which stack to hook (default `rest`, the RLink game
  API).
- `--dir <dir>` — output directory (default `.`); receives `wss.json` and
  `rest.json`.
- `--exe <name>` — executable to wait for (default `AoE2DE_s.exe`).
- `--pid <id>` — attach to an already-running process instead of polling.
- `--poll-ms <n>` — poll interval while waiting (default 200).
- `--no-breakpoints` — diagnostic: attach and locate but set no breakpoints.

`RUST_LOG=debug` raises the log level.

## Output

**`rest.json`** — the RLink REST requests, one per WinHTTP request:

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

**`wss.json`** — one record per OpenSSL/WebSocket buffer. `decoded` is `http`
(an HTTP/1.x request or response, including the WebSocket upgrade), `http2_preface`,
`text` (a JSON operation carried in a WebSocket frame), or `binary` (a WebSocket
frame kept whole as hex).

## Limitations

- **This is a debugger.** It attaches to the game. A plain attach was observed to
  be harmless for a full session. But software breakpoints on the game's own
  (Themida-protected) code are not. So OpenSSL and libcurl are hooked with
  hardware breakpoints, and only the OS `winhttp.dll` is patched (Wine's under
  Proton, the system's on Windows).
- **Runtime testing needs the game.** The parsing, locator, REST-correlation,
  JSON and bookkeeping logic is unit-tested, and the locator is checked end to
  end against a real decrypted client image (see below). The attach-and-hook
  loop can only be exercised against the running game.
- **The Windows backend is not yet field-tested.** The Linux backend has run full
  game sessions. Both share the same hooks and pure logic, but the Windows Debug
  API path has only been cross-compiled and reviewed. Run it elevated (or with
  `SeDebugPrivilege`) so it can attach.
- Only the AoE2 OpenSSL build is targeted. Other titles share the engine but are
  not yet verified.

## Tests

```
cargo test
```

The locator has an end-to-end test against a real decrypted `AoE2DE_s.exe`
image. That image is not in the repository; point `SOCKETSPY_TEST_DUMP` at one
to run it, otherwise the test skips:

```
SOCKETSPY_TEST_DUMP=/path/to/decrypted-AoE2DE_s.exe cargo test
```

## License

GPL-3.0-or-later. See [LICENSE](./LICENSE).
