# ThatMyAssets AgentWork

Windows endpoint vertical slice: authoritative SCM service, browser Native Messaging relay, text detector/policy engine, restricted parser process, durable metadata queue, diagnostics and single-file installer. Rust only; no Python or .NET.

## Current protection boundary

**Text-only inspection.** Accepted file extensions: `txt,csv,json,xml,yaml,yml,log,env,sql,py,js,ts,go,rs`; prompts are text. Files and prompts must be UTF-8 and at most 768 KiB decoded, within 64 nesting levels and the 1 MiB Native Messaging frame. Unsupported, malformed, oversized or over-deep input returns non-complete inspection and follows `failure_mode` (`block` by default). There is no OCR, image/PDF/Office parsing, archive extraction, endpoint clipboard/file-system interception, network interception or desktop enforcement. Complex documents are outside this slice; the isolated `tma-parser` explicitly returns `unsupported_format` and is never a clean-path shortcut.

The extension enforces supported browser routes and confirms enforcement. A response is not confirmation. Local service records `pending` until `enforcement_result` arrives. Events contain metadata and detector names only: never raw prompt/file text, matched values, credential values or bytes.

## Prerequisites

- 64-bit Windows 10/11 or Windows Server with Chrome/Edge.
- Rust toolchain (`rustup`), stable 1.80 or newer; MSVC x64 target and Visual Studio C++ Build Tools.
- Administrator shell for install/repair/upgrade/uninstall.
- Running TMA-Dashboard control plane and one-time pairing code for enrollment. See its repository for server commands.

## Build and test

```powershell
cargo test --workspace
# Build all agent executables, then embed compressed copies in standalone setup.exe.
cargo build --release -p tma-agent
$env:TMA_PAYLOAD_DIR = "$PWD\target\release"
cargo build --release -p tma-installer
New-Item -ItemType Directory -Force dist
Copy-Item target/release/tma-installer.exe dist/setup.exe
Remove-Item Env:TMA_PAYLOAD_DIR
```

`dist/setup.exe` is standalone offline installer: its build script embeds zlib-compressed `tma-agent.exe`, `tma-relay.exe`, `tma-parser.exe` and `tma-doctor.exe`. Payload directory is needed only while building installer, not while running it. Explicit development path: build installer without `TMA_PAYLOAD_DIR` and keep those four binaries beside `tma-installer.exe`.

GitHub Actions builds and publishes the same installer when a `v*` tag is pushed. The release includes `TMA-Agent-Setup.exe` and `SHA256SUMS.txt`; formatting, Clippy, and workspace tests must pass before publication.

Launch `dist\setup.exe` without arguments for native Windows setup. Choose **Install agent**, **Repair / upgrade**, or **Uninstall**. The form validates the control-plane URL, one-time pairing code, required Chrome extension ID and optional Edge ID before requesting UAC elevation. For a lab Control Plane over plain HTTP, select **Development mode — allow direct HTTP to a lab Control Plane** in the installer. It is unchecked by default for safety and its choice is saved in `config.json`; HTTPS does not require this option. Work runs in a separate elevated process; the window reports actual setup stages and errors without freezing. **Recheck health** queries the installed service over authenticated IPC. Setup never claims `Protected` from service startup alone: enrollment, policy readiness and browser connection must be confirmed by health.

The same executable retains all CLI commands below. GUI repair with every connection field blank preserves existing configuration. Uninstall retains data by default; selecting purge shows an explicit irreversible-data warning before removing queued events, enrollment and policy.

## Install, pair and start

```powershell
$env:TMA_DEVELOPMENT = "true"
$env:TMA_CONTROL_PLANE_URL = "http://43.157.201.52:18080"
$env:TMA_PAIRING_CODE = "one-time-code-from-admin"
$env:TMA_CHROME_EXTENSION_ID = "extension-id-from-chrome-web-store-or-unpacked-load"
.\dist\setup.exe install
```

Installer creates `C:\Program Files\ThatMyAssets\Agent` and `C:\ProgramData\ThatMyAssets`, protected random IPC credential, SQLite queue and default policy. Service name is `TMAAgent`, `SERVICE_AUTO_START`, runs as `NT AUTHORITY\LocalService`, starts immediately and has restart recovery after 5 s, 15 s and 60 s. Service runs before logon; browser relay starts on demand when a browser connects. Install/repair/upgrade preserve local queue, enrollment, control-plane URL and IPC credential. Set `TMA_ROTATE_IPC_CREDENTIAL=1` only when intentional credential rotation is required. `TMA_EDGE_EXTENSION_ID` can additionally configure an Edge allowlist entry for CLI installation.

Native host name is **`com.thatmyassets.dlp`**. Installer writes `%ProgramData%\ThatMyAssets\native-host.json` and HKLM Chrome/Edge NativeMessagingHosts keys. Empty extension allowlist denies all browsers. Set an actual packed/unpacked extension ID before expecting a connection; add a distinct Edge ID if needed:

```powershell
.\dist\setup.exe register-extension <chrome-extension-id> [edge-extension-id]
```

Service pairing is performed at first synchronization using the one-time code. Pairing code and device token are not command-line arguments, events or logs. Device token is stored in ACL-protected `%ProgramData%\ThatMyAssets\device-token`; only service, LocalService, SYSTEM and Administrators can read it. Set `TMA_DEVELOPMENT=true` for direct HTTP control-plane URLs; the installer stores this as `development:true` in `config.json`, or an existing config can set that field directly. **Development only:** plain HTTP exposes enrollment and device traffic on the network. Use HTTPS in production; without development mode, HTTP remains restricted to loopback.

## Diagnostics and local operation

```powershell
& 'C:\Program Files\ThatMyAssets\Agent\tma-doctor.exe' status
& 'C:\Program Files\ThatMyAssets\Agent\tma-doctor.exe' health
& 'C:\Program Files\ThatMyAssets\Agent\tma-doctor.exe' queue
& 'C:\Program Files\ThatMyAssets\Agent\tma-doctor.exe' sync
& 'C:\Program Files\ThatMyAssets\Agent\tma-doctor.exe' verify-store
```

`status` reports installed binary, SCM state/start mode, IPC presence/ACL configuration, parser binary and browser registration. `queue` prints counts, never event bodies. SQLite uses WAL, bounded retry batches and exponential backoff. Events upload to authenticated `/api/v1/events`, idempotently keyed by event UUID. Unavailable control plane does not drop events or make local inspection clean/allow.

Development console health check (does not create a Windows service or Native Messaging listener):

```powershell
$env:TMA_DATA_DIR = "$PWD\dev-data"
# Create config.json with install_dir, a random ipc_credential of at least 32 characters, and development:true when using a direct HTTP URL.
cargo run --bin tma-agent -- --console
```

## Upgrade and removal

Place new installer and four new binaries in one staging directory, then:

```powershell
.\staging\tma-installer.exe upgrade
# Remove service/binaries but preserve enrollment and queued events:
.\staging\tma-installer.exe uninstall
# Permanently remove local events and enrollment too:
.\staging\tma-installer.exe uninstall --purge
```

## Protocol summary

Standard unsigned 32-bit little-endian length prefix, JSON body, maximum 1 MiB. Browser → `tma-relay` → ACL-restricted `\\.\pipe\ThatMyAssetsAgent` → service. Relay adds request-body-bound HMAC-SHA-256 using a per-install random credential. It performs no detection or policy decisions. Health, inspection and enforcement-result messages may share one persistent port; each request/response is sequential.

`file` is `{name,content_base64}`; `prompt` is `{text}`. Exactly one is non-null. Inspection response has `inspection_status`, `inspection_complete`, `decision`, `risk_score`, findings, `policy_version`, `event_id`. Browser sends separate `enforcement_result` request and receives `{type:"enforcement_result_ack",request_id,event_id,accepted}`. `accepted:false` means unknown event, not successful acknowledgement.

Default policy blocks high+ credential/private key findings, audits medium+ PII/financial findings, and allows only complete inspection with no matching rule. Lowest rule priority number wins; empty provider list means all. Detector coverage: PEM private keys, AWS access key IDs, GitHub tokens, JWT-shaped credentials, high-confidence API-key assignments, Luhn-valid credit cards, context-qualified 16-digit NIK, email addresses. These deterministic detectors are not a guarantee against evasion or all sensitive data.

## Repository checks

GitHub Actions runs formatting check, Clippy, tests and release build on `windows-latest`. No test content is sent to a control plane. Self-tests cover detector true/false positives and malformed input, policy precedence/fail-closed behavior, protocol lengths/auth/semantic validation, and SQLite persistence/idempotency.
