# WebRelayX

WebRelayX is an NTLM relay tool focused on Web (http/s) targets. It builds on impacket's ntlmrelayx and adds cookie harvesting and auth scan.

The goal of this tool is to automate NTLM-Relaying to targets other than ADCS or Exchange, by harvesting session cookies before or after successful authentication.

**This tool is for educational and authorized testing purposes only. Do not use it without permission. We are not responsible for any misuse.**

Created and maintained by [SecCore GmbH](https://seccore.at).

## Requirements

- Python 3.13+
- [impacket](https://github.com/fortra/impacket) >= 0.13
- root user to bind to privileged ports (445, 80, etc.)

## Installation

```
pipx install git+https://github.com/SecCoreGmbH/WebRelayX
```

Or clone and install locally:

```
git clone https://github.com/SecCoreGmbH/WebRelayX
cd WebRelayX
pipx install .
```

Or with Poetry:

```
poetry install
```

### Playwright
We use playwright to automate browser interactions for `--open-browser` and `launch` subcommands. This tools attempts to install playwright and the browser binaries automatically.

## Subcommands

### scan

Probes one or more HTTP/HTTPS targets for NTLM authentication and reports:

- If auth is required and NTLM can be used for authentication
- NTLM domain, hostname, and DNS info from the challenge
- MIC and SPN enforcement flags
- EPA status **(WIP!)**
    - I still need some more test data and understanding about how to detect EPA reliably. May not work correctly!

```
webrelayx scan -t http://intranet.demo.internal
webrelayx scan -t http://intranet.demo.internal -t https://sharepoint.demo.internal
webrelayx scan -tf targets.txt
```

### relay

Starts relay listeners (SMB, HTTP, WCF, RAW, RPC, WinRM) and relays incoming NTLM authentication to the specified HTTP/HTTPS targets. Captured session cookies are printed to stdout and optionally written to a file.

```
# basic relay, outputs cookies to terminal
sudo webrelayx relay -t http://intranet.demo.internal

# relay and store cookies in cookies.json
sudo webrelayx relay -t https://intranet.demo.internal -o cookies.json

# relay without SMB or WCF server
sudo webrelayx relay -t http://intranet.demo.internal --no-smb-server --no-wcf-server

# automatically open a browser with the injected session cookies
sudo webrelayx relay -t http://intranet.demo.internal --open-browser
```

The browser stays open until you close the tab. The relay listener keeps running in the background.

### list
Lists captured sessions from cookies.jsonl with index, user and target. Use this index to launch with `launch` subcommand.

```
webrelayx list
```

### launch
launches a browser with the cookies from a saved session in cookies.json. Use `list` to get the cookie index.
```
# launch first session with default browser
webrelayx launch -i 0
# launch second session with firefox
webrelayx launch -i 1 --browser firefox
```

## Options

### Common

| Flag | Description |
|---|---|
| `-t`, `--target` | Target URL (repeatable) |
| `-tf`, `--targets-file` | File with one target URL per line |
| `-v`, `--verbose` | Enable debug logging |

### relay

| Flag | Default | Description |
|---|---|---|
| `-l`, `--listen-ip` | `0.0.0.0` | IP to bind all listeners to |
| `--no-smb-server` | - | Disable SMB listener |
| `--no-http-server` | - | Disable HTTP listener |
| `--no-wcf-server` | - | Disable WCF listener |
| `--no-raw-server` | - | Disable RAW listener |
| `--no-rpc-server` | - | Disable RPC listener |
| `--no-winrm-server` | - | Disable WinRM/WinRMS listeners |
| `-b`, `--open-browser` | - | Open browser with captured cookies after relay |
| `--browser` | `chromium` | Select browser to launch cookie injection with |

### launch
| Flag | Default | Description |
|---|---|---|
| `-i`, `--index` | - | Session from cookie jsonl |
| `--browser` | `chromium` | Select browser to launch cookie injection with |