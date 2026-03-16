import base64
import hashlib
import re
import ssl
import struct
from dataclasses import dataclass, field
from http.client import HTTPConnection, HTTPSConnection
from struct import unpack
from urllib.parse import urlparse

from cryptography import x509
from cryptography.hazmat.primitives import hashes as _crypto_hashes
from cryptography.hazmat.primitives.hashes import MD5 as _MD5
from cryptography.hazmat.primitives.hashes import SHA1 as _SHA1
from impacket import LOG
from impacket.ntlm import (
    AV_PAIRS,
    NTLMSSP_AV_CHANNEL_BINDINGS,
    NTLMSSP_AV_DNS_DOMAINNAME,
    NTLMSSP_AV_DNS_HOSTNAME,
    NTLMSSP_AV_DOMAINNAME,
    NTLMSSP_AV_FLAGS,
    NTLMSSP_AV_HOSTNAME,
    NTLMSSP_AV_TARGET_NAME,
    NTLMSSP_NEGOTIATE_56,
    NTLMSSP_NEGOTIATE_128,
    NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY,
    NTLMSSP_NEGOTIATE_NTLM,
    NTLMSSP_NEGOTIATE_UNICODE,
    NTLMAuthChallenge,
    NTLMAuthNegotiate,
    getNTLMSSPType3,
)

from webrelayx.util import shared
from webrelayx.util.cookies import report_pre_auth_cookies

# MsvAvFlags bit meanings
_AVFLAG_MIC_PRESENT = 0x00000002
_AVFLAG_SPN_PRESENT = 0x00000004

_SEP = "─" * 70


@dataclass
class ScanResult:
    url: str
    reachable: bool = False
    auth_required: bool = False
    auth_methods: list[str] = field(default_factory=list)
    is_https: bool = False
    ntlm_domain: str = ""
    ntlm_hostname: str = ""
    ntlm_dns_hostname: str = ""
    ntlm_dns_domain: str = ""
    ntlm_flags: int = 0
    ntlm_extended_security: bool = False
    avflag_mic_required: bool = False
    avflag_spn_required: bool = False
    spn_present: bool = False  # MsvAvTargetName in challenge
    channel_bindings_present: bool = False  # MsvAvChannelBindings in challenge
    # TLS / EPA fields (HTTPS only)
    cert_sha256: str = ""
    cbt_hex: str = ""
    epa_enforced: bool | None = None
    epa_verdict: str = "UNKNOWN"
    # All cookies issued by the server before authentication (on the 401).
    pre_auth_cookies: list[str] = field(default_factory=list)
    error: str = ""


def _make_negotiate() -> NTLMAuthNegotiate:
    neg = NTLMAuthNegotiate()
    neg["flags"] = (
        NTLMSSP_NEGOTIATE_UNICODE
        | NTLMSSP_NEGOTIATE_NTLM
        | NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY
        | NTLMSSP_NEGOTIATE_128
        | NTLMSSP_NEGOTIATE_56
    )
    return neg


def _make_negotiate_blob() -> bytes:
    return _make_negotiate().getData()


def _open_connection(hostname: str, port: int, is_https: bool) -> HTTPConnection:
    if is_https:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = (
            ssl.CERT_NONE
        )  # never verify ssl certs, this is a hacker tool after all haha
        return HTTPSConnection(hostname, port, context=ctx, timeout=3)
    return HTTPConnection(hostname, port, timeout=3)


def _extract_cert_der(conn: HTTPConnection) -> bytes | None:
    try:
        return conn.sock.getpeercert(binary_form=True)
    except Exception:
        return None


def _cert_cbt(cert_der: bytes) -> bytes:
    cert = x509.load_der_x509_certificate(cert_der)
    sig_alg = cert.signature_hash_algorithm
    if sig_alg is None or isinstance(sig_alg, (_MD5, _SHA1)):
        hash_alg: _crypto_hashes.HashAlgorithm = _crypto_hashes.SHA256()
    else:
        # Use same algorithm class with a fresh instance
        hash_alg = type(sig_alg)()

    dgst = _crypto_hashes.Hash(hash_alg)
    dgst.update(cert_der)
    cert_hash = dgst.finalize()

    token = b"tls-server-end-point:" + cert_hash
    # gss_channel_bindings_struct: 16 null bytes + uint32LE len + token
    binding_struct = b"\x00" * 16 + struct.pack("<I", len(token)) + token
    return hashlib.md5(binding_struct).digest()  # 16 bytes


def _av_str(av_pairs: AV_PAIRS, av_id: int) -> str:
    entry = av_pairs[av_id]
    if entry is None:
        return ""
    try:
        return entry[1].decode("utf-16-le")
    except Exception:
        return entry[1].hex()


def _probe_target(url: str) -> ScanResult:
    result = ScanResult(url=url)
    parsed = urlparse(url)

    scheme = parsed.scheme.lower()
    result.is_https = scheme == "https"
    hostname = parsed.hostname or ""
    port = parsed.port or (443 if result.is_https else 80)
    path = parsed.path or "/"
    if parsed.query:
        path = path + "?" + parsed.query

    try:
        conn = _open_connection(hostname, port, result.is_https)
        conn.request("GET", path)
        res = conn.getresponse()
        res.read()
        result.reachable = True
    except Exception as exc:
        result.error = "Connection failed: %s" % exc
        return result

    if res.status != 401:
        result.auth_required = False
        # Still record any auth header even on non-401, some servers return 200
        www = res.getheader("WWW-Authenticate", "")
        if www:
            result.auth_methods = [m.strip().split()[0] for m in www.split(",")]
        return result

    result.auth_required = True
    www = res.getheader("WWW-Authenticate", "") or ""
    result.auth_methods = [m.strip().split()[0] for m in www.split(",") if m.strip()]

    # Collect all Set-Cookie headers from the 401 response.
    result.pre_auth_cookies = res.headers.get_all("Set-Cookie") or []

    has_ntlm = any(m.upper() in ("NTLM", "NEGOTIATE") for m in result.auth_methods)
    if not has_ntlm:
        result.epa_verdict = "NOT DETECTED"
        return result

    auth_method = (
        "Negotiate"
        if any(m.upper() == "NEGOTIATE" for m in result.auth_methods)
        else "NTLM"
    )

    try:
        neg_obj = _make_negotiate()
        negotiate_b64 = base64.b64encode(neg_obj.getData()).decode("ascii")
        conn2 = _open_connection(hostname, port, result.is_https)
        conn2.request(
            "GET",
            path,
            headers={"Authorization": "%s %s" % (auth_method, negotiate_b64)},
        )
        res2 = conn2.getresponse()
        res2.read()
    except Exception as exc:
        result.error = "NTLM negotiate failed: %s" % exc
        return result

    www2 = res2.getheader("WWW-Authenticate", "") or ""

    m = re.search(r"(?:NTLM|Negotiate)\s+([a-zA-Z0-9+/]+=*)", www2)
    if not m:
        result.error = "No NTLM challenge in response"
        return result

    try:
        raw_challenge = base64.b64decode(m.group(1))
        challenge = NTLMAuthChallenge()
        challenge.fromString(raw_challenge)
    except Exception as exc:
        result.error = "Failed to parse NTLM challenge: %s" % exc
        return result

    result.ntlm_flags = int(challenge["flags"])
    result.ntlm_extended_security = bool(
        result.ntlm_flags & NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY
    )

    # AV pairs
    try:
        av_pairs = AV_PAIRS(challenge["TargetInfoFields"])
        result.ntlm_domain = _av_str(av_pairs, NTLMSSP_AV_DOMAINNAME)
        result.ntlm_hostname = _av_str(av_pairs, NTLMSSP_AV_HOSTNAME)
        result.ntlm_dns_hostname = _av_str(av_pairs, NTLMSSP_AV_DNS_HOSTNAME)
        result.ntlm_dns_domain = _av_str(av_pairs, NTLMSSP_AV_DNS_DOMAINNAME)

        av_flags_entry = av_pairs[NTLMSSP_AV_FLAGS]
        if av_flags_entry is not None:
            av_flags_val = struct.unpack("<I", av_flags_entry[1])[0]
            result.avflag_mic_required = bool(av_flags_val & _AVFLAG_MIC_PRESENT)
            result.avflag_spn_required = bool(av_flags_val & _AVFLAG_SPN_PRESENT)

        result.spn_present = av_pairs[NTLMSSP_AV_TARGET_NAME] is not None
        result.channel_bindings_present = (
            av_pairs[NTLMSSP_AV_CHANNEL_BINDINGS] is not None
        )
    except Exception as exc:
        result.error = "AV pair parsing error: %s" % exc

    # Check for EPA
    if result.is_https:
        cert_der = _extract_cert_der(conn2)
        if cert_der:
            result.cert_sha256 = hashlib.sha256(cert_der).hexdigest()
            try:
                result.cbt_hex = _cert_cbt(cert_der).hex()
            except Exception as exc:
                LOG.debug("CBT computation failed: %s", exc)

        # null CBT check
        try:
            type3_msg, _ = getNTLMSSPType3(
                neg_obj,
                raw_challenge,
                user="",
                password="",
                domain="",
                channel_binding_value=b"\x00" * 16,  # null CBT = no binding
                service="http",
            )
            type3_b64 = base64.b64encode(type3_msg.getData()).decode("ascii")
            conn2.request(
                "GET",
                path,
                headers={"Authorization": "%s %s" % (auth_method, type3_b64)},
            )
            res3 = conn2.getresponse()
            www3 = res3.getheader("WWW-Authenticate", "") or ""
            res3.read()

            has_new_challenge = bool(
                re.search(r"(?:NTLM|Negotiate)\s+[a-zA-Z0-9+/]{20,}=*", www3)
            )
            if res3.status == 403:
                # Hard rejection by server: EPA
                result.epa_enforced = True
            elif res3.status == 401 and not has_new_challenge:
                # 401 but no fresh NTLM challenge blob: EPA
                result.epa_enforced = True
            elif res3.status == 401 and has_new_challenge:
                # Server issued a fresh challenge: Null CBT accepted -> NO EPA
                result.epa_enforced = False
        except Exception as exc:
            LOG.debug("EPA active probe failed: %s", exc)
            result.epa_enforced = None

    result.epa_verdict = _epa_verdict(result)
    return result


def _epa_verdict(r: ScanResult) -> str:
    if not r.is_https:
        return "NOT APPLICABLE (HTTP only)"

    # Active probe result
    if r.epa_enforced is True:
        return "ENFORCED"
    if r.epa_enforced is False:
        return "NOT ENFORCED"

    # Fall back to passive
    if r.channel_bindings_present:
        return "CONFIGURED (enforcement unknown: active probe failed)"
    return "NOT CONFIGURED"


def _print_result(r: ScanResult) -> None:
    print(_SEP)
    print("Target : %s" % r.url)
    if r.error and not r.reachable:
        print("Status : UNREACHABLE: %s" % r.error)
        return
    if not r.reachable:
        print("Status : UNREACHABLE")
        return

    print(
        "Status : Reachable  |  Auth required: %s"
        % ("Yes" if r.auth_required else "No")
    )

    if r.auth_methods:
        print("Auth   : %s" % ", ".join(r.auth_methods))
    else:
        print("Auth   : none advertised")

    if not r.auth_required:
        if r.error:
            print("Note   : %s" % r.error)
        return

    if r.error:
        print("Error  : %s" % r.error)

    if r.ntlm_domain or r.ntlm_hostname:
        print("")
        print("NTLM Challenge info:")
        if r.ntlm_domain:
            print("  Domain       : %s" % r.ntlm_domain)
        if r.ntlm_hostname:
            print("  NetBIOS host : %s" % r.ntlm_hostname)
        if r.ntlm_dns_hostname:
            print("  DNS hostname : %s" % r.ntlm_dns_hostname)
        if r.ntlm_dns_domain:
            print("  DNS domain   : %s" % r.ntlm_dns_domain)
        print("  Extended sec : %s" % r.ntlm_extended_security)
        print("  MIC required : %s" % r.avflag_mic_required)
        print("  SPN required : %s" % r.avflag_spn_required)
        print("  SPN present  : %s" % r.spn_present)
        print("  CBT present  : %s" % r.channel_bindings_present)

    print("")
    tls_label = "HTTPS (TLS)" if r.is_https else "HTTP (no TLS)"
    print("Transport : %s" % tls_label)
    if r.is_https and r.cert_sha256:
        print("Cert SHA-256 : %s" % r.cert_sha256)
    if r.cbt_hex:
        print("Channel binding token (CBT) : %s" % r.cbt_hex)
        print("  (use this value in the relay's MsvAvChannelBindings to bypass EPA)")
    print("EPA status: %s" % r.epa_verdict)

    if r.pre_auth_cookies:
        print("")
        report_pre_auth_cookies(r.pre_auth_cookies, r.url)


def run_scan(targets: list[str]) -> list[ScanResult]:
    results = []
    LOG.info("Starting NTLM/EPA scan of %d target(s)", len(targets))
    for url in targets:
        url = shared._normalize_url(url)
        LOG.debug("Scanning %s", url)
        r = _probe_target(url)
        _print_result(r)
        results.append(r)
    print(_SEP)
    # Summary
    ntlm_targets = [r for r in results if r.auth_required]
    epa_likely = [
        r
        for r in results
        if "likely" in r.epa_verdict.lower() or "configured" in r.epa_verdict.lower()
    ]
    preauth_cookies = [r for r in results if r.pre_auth_cookies]
    print(
        "Summary: %d/%d targets require NTLM auth  |  %d with EPA configured/likely  |  %d with pre-auth cookie(s)"
        % (len(ntlm_targets), len(results), len(epa_likely), len(preauth_cookies))
    )
    print(_SEP)
    return results
