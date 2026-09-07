"""TLS for remote connections; plaintext is restricted to loopback addresses."""

import ipaddress
import ssl

from .config import TLS


MINIMUM_TLS_VERSION = ssl.TLSVersion[TLS["minimum_version"]]

def require_local_address(host):
    try:
        if ipaddress.ip_address(host).is_loopback:
            return
    except ValueError:
        pass
    raise ValueError("Connections without TLS require a loopback IP, such as 127.0.0.1.")


def server_context(host, certfile=None, keyfile=None):
    if bool(certfile) != bool(keyfile):
        raise ValueError("Supply both --cert and --key.")
    if not certfile:
        require_local_address(host)
        return None
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = MINIMUM_TLS_VERSION
    context.load_cert_chain(certfile, keyfile)
    return context


def client_context(host, tls=False, cafile=None):
    if cafile and not tls:
        raise ValueError("--cafile requires --tls.")
    if not tls:
        require_local_address(host)
        return None
    context = ssl.create_default_context(cafile=cafile)
    context.minimum_version = MINIMUM_TLS_VERSION
    return context
