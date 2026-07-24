"""Self-signed TLS certificate generation via openssl CLI."""

import os
import subprocess


def generate_self_signed_cert(directory, cert_name="ircd.crt", key_name="ircd.key"):
    """Generate a self-signed certificate and key in the given directory.

    Returns (cert_path, key_path).
    """
    cert_path = os.path.join(directory, cert_name)
    key_path = os.path.join(directory, key_name)

    subprocess.run(
        [
            "openssl", "req", "-x509", "-newkey", "rsa:2048",
            "-keyout", key_path, "-out", cert_path,
            "-days", "1", "-nodes",
            "-subj", "/CN=irc.test/O=BahamutTest",
        ],
        check=True,
        capture_output=True,
    )

    return cert_path, key_path
