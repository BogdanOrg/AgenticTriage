"""CWE-319: Cleartext Transmission of Sensitive Information.

Credentials and an API token are sent over plain HTTP, so they can be read by
anyone on the network path. The fix is to use an https:// URL (TLS).
"""

import urllib.request
import json


def authenticate(username: str, password: str, api_token: str) -> int:
    # CWE-319: sensitive data sent over an unencrypted HTTP connection
    url = "http://api.example.com/v1/login"
    payload = json.dumps({"username": username, "password": password}).encode("utf-8")

    request = urllib.request.Request(url, data=payload, method="POST")
    request.add_header("Content-Type", "application/json")
    # API token transmitted in cleartext header
    request.add_header("Authorization", f"Bearer {api_token}")

    with urllib.request.urlopen(request) as response:
        return response.status


if __name__ == "__main__":
    authenticate("alice", "S3cr3tP@ss", "tok_live_abc123")
