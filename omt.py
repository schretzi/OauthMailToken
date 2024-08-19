#
# Mutt OAuth2 token management script, version 2020-08-07
# Written against python 3.7.3, not tried with earlier python versions.
#
#   Copyright (C) 2020 Alexander Perlis
#
#   This program is free software; you can redistribute it and/or
#   modify it under the terms of the GNU General Public License as
#   published by the Free Software Foundation; either version 2 of the
#   License, or (at your option) any later version.
#
#   This program is distributed in the hope that it will be useful,
#   but WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
#   General Public License for more details.
#
#   You should have received a copy of the GNU General Public License
#   along with this program; if not, write to the Free Software
#   Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
#   02110-1301, USA.
"""Mutt OAuth2 token management"""

import keyring
import yaml
import sys
import json
import argparse
import urllib.parse
import urllib.request
import imaplib
import poplib
import smtplib
import base64
import secrets
import hashlib
import time
from datetime import timedelta, datetime
from pathlib import Path
import socket
import http.server
import subprocess
import readline
from pprint import pprint as pp
from xdg.BaseDirectory import load_first_config
import os

conf_dir = load_first_config("omt")
if conf_dir:
    conf_path = os.path.join(conf_dir, "config.yaml")

authcode = ""

with open(conf_path, "r") as configfile:
    config = yaml.load(configfile, Loader=yaml.FullLoader)


ap = argparse.ArgumentParser(
    epilog="""
This script obtains and prints a valid OAuth2 access token.  State is maintained in an
encrypted TOKENFILE.  Run with "--verbose --authorize" to get started or whenever all
tokens have expired, optionally with "--authflow" to override the default authorization
flow.  To truly start over from scratch, first delete TOKENFILE.  Use "--verbose --test"
to test the IMAP/POP/SMTP endpoints.
"""
)
ap.add_argument("-v", "--verbose", action="store_true", help="increase verbosity")
ap.add_argument("-d", "--debug", action="store_true", help="enable debug output")
ap.add_argument("account", help="account name")
ap.add_argument(
    "-a", "--authorize", action="store_true", help="manually authorize new tokens"
)
ap.add_argument("--authflow", help="authcode | localhostauthcode | devicecode")
ap.add_argument(
    "-t", "--test", action="store_true", help="test IMAP/POP/SMTP endpoints"
)
args = ap.parse_args()

keyringSystem = "OauthMailToken"


def writeToken():
    keyring.set_password(keyringSystem, args.account, json.dumps(token))


def readToken():
    if "storage" not in config["global"]:
        print("Storage not set, trying keyring with system backend")
        config["global"]["storage"] = "keyring"
        config["global"]["keyring-backend"] = "system"

    if config["global"]["storage"] == "keyring":
        if "keyring-backend" not in config["global"]:
            print("Keyring Backend not set, trying keyring with system backend")
            config["global"]["keyring-backend"] = "system"

    result = keyring.get_password(keyringSystem, args.account)
    if not result or result == "null":
        return None
    else:
        return json.loads(result)


def authorize():
    provider = config["global"][config["accounts"][args.account]["provider"]]

    if (
        "authflow" not in config["accounts"][args.account]
        or not config["accounts"][args.account]["authflow"]
    ):
        if args.authflow:
            config["accounts"][args.account]["authflow"] = args.authflow
        else:
            config["accounts"][args.account]["authflow"] = input(
                'Preferred OAuth2 flow ("authcode" or "localhostauthcode" '
                'or "devicecode"): '
            )

    p = {"client_id": provider["client_id"]}
    # Microsoft uses 'tenant' but Google does not
    if "tenant" in provider:
        p["tenant"] = provider["tenant"]
    p["scope"] = provider["scope"]
    if config["accounts"][args.account]["authflow"] in (
        "authcode",
        "localhostauthcode",
    ):
        response = authorizeAuthcode(p, provider)
    elif config["accounts"][args.account]["authflow"] == "devicecode":
        response = authorizeDevicecode(p, provider)
    else:
        sys.exit(
            f'ERROR: Unknown OAuth2 flow "{token["authflow"]}. Delete token file and '
            f'start over.'
        )

    update_tokens(response)


def access_token_valid():
    """Returns True when stored access token exists and is still valid at this time."""
    token_exp = token["access_token_expiration"]
    return token_exp and datetime.now() < datetime.fromisoformat(token_exp)


def update_tokens(r):
    """Takes a response dictionary, extracts tokens out of it, and updates token file."""
    global token
    if token is None:
        token = {}
    token["access_token"] = r["access_token"]
    token["access_token_expiration"] = (
        datetime.now() + timedelta(seconds=int(r["expires_in"]))
    ).isoformat()
    if "refresh_token" in r:
        token["refresh_token"] = r["refresh_token"]
    writeToken()
    if args.verbose:
        print(
            f'NOTICE: Obtained new access token, expires {token["access_token_expiration"]}.'
        )
    print(token["refresh_token"])


def authorizeAuthcode(p, provider):
    global authcode
    verifier = secrets.token_urlsafe(90)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest())[
        :-1
    ]
    redirect_uri = provider["redirect_uri"]
    listen_port = 0
    if config["accounts"][args.account]["authflow"] == "localhostauthcode":
        # Find an available port to listen on
        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        listen_port = s.getsockname()[1]
        s.close()
        redirect_uri = "http://localhost:" + str(listen_port) + "/"
        # Probably should edit the port number into the actual redirect URL.

    p.update(
        {
            "login_hint": args.account,
            "response_type": "code",
            "redirect_uri": redirect_uri,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
        }
    )
    print(
        provider["authorize_endpoint"]
        + "?"
        + urllib.parse.urlencode(p, quote_via=urllib.parse.quote)
    )

    if config["accounts"][args.account]["authflow"] == "authcode":
        authcode = input(
            "Visit displayed URL to retrieve authorization code. Enter "
            "code from server (might be in browser address bar): "
        )
    else:
        print(
            "Visit displayed URL to authorize this application. Waiting...",
            end="",
            flush=True,
        )

        class MyHandler(http.server.BaseHTTPRequestHandler):
            """Handles the browser query resulting from redirect to redirect_uri."""

            # pylint: disable=C0103
            def do_HEAD(self):
                """Response to a HEAD requests."""
                self.send_response(200)
                self.send_header("Content-type", "text/html")
                self.end_headers()

            def do_GET(self):
                """For GET request, extract code parameter from URL."""
                # pylint: disable=W0603
                global authcode
                querystring = urllib.parse.urlparse(self.path).query
                querydict = urllib.parse.parse_qs(querystring)
                if "code" in querydict:
                    authcode = querydict["code"][0]
                self.do_HEAD()
                self.wfile.write(
                    b"<html><head><title>Authorizaton result</title></head>"
                )
                self.wfile.write(
                    b"<body><p>Authorization redirect completed. You may "
                    b"close this window.</p></body></html>"
                )

        with http.server.HTTPServer(("127.0.0.1", listen_port), MyHandler) as httpd:
            try:
                httpd.handle_request()
            except KeyboardInterrupt:
                pass

    if not authcode:
        sys.exit("Did not obtain an authcode.")

    for k in (
        "response_type",
        "login_hint",
        "code_challenge",
        "code_challenge_method",
    ):
        del p[k]
    p.update(
        {
            "grant_type": "authorization_code",
            "code": authcode,
            "client_secret": provider["client_secret"],
            "code_verifier": verifier,
        }
    )
    print("Exchanging the authorization code for an access token")
    try:
        response = urllib.request.urlopen(
            provider["token_endpoint"], urllib.parse.urlencode(p).encode()
        )
    except urllib.error.HTTPError as err:
        print(err.code, err.reason)
        response = err
    response = response.read()
    if args.debug:
        print(response)
    response = json.loads(response)
    if "error" in response:
        print(response["error"])
        if "error_description" in response:
            print(response["error_description"])
            sys.exit(1)

    return response


def authorizeDevicecode(p, provider):
    try:
        response = urllib.request.urlopen(
            provider["devicecode_endpoint"], urllib.parse.urlencode(p).encode()
        )
    except urllib.error.HTTPError as err:
        print(err.code, err.reason)
        response = err
    response = response.read()
    if args.debug:
        print(response)
    response = json.loads(response)
    if "error" in response:
        print(response["error"])
        if "error_description" in response:
            print(response["error_description"])
        sys.exit(1)
    print(response["message"])
    del p["scope"]
    p.update(
        {
            "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
            "client_secret": provider["client_secret"],
            "device_code": response["device_code"],
        }
    )
    interval = int(response["interval"])
    print("Polling...", end="", flush=True)
    while True:
        time.sleep(interval)
        print(".", end="", flush=True)
        try:
            response = urllib.request.urlopen(
                provider["token_endpoint"], urllib.parse.urlencode(p).encode()
            )
        except urllib.error.HTTPError as err:
            # Not actually always an error, might just mean "keep trying..."
            response = err
        response = response.read()
        if args.debug:
            print(response)
        response = json.loads(response)
        if "error" not in response:
            break
        if response["error"] == "authorization_declined":
            print(" user declined authorization.")
            sys.exit(1)
        if response["error"] == "expired_token":
            print(" too much time has elapsed.")
            sys.exit(1)
        if response["error"] != "authorization_pending":
            print(response["error"])
            if "error_description" in response:
                print(response["error_description"])
            sys.exit(1)
    print()

    return response


def build_sasl_string(user, host, port, bearer_token):
    """Build appropriate SASL string, which depends on cloud server's supported SASL method."""
    if provider["sasl_method"] == "OAUTHBEARER":
        return f"n,a={user},\1host={host}\1port={port}\1auth=Bearer {bearer_token}\1\1"
    if provider["sasl_method"] == "XOAUTH2":
        return f"user={user}\1auth=Bearer {bearer_token}\1\1"
    sys.exit(f'Unknown SASL method {provider["sasl_method"]}.')


if "global" not in config:
    print("global section does not exist in config")
    sys.exit(1)

if "accounts" not in config:
    print("accounts section does not exist in config")
    sys.exit(1)

if args.account not in config["accounts"]:
    print("Account does not exist in configfile")
    sys.exit(1)


token = readToken()

if token is None:
    print("Token not found, please authorize")
    authorize()

if args.authorize:
    print("Authorization choosen")
    authorize()

if not access_token_valid():
    if args.verbose:
        print(
            "NOTICE: Invalid or expired access token; using refresh token "
            "to obtain new access token."
        )
    if not token["refresh_token"]:
        sys.exit('ERROR: No refresh token. Run script with "--authorize".')
    provider = config["global"][config["accounts"][args.account]["provider"]]
    p = {"client_id": provider["client_id"]}
    p.update(
        {
            "client_secret": provider["client_secret"],
            "refresh_token": token["refresh_token"],
            "grant_type": "refresh_token",
        }
    )
    try:
        response = urllib.request.urlopen(
            provider["token_endpoint"], urllib.parse.urlencode(p).encode()
        )
    except urllib.error.HTTPError as err:
        print(err.code, err.reason)
        response = err
    response = response.read()
    if args.debug:
        print(response)
    response = json.loads(response)
    if "error" in response:
        print(response["error"])
        if "error_description" in response:
            print(response["error_description"])
        print('Perhaps refresh token invalid. Try running once with "--authorize"')
        sys.exit(1)
    update_tokens(response)

if args.verbose:
    print("Access Token: ", end="")
print(token["access_token"])
