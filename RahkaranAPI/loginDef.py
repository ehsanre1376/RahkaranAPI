"""Login Rahkaran"""

import json
import tempfile
import requests
import os
from datetime import datetime, timedelta
import rsa
import binascii


g_session = ""
g_expire_date = datetime.now() - timedelta(minutes=5)
G_protocol = "http"
G_ServerName = "127.0.0.1"
G_ServerPort = "80"
G_RahkaranName = "DEV"
G_BaseURL = (
    G_protocol + "://" + G_ServerName + ":" + G_ServerPort + "/" + G_RahkaranName
)
G_AuthenticationName = "sg-auth-" + G_RahkaranName
G_UserName = "admin"
G_PassWord = "admin"


def hex_string_to_bytes(hex_string):
    return binascii.unhexlify(hex_string)


def bytes_to_hex_string(byte_array):
    return binascii.hexlify(byte_array).decode()


def login(is_this_not_first_try=False):
    global g_expire_date
    global g_session
    if is_this_not_first_try:
        return send_request_login()
    elif g_expire_date < datetime.now():
        try:
            with open(
                os.path.join(
                    tempfile.gettempdir(),
                    G_AuthenticationName + G_RahkaranName + ".txt",
                ),
                "r",
                encoding="utf-8",
            ) as file:
                content = file.readlines()
                g_session = content[0][:-2]
                g_expire_date = datetime.strptime(
                    content[1].strip(), "%d-%b-%Y %H:%M:%S"
                )
                if datetime.now() > g_expire_date:
                    return send_request_login()
                else:
                    return g_session
        except Exception:
            return send_request_login()
    else:
        return g_session


def send_request_login(user_name=G_UserName, password=G_PassWord):
    url = G_BaseURL + "/Services/Framework/AuthenticationService.svc"
    session_url = url + "/session"
    login_url = url + "/login"

    response = requests.get(session_url, timeout=10)
    if response.status_code != 200:
        raise ValueError(f"GET /session {response.status_code}")
    session = json.loads(response.text)
    m = hex_string_to_bytes(session["rsa"]["M"])
    e = hex_string_to_bytes(session["rsa"]["E"])
    rsa_key = rsa.PublicKey(
        int.from_bytes(m, byteorder="big"), int.from_bytes(e, byteorder="big")
    )
    session_plus_password = session["id"] + "**" + password
    encrypted_password = rsa.encrypt(session_plus_password.encode(), rsa_key)
    headers = {"content-Type": "application/json"}
    data = {
        "sessionId": session["id"],
        "username": user_name,
        "password": bytes_to_hex_string(encrypted_password),
    }
    response = requests.post(
        login_url, headers=headers, data=json.dumps(data), timeout=10
    )
    if response.status_code != 200:
        raise ValueError(f"POST /login {response.status_code}")
    session = response.headers["Set-Cookie"].split(",")[2].split(";")[0].strip()
    expire_date = response.headers["Set-Cookie"].split(",")[1].split(";")[0].strip()
    expire_date = datetime.strptime(expire_date, "%d-%b-%Y %H:%M:%S %Z")
    g_session = session
    g_expire_date = expire_date
    with open(
        os.path.join(
            tempfile.gettempdir(), G_AuthenticationName + G_RahkaranName + ".txt"
        ),
        "w",
        encoding="utf-8",
    ) as f:
        f.write(g_session + "\n")
        f.write(g_expire_date.strftime("%d-%b-%Y %H:%M:%S %Z"))
    return session


session = login()
session2 = login()
session3 = login()
print(session, "---------", session2, "---------", session3)
