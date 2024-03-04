"""Login Rahkaran"""

import requests
import rsa
import json
import binascii
import tempfile
import os
from datetime import datetime, timedelta

G_session = ""
G_ExpireDate = datetime.now() - timedelta(minutes=5)
G_protocol = "http"
G_ServerName = "127.0.0.1"
G_ServerPort = "80"
G_RahkaranName = "PortfolioDEV"
G_BaseURL = G_protocol + "://" + G_ServerName + ":" + "80" + "/" + G_RahkaranName
G_AuthenticationName = "sg-auth-"
G_UserName = "admin"
G_PassWord = "admin"


def hex_string_to_bytes(hex_string):
    return binascii.unhexlify(hex_string)


def bytes_to_hex_string(byte_array):
    return binascii.hexlify(byte_array).decode()


def login(Is_this_Not_Firest_Try=False):
    global G_ExpireDate
    global G_session
    if Is_this_Not_Firest_Try:
        return SendRequestlogin()
    elif G_ExpireDate < datetime.now():
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
                G_session = content[0][:-2]
                G_ExpireDate = datetime.strptime(
                    content[1].strip(), "%d-%b-%Y %H:%M:%S"
                )
                if datetime.now() > G_ExpireDate:
                    return SendRequestlogin()
                else:
                    return G_session
        except Exception as e:
            return SendRequestlogin()
    else:
        return G_session


def SendRequestlogin(user_name=G_UserName, password=G_PassWord):
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
    ExpireDate = response.headers["Set-Cookie"].split(",")[1].split(";")[0].strip()
    ExpireDate = datetime.strptime(ExpireDate, "%d-%b-%Y %H:%M:%S %Z")
    G_session = session
    G_ExpireDate = ExpireDate
    with open(
        os.path.join(
            tempfile.gettempdir(), G_AuthenticationName + G_RahkaranName + ".txt"
        ),
        "w",
        encoding="utf-8",
    ) as f:
        f.write(G_session + "\n")
        f.write(G_ExpireDate.strftime("%d-%b-%Y %H:%M:%S %Z"))
    return session


session = login()
session2 = login()
session3 = login()
print(session, "---------", session2, "---------", session3)
