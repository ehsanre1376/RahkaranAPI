import json
import tempfile
import requests
import os
from datetime import datetime, timedelta
import rsa
import binascii


class RahkaranAuth:
    def __init__(
        self,
        rahkaran_name,
        server_name="localhost",
        port="80",
        username="admin",
        password="admin",
        protocol="http",
    ):
        self.server_name = server_name
        self.port = port
        self.username = username
        self.password = password
        self.rahkaran_name = rahkaran_name
        self.protocol = protocol
        self.session = ""
        self.expire_date = datetime.now() - timedelta(minutes=5)
        self.auth_file = f"sg-auth-{rahkaran_name}{rahkaran_name}.txt"

    @property
    def base_url(self):
        return f"{self.protocol}://{self.server_name}:{self.port}/{self.rahkaran_name}"

    def hex_string_to_bytes(self, hex_string):
        return binascii.unhexlify(hex_string)

    def bytes_to_hex_string(self, byte_array):
        return binascii.hexlify(byte_array).decode()

    def login(self, is_retry=False):
        if is_retry:
            return self._send_request_login()
        elif self.expire_date < datetime.now():
            try:
                with open(
                    os.path.join(tempfile.gettempdir(), self.auth_file),
                    "r",
                    encoding="utf-8",
                ) as file:
                    content = file.readlines()
                    self.session = content[0][:-2]
                    self.expire_date = datetime.strptime(
                        content[1].strip(), "%d-%b-%Y %H:%M:%S"
                    )
                    if datetime.now() > self.expire_date:
                        return self._send_request_login()
                    return self.session
            except Exception:
                return self._send_request_login()
        else:
            return self.session

    def _send_request_login(self):
        url = f"{self.base_url}/Services/Framework/AuthenticationService.svc"
        session_url = f"{url}/session"
        login_url = f"{url}/login"

        response = requests.get(session_url, timeout=10)
        if response.status_code != 200:
            raise ValueError(f"GET /session {response.status_code}")

        session = json.loads(response.text)
        m = self.hex_string_to_bytes(session["rsa"]["M"])
        e = self.hex_string_to_bytes(session["rsa"]["E"])
        rsa_key = rsa.PublicKey(
            int.from_bytes(m, byteorder="big"), int.from_bytes(e, byteorder="big")
        )

        session_plus_password = f"{session['id']}**{self.password}"
        encrypted_password = rsa.encrypt(session_plus_password.encode(), rsa_key)

        headers = {"content-Type": "application/json"}
        data = {
            "sessionId": session["id"],
            "username": self.username,
            "password": self.bytes_to_hex_string(encrypted_password),
        }

        response = requests.post(
            login_url, headers=headers, data=json.dumps(data), timeout=10
        )
        if response.status_code != 200:
            raise ValueError(f"POST /login {response.status_code}")

        self.session = (
            response.headers["Set-Cookie"].split(",")[2].split(";")[0].strip()
        )
        self.expire_date = datetime.strptime(
            response.headers["Set-Cookie"].split(",")[1].split(";")[0].strip(),
            "%d-%b-%Y %H:%M:%S %Z",
        )

        with open(
            os.path.join(tempfile.gettempdir(), self.auth_file), "w", encoding="utf-8"
        ) as f:
            f.write(f"{self.session}\n")
            f.write(self.expire_date.strftime("%d-%b-%Y %H:%M:%S %Z"))

        return self.session


r = RahkaranAuth("DEV")

print(r._send_request_login())
