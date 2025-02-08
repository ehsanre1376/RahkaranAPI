import json
import tempfile
import requests
import os
from datetime import datetime, timedelta
import rsa
import binascii
import logging
from logging.handlers import BaseRotatingHandler



class DailyRotatingFileHandler(BaseRotatingHandler):
    def __init__(self, filename_prefix, backup_days=7):
        self.filename_prefix = filename_prefix
        self.backup_days = backup_days
        self.current_date = datetime.now().date()
        self._cleanup_old_logs()
        super().__init__(self._current_filename(), "a")

    def _current_filename(self):
        return f"{self.filename_prefix}_{self.current_date.strftime('%Y-%m-%d')}.log"

    def _cleanup_old_logs(self):
        cutoff = datetime.now() - timedelta(days=self.backup_days)
        for filename in os.listdir(os.path.dirname(self.filename_prefix) or "."):
            if filename.startswith(os.path.basename(self.filename_prefix)):
                try:
                    file_date = datetime.strptime(filename[-14:-4], "%Y-%m-%d").date()
                    if file_date < cutoff.date():
                        os.remove(
                            os.path.join(
                                os.path.dirname(self.filename_prefix), filename
                            )
                        )
                except ValueError:
                    continue

    def shouldRollover(self, record):
        self.record = record
        return datetime.now().date() != self.current_date

    def doRollover(self):
        if self.stream:
            self.stream.close()
        self.current_date = datetime.now().date()
        self._cleanup_old_logs()
        self.baseFilename = self._current_filename()
        self.stream = self._open()


# Configure logging at the start of your application
logger = logging.getLogger(__name__)
handler = DailyRotatingFileHandler(
    filename_prefix="rahkaran_api",  # Base name for log files
    backup_days=7,  # Delete logs older than 7 days
)
handler.setFormatter(
    logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
)
logger.addHandler(handler)
logger.setLevel(logging.ERROR)  # Set to ERROR level as per original code

APPLICATION_JSON = "application/json"


class RahkaranAPI:
    def __init__(
        self,
        rahkaran_name,
        server_name="localhost",
        port="80",
        username="admin1",
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
        self.auth_file = f"sg-auth-{rahkaran_name}.txt"

    @property
    def base_url(self):
        return f"{self.protocol}://{self.server_name}:{self.port}/{self.rahkaran_name}"

    def hex_string_to_bytes(self, hex_string):
        try:
            return binascii.unhexlify(hex_string)
        except binascii.Error as e:
            logger.error(f"Hex to bytes conversion error: {e}")
            return None

    def bytes_to_hex_string(self, byte_array):
        try:
            return binascii.hexlify(byte_array).decode()
        except binascii.Error as e:
            logger.error(f"Bytes to hex conversion error: {e}")
            return ""

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
                    self.session = content[0].strip()
                    self.expire_date = datetime.strptime(
                        content[1].strip(), "%d-%b-%Y %H:%M:%S"
                    )
                    if datetime.now() > self.expire_date:
                        return self._send_request_login()
                    return self.session
            except Exception as e:
                logger.error(f"Error reading auth file: {e}")
                return self._send_request_login()
        else:
            return self.session

    def _send_request_login(self):
        url = f"{self.base_url}/Services/Framework/AuthenticationService.svc"
        session_url = f"{url}/session"
        login_url = f"{url}/login"

        try:
            response = requests.get(session_url, timeout=10)
            response.raise_for_status()
        except requests.exceptions.RequestException as e:
            logger.error(f"Failed to get session: {e}")
            return None

        try:
            session = json.loads(response.text)
        except json.JSONDecodeError as e:
            logger.error(f"Failed to decode session response: {e}")
            return None

        try:
            m = self.hex_string_to_bytes(session["rsa"]["M"])
            ee = self.hex_string_to_bytes(session["rsa"]["E"])
            if m is None or ee is None:
                return None
        except KeyError as e:
            logger.error(f"Missing RSA parameters in session data: {e}")
            return None

        try:
            rsa_key = rsa.PublicKey(
                int.from_bytes(m, byteorder="big"), int.from_bytes(ee, byteorder="big")
            )
        except Exception as e:
            logger.error(f"Error creating RSA public key: {e}")
            return None

        try:
            session_id = session["id"]
            session_plus_password = f"{session_id}**{self.password}"
            encrypted_password = rsa.encrypt(session_plus_password.encode(), rsa_key)
        except KeyError as e:
            logger.error(f"Session ID missing: {e}")
            return None
        except rsa.pkcs1.EncryptionError as e:
            logger.error(f"RSA encryption failed: {e}")
            return None

        hex_password = self.bytes_to_hex_string(encrypted_password)
        if not hex_password:
            return None

        headers = {"content-Type": APPLICATION_JSON}
        data = {
            "sessionId": session_id,
            "username": self.username,
            "password": hex_password,
        }

        try:
            response = requests.post(
                login_url, headers=headers, data=json.dumps(data), timeout=10
            )
            response.raise_for_status()
        except requests.exceptions.RequestException as e:
            logger.error(f"Login POST request failed: {e}")
            return None

        try:
            set_cookie = response.headers["Set-Cookie"]
            self.session = set_cookie.split(",")[2].split(";")[0].strip()
            expire_str = set_cookie.split(",")[1].split(";")[0].strip()
            self.expire_date = datetime.strptime(expire_str, "%d-%b-%Y %H:%M:%S %Z")
        except (KeyError, IndexError) as e:
            logger.error(f"Set-Cookie header processing failed: {e}")
            return None
        except ValueError as e:
            logger.error(f"Expire date parsing failed: {e}")
            return None

        try:
            with open(
                os.path.join(tempfile.gettempdir(), self.auth_file),
                "w",
                encoding="utf-8",
            ) as f:
                f.write(f"{self.session}\n")
                f.write(self.expire_date.strftime("%d-%b-%Y %H:%M:%S %Z"))
        except IOError as e:
            logger.error(f"Failed to write auth file: {e}")

        return self.session

    def _send_get(self, url):
        cookie = self.login()
        if not cookie:
            logger.error("No valid session cookie available")
            return None
        headers = {"content-Type": APPLICATION_JSON, "Cookie": cookie}

        response = requests.get(self.base_url + url, headers=headers, timeout=10)
        if response.status_code != 200:
            logger.error(f"Initial GET failed for {url}: {response.status_code}")
            retry_cookie = self.login(is_retry=True)
            if not retry_cookie:
                logger.error("Retry login failed during GET request")
                return None
            headers["Cookie"] = retry_cookie
            response = requests.get(self.base_url + url, headers=headers, timeout=10)
            if response.status_code != 200:
                logger.error(f"Retry GET failed for {url}: {response.status_code}")
                return None

        try:
            return json.loads(response.text)
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse GET response: {e}")
            return None

    def _send_post(self, url, data):
        cookie = self.login()
        if not cookie:
            logger.error("No valid session cookie available")
            return None
        headers = {"content-Type": APPLICATION_JSON, "Cookie": cookie}

        response = requests.post(
            self.base_url + url, headers=headers, data=json.dumps(data), timeout=10
        )
        if response.status_code != 200:
            logger.error(f"Initial POST failed for {url}: {response.status_code}")
            retry_cookie = self.login(is_retry=True)
            if not retry_cookie:
                logger.error("Retry login failed during POST request")
                return None
            headers["Cookie"] = retry_cookie
            response = requests.post(
                self.base_url + url, headers=headers, data=json.dumps(data), timeout=10
            )
            if response.status_code != 200:
                logger.error(f"Retry POST failed for {url}: {response.status_code}")
                return None

        try:
            return json.loads(response.text)
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse POST response: {e}")
            return None


r = RahkaranAPI("DEV")

print(
    r._send_get(
        "/General/AddressManagement/Services/AddressManagementWebService.svc/GetRegionalDivisionList"
    )
)
data = [{"Type ": 1, "FirstName": "Ehsan", "LastName": "Rezaei"}]
print(
    r._send_post(
        "/General/PartyManagement/Services/PartyService.svc/GenerateParty",
        data,
    )
)
