
# Rahkaran Authentication Client

A Python client for handling Rahkaran authentication sessions.

## Installation

---
```bash
pip install RahkaranAPI
```
---

## Usage

---
```python
from RahkaranAPI import RahkaranAPI

# Initialize client
SG = RahkaranAPI(
    server_name="127.0.0.1",
    port="80",
    username="admin",
    password="admin",
    rahkaran_name="DEV",
    protocol="http"
)

# Get session
try:
    session = auth_client.login()
    print(f"Authenticated session: {session}")
except Exception as e:
    print(f"Authentication failed: {str(e)}")
```
---

---
```go
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

```
---
