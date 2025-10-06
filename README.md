# python-auth-dpkt
A Python project for practicing user authentication with salted password hashing and analyzing network traffic captures (PCAP files) using dpkt. The project demonstrates secure login/registration flow, DNS/URL/IP extraction from traffic, and writing structured results to text.

## 🚀 Features

### 1. User Authentication
- Allows users to **register** with:
  - `username`
  - random 32-character **salt**
  - **SHA256(salt + password)** hash
- Allows users to **log in** by verifying stored credentials.
- User data is stored persistently.

### 2. PCAP Analysis (with `dpkt`)
Implements functions for analyzing captured network traffic:
- `get_domain_queries(pcap_path)` → returns a dictionary of DNS domain queries and their counts.
- `get_full_urls(pcap_path)` → extracts full URLs from HTTP traffic with occurrence counts.
- `get_ip_addresses(pcap_path)` → extracts IPv4 source/destination addresses with occurrence counts.

### 3. Documentation
- Includes `ex2.txt` with explanations of the solution process.


## ⚙️ Requirements
- Python 3.x
- `dpkt` library  

Install dependencies:
```bash
pip install dpkt


▶️ Usage

1.Run the program:
python ex2.py

2.Choose to Register or Login as a user.

3.Use the analysis functions on .pcap files to extract:
-DNS queries
-HTTP URLs
-IPv4 addresses

Example (inside the script or via interactive use):
from ex2 import get_domain_queries, get_full_urls, get_ip_addresses

print(get_domain_queries("traffic.pcap"))
print(get_full_urls("traffic.pcap"))
print(get_ip_addresses("traffic.pcap"))

📜 Notes:
-Do not use external libraries other than dpkt.
-Code is written in Python only (no helper scripts).
-The project demonstrates basic network security practices: password salting, hashing, and traffic inspection.
