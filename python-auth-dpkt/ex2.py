import os
import hashlib
import random
import string
import json
import dpkt


USERS_FILE = "users.json"

def generate_salt(length=32):
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

def hash_password(password, salt):
    return hashlib.sha256((password + salt).encode()).hexdigest()

def save_users(users):
    with open(USERS_FILE, "w") as f:
        json.dump(users, f)

def load_users():
    if not os.path.exists(USERS_FILE):
        return {}
    with open(USERS_FILE, "r") as f:
        return json.load(f)

def register():
    print("REGISTER:")
    users = load_users()
    while True:
        username = input("Username: ")
        if username in users:
            print("Username already exists. Choose another username.")
            continue
        password = input("Password: ")
        salt = generate_salt()
        hashed_password = hash_password(password, salt)
        users[username] = {"salt": salt, "password": hashed_password}
        save_users(users)
        print("You have successfully registered")
        return

def login():
    print("LOGIN:")
    users = load_users()
    while True:
        username = input("Username: ")
        if username not in users:
            print("User not found... try again")
            continue
        password = input("Password: ")
        hashed_password = hash_password(password, users[username]["salt"])
        if hashed_password == users[username]["password"]:
            print("You have successfully connected")
            return  
        else:
            print("Wrong password, try again")

def get_ip_address_counts(pcap_path):
    ip_counts = {}
    with open(pcap_path, 'rb') as f:
        pcap = dpkt.pcap.Reader(f)
        for timestamp, buf in pcap:
            try:
                eth = dpkt.ethernet.Ethernet(buf)
                if isinstance(eth.data, dpkt.ip.IP):
                    ip = eth.data
                    src_ip = dpkt.utils.inet_to_str(ip.src)
                    dst_ip = dpkt.utils.inet_to_str(ip.dst)
                    ip_counts[src_ip] = ip_counts.get(src_ip, 0) + 1
                    ip_counts[dst_ip] = ip_counts.get(dst_ip, 0) + 1
            except Exception as e:
                print(f"Error parsing packet: {e}")
    return ip_counts

def get_full_urls(pcap_path):
    url_counts = {}
    with open(pcap_path, 'rb') as f:
        pcap = dpkt.pcap.Reader(f)
        for timestamp, buf in pcap:
            try:
                eth = dpkt.ethernet.Ethernet(buf)
                if isinstance(eth.data, dpkt.ip.IP):
                    ip = eth.data
                    if isinstance(ip.data, dpkt.tcp.TCP):
                        tcp = ip.data
                        if tcp.sport == 80 or tcp.dport == 80:
                            try:
                                http = dpkt.http.Request(tcp.data)
                                host = http.headers.get('host', '')
                                uri = http.uri
                                if host and uri:
                                    url = f"http://{host}{uri}"
                                    url_counts[url] = url_counts.get(url, 0) + 1
                            except (dpkt.dpkt.NeedData, dpkt.dpkt.UnpackError):
                                continue
            except Exception as e:
                print(f"Error parsing packet: {e}")
    return url_counts

def get_domain_queries(pcap_path):
    dns_queries = {}
    with open(pcap_path, 'rb') as f:
        pcap = dpkt.pcap.Reader(f)
        for timestamp, buf in pcap:
            try:
                eth = dpkt.ethernet.Ethernet(buf)
                if not isinstance(eth.data, dpkt.ip.IP):
                    continue
                ip = eth.data
                if not isinstance(ip.data, dpkt.udp.UDP):
                    continue
                udp = ip.data
                if udp.sport == 53 or udp.dport == 53:
                    dns = dpkt.dns.DNS(udp.data)
                    if dns.qr == dpkt.dns.DNS_Q:
                        for query in dns.qd:
                            domain = query.name
                            dns_queries[domain] = dns_queries.get(domain, 0) + 1
            except Exception:
                continue
    return dns_queries

def main():
    while True:
        print("\n1. Register\n2. Login")
        sign = input("Select option: (1/2) ")
        if sign == "1":
            register()
        elif sign == "2":
            login()
        else:
            print("Wrong Input!")
         


if __name__ == "__main__":
    main()