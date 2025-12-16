import json
import socket
import base64
from scapy.all import DNS, DNSQR, IP, UDP

TARGET_IP = "127.0.0.1"  # Set your test DNS server IP
TARGET_PORT = 53
TIMEOUT = 2
INPUT_FILE = "attack.json"
OUTPUT_FILE = "stat.json"

# Helper to inject payload into the specified DNS field
def build_dns_packet(payload, fild):
    domain = "example.com"
    dns = DNS(rd=1, qd=DNSQR(qname=domain))
    # Inject payload into the specified field
    if fild.lower() in ["id", "dns id", "header id"]:
        dns.id = int.from_bytes(payload[:2], 'big', signed=False)
    elif fild.lower() in ["qdcount", "question count"]:
        dns.qdcount = int.from_bytes(payload[:2], 'big', signed=False)
    elif fild.lower() in ["ancount", "answer count"]:
        dns.ancount = int.from_bytes(payload[:2], 'big', signed=False)
    elif fild.lower() in ["nscount", "authority count"]:
        dns.nscount = int.from_bytes(payload[:2], 'big', signed=False)
    elif fild.lower() in ["arcount", "additional count"]:
        dns.arcount = int.from_bytes(payload[:2], 'big', signed=False)
    elif fild.lower() in ["flags", "header flags"]:
        dns.flags = int.from_bytes(payload[:2], 'big', signed=False)
    elif fild.lower() in ["qname", "question name"]:
        dns.qd.qname = payload.decode(errors="ignore")
    elif fild.lower() in ["qtype", "question type"]:
        dns.qd.qtype = int.from_bytes(payload[:2], 'big', signed=False)
    elif fild.lower() in ["qclass", "question class"]:
        dns.qd.qclass = int.from_bytes(payload[:2], 'big', signed=False)
    # Add more fields as needed
    return dns

def send_dns_packet(dns_pkt):
    pkt = IP(dst=TARGET_IP)/UDP(dport=TARGET_PORT)/dns_pkt
    try:
        from scapy.all import sr1
        response = sr1(pkt, timeout=TIMEOUT, verbose=0)
        return response
    except Exception:
        return None

def main():
    with open(INPUT_FILE, "r") as f:
        data = json.load(f)
    results = []
    for entry in data:
        input_payload = entry["input"]
        fild = entry["fild"]
        # Try to decode input as base64, fallback to utf-8
        try:
            payload_bytes = base64.b64decode(input_payload)
        except Exception:
            payload_bytes = input_payload.encode(errors="ignore")
        dns_pkt = build_dns_packet(payload_bytes, fild)
        response = send_dns_packet(dns_pkt)
        if response:
            try:
                from scapy.all import DNS
                parsed = response.getlayer(DNS)
                if parsed:
                    obs = "valid DNS response"
                else:
                    obs = "malformed response"
                response_data = base64.b64encode(bytes(response)).decode()
            except Exception:
                obs = "malformed response"
                response_data = None
            received = True
        else:
            obs = "timeout"
            response_data = None
            received = False
        results.append({
            "input": input_payload,
            "fild": fild,
            "response_received": received,
            "response_data": response_data,
            "observations": obs
        })
    with open(OUTPUT_FILE, "w") as f:
        json.dump(results, f, indent=2)
    print(json.dumps(results, indent=2))

if __name__ == "__main__":
    main()
