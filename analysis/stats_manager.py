
# --- New Implementation for Socket-based Workflow ---
import json
import socket
import base64
from scapy.all import DNS, DNSQR, IP, UDP, sr1
import threading
import os

TARGET_IP = "127.0.0.1"  # Set your test DNS server IP
TARGET_PORT = 53
TIMEOUT = 2
OUTPUT_FILE = "data.json"
SOCKET_HOST = "127.0.0.1"  # Where to listen for test cases
SOCKET_PORT = 55555         # Port to listen for test cases
SOCKET_BACKLOG = 5

def receive_test_case_from_socket(sock):
    """
    Receives a single test case from the socket.
    Protocol: binary-encoded JSON (length-prefixed)
    Returns (payload_bytes, fild_str) or (None, None) on error/EOF.
    """
    # Read 4 bytes for length prefix (big endian)
    length_bytes = b''
    while len(length_bytes) < 4:
        chunk = sock.recv(4 - len(length_bytes))
        if not chunk:
            return None, None
        length_bytes += chunk
    msg_len = int.from_bytes(length_bytes, 'big')
    # Read the message
    msg_bytes = b''
    while len(msg_bytes) < msg_len:
        chunk = sock.recv(msg_len - len(msg_bytes))
        if not chunk:
            return None, None
        msg_bytes += chunk
    # Decode as JSON
    try:
        msg = json.loads(msg_bytes.decode('utf-8', errors='ignore'))
        payload_bytes = base64.b64decode(msg['input']) if isinstance(msg['input'], str) else bytes(msg['input'])
        fild = msg['fild']
        return payload_bytes, fild
    except Exception as e:
        return None, None

def build_default_dns_query():
    """Build a default DNS query for example.com (A record)."""
    return DNS(rd=1, qd=DNSQR(qname="example.com", qtype="A"))

def inject_input_into_field(dns_pkt, fild, payload_bytes):
    """Inject payload_bytes into the specified DNS field only."""
    f = fild.lower()
    if f in ["id", "dns id", "header id"]:
        dns_pkt.id = int.from_bytes(payload_bytes[:2], 'big', signed=False)
    elif f in ["qdcount", "question count"]:
        dns_pkt.qdcount = int.from_bytes(payload_bytes[:2], 'big', signed=False)
    elif f in ["ancount", "answer count"]:
        dns_pkt.ancount = int.from_bytes(payload_bytes[:2], 'big', signed=False)
    elif f in ["nscount", "authority count"]:
        dns_pkt.nscount = int.from_bytes(payload_bytes[:2], 'big', signed=False)
    elif f in ["arcount", "additional count"]:
        dns_pkt.arcount = int.from_bytes(payload_bytes[:2], 'big', signed=False)
    elif f in ["flags", "header flags"]:
        dns_pkt.flags = int.from_bytes(payload_bytes[:2], 'big', signed=False)
    elif f in ["qname", "question name"]:
        dns_pkt.qd.qname = payload_bytes.decode(errors="ignore")
    elif f in ["qtype", "question type"]:
        dns_pkt.qd.qtype = int.from_bytes(payload_bytes[:2], 'big', signed=False)
    elif f in ["qclass", "question class"]:
        dns_pkt.qd.qclass = int.from_bytes(payload_bytes[:2], 'big', signed=False)
    # Add more fields as needed
    return dns_pkt

def send_dns_query_and_get_response(dns_pkt):
    pkt = IP(dst=TARGET_IP)/UDP(dport=TARGET_PORT)/dns_pkt
    try:
        response = sr1(pkt, timeout=TIMEOUT, verbose=0)
        return response
    except Exception:
        return None

def health_check_dns_server():
    """Send a standard DNS query to check server health. Returns True if healthy, False if not."""
    try:
        dns_pkt = build_default_dns_query()
        response = send_dns_query_and_get_response(dns_pkt)
        if response:
            parsed = response.getlayer(DNS)
            return parsed is not None
        return False
    except Exception:
        return False

def check_memory_growth(payload_bytes, fild):
    """Placeholder for memory leak detection. Returns False (no leak) by default."""
    # In a real system, implement memory monitoring here
    return False

def classify_failure(response, payload_bytes, fild):
    """
    Classify the failure cause and observations.
    Returns (failure_cause, explanation, response_received, response_b64, observations)
    """
    if response:
        try:
            parsed = response.getlayer(DNS)
            if parsed:
                obs = ["valid_dns"]
                failure_cause = None
                explanation = "The server responded normally to the injected payload."
            else:
                obs = ["malformed_dns"]
                failure_cause = "Server Fault"
                explanation = "The server returned a malformed or unexpected DNS response, indicating a protocol parsing or handling error."
            response_b64 = base64.b64encode(bytes(response)).decode()
            response_received = True
        except Exception:
            obs = ["malformed_dns"]
            failure_cause = "Server Fault"
            explanation = "The server returned a malformed or non-standard response, likely due to protocol parsing issues."
            response_b64 = None
            response_received = True
    else:
        # Timeout: perform health check
        obs = ["timeout"]
        response_b64 = None
        response_received = False
        server_healthy = health_check_dns_server()
        if not server_healthy:
            failure_cause = "Server Crash"
            explanation = "The server did not respond to either the test or a standard health-check query, indicating a likely crash or unavailability."
        else:
            failure_cause = "Server Fault"
            explanation = "The server did not respond to the test query, but responded to a standard health-check query. This suggests a payload-specific fault, not a full crash."
    # Memory leak detection (placeholder)
    if check_memory_growth(payload_bytes, fild):
        failure_cause = "Memory Leak"
        explanation = "Repeated sending of this input appears to cause memory usage growth on the server."
    return failure_cause, explanation, response_received, response_b64, obs

def append_to_stat_json(entry):
    """Append a single entry to data.json safely as a top-level array of records."""
    # Use script directory for data.json
    script_dir = os.path.dirname(os.path.abspath(__file__))
    output_path = os.path.join(script_dir, OUTPUT_FILE)
    # Read existing entries
    if os.path.exists(output_path):
        with open(output_path, "r") as f:
            try:
                data = json.load(f)
                if not isinstance(data, list):
                    data = []
            except Exception:
                data = []
    else:
        data = []
    data.append(entry)
    with open(output_path, "w") as f:
        json.dump(data, f, indent=2)

def handle_client(sock):
    while True:
        payload_bytes, fild = receive_test_case_from_socket(sock)
        if payload_bytes is None or fild is None:
            break
        dns_pkt = build_default_dns_query()
        dns_pkt = inject_input_into_field(dns_pkt, fild, payload_bytes)
        response = send_dns_query_and_get_response(dns_pkt)
        failure_cause, explanation, response_received, response_b64, obs = classify_failure(response, payload_bytes, fild)
        # Determine if this is a real problem
        is_problem = False
        if failure_cause in ("Server Crash", "Server Fault", "Memory Leak", "Other"):
            is_problem = True
        elif ("timeout" in obs) or ("malformed_dns" in obs):
            is_problem = True
        elif response_received is False:
            is_problem = True
        # Only save if is_problem
        if is_problem:
            entry = {
                "problematic_input": base64.b64encode(payload_bytes).decode(),
                "problematic_field": fild,
                "failure_cause": failure_cause if failure_cause is not None else None,
                "explanation": explanation,
                "response_received": response_received,
                "response_b64": response_b64,
                "observations": obs
            }
            append_to_stat_json(entry)

def main():
    # Listen for incoming test cases over TCP socket
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_sock:
        server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_sock.bind((SOCKET_HOST, SOCKET_PORT))
        server_sock.listen(SOCKET_BACKLOG)
        print(f"Listening for test cases on {SOCKET_HOST}:{SOCKET_PORT} ...")
        while True:
            client_sock, addr = server_sock.accept()
            print(f"Accepted connection from {addr}")
            t = threading.Thread(target=handle_client, args=(client_sock,))
            t.daemon = True
            t.start()

if __name__ == "__main__":
    main()
