from boofuzz import *
import socket
import time
import subprocess
import hashlib
from flask import session

# =========================
# Target / Docker Settings
# =========================
TARGET_IP = "127.0.0.1"
TARGET_PORT = 5533

DOCKER_IMAGE_NAME = "vuln-dnsmasq"
CONTAINER_NAME = "test-health"

START_CMD = [
    "docker", "run", "-d", "--rm",
    "--name", CONTAINER_NAME,
    "-p", f"{TARGET_PORT}:53",
    DOCKER_IMAGE_NAME
]

# =========================
# Target Control
# =========================
def wait_for_service(ip, port, timeout=10):
    start_time = time.time()
    print(f"[*] Waiting for service at {ip}:{port}...")
    
    while time.time() - start_time < timeout:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(0.5)
            
            sock.sendto(b"ping", (ip, port))
            
            time.sleep(0.1)
            sock.close()
            return True
            
        except (ConnectionResetError, ConnectionRefusedError, OSError):
            time.sleep(0.5)
        except Exception:
            time.sleep(0.5)
            
    return False

# =========================
# פונקציית הריסטארט המעודכנת
# =========================
def restart_target():
    print("[*] Restarting target...")
    
    subprocess.run(["docker", "rm", "-f", CONTAINER_NAME], 
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    
    cmd = [
        "docker", "run", "-d", "--rm",
        "--name", CONTAINER_NAME,
        "-p", f"{TARGET_PORT}:53/udp",
        DOCKER_IMAGE_NAME
    ]

    try:
        subprocess.run(cmd, check=True, stdout=subprocess.DEVNULL)
        
        if wait_for_service(TARGET_IP, TARGET_PORT):
            print(f"[*] Target is UP and listening on {TARGET_PORT}")
        else:
            print("[!!!] Warning: Target started but port seems closed. Fuzzing might fail.")

    except subprocess.CalledProcessError:
        print("[!!!] Failed to start Docker container")
        sys.exit(1)

# =========================
# Crash Reporting
# =========================
def generate_readable_report(session, filename_base):
    path = f"{filename_base}.txt"

    with open(path, "w") as f:
        f.write("=== MUTATION METADATA ===\n")
        node = session.fuzz_node

        f.write("\n=== FULL PAYLOAD (HEX) ===\n")
        if session.last_send:
            f.write(session.last_send.hex())
        else:
            f.write("<no payload captured>")

    print(f"[+] Crash report written: {path}")

def save_crash_evidence(session):
    ts = int(time.time())
    base = f"crash_{session.total_mutant_index}_{ts}"

    with open(f"{base}_server.log", "w") as f:
        subprocess.run(
            ["docker", "logs", CONTAINER_NAME],
            stdout=f,
            stderr=f
        )

    # Binary payload
    if session.last_send:
        with open(f"{base}.bin", "wb") as f:
            f.write(session.last_send)

    generate_readable_report(session, base)

# =========================
# Crash Detection
# =========================
def check_is_alive(target, fuzz_data_logger, session, *args, **kwargs):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(0.5)

        valid_dns = (
            b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
            b"\x06google\x03com\x00"
            b"\x00\x01\x00\x01"
        )

        sock.sendto(valid_dns, (TARGET_IP, TARGET_PORT))
        sock.recvfrom(1024)
        sock.close()
        return

    except socket.timeout:
        print(f"\n[!!!] CRASH DETECTED at index {session.total_mutant_index}")
        save_crash_evidence(session)
        restart_target()

# =========================
# Main Fuzzer
# =========================
def main():
    restart_target()

    session = Session(
        target=Target(
            connection=SocketConnection(
                TARGET_IP,
                TARGET_PORT,
                proto="udp"
            )
        ),
        post_test_case_callbacks=[check_is_alive],
        sleep_time=0.1,
        restart_sleep_time=1
    )

    s_initialize("dns_request")

    # -------- DNS HEADER --------
    s_word(0xAAAA, name="transaction_id", fuzzable=False)
    s_word(0x0100, name="flags", fuzzable=False)
    s_word(0x0001, name="qdcount", fuzzable=False)
    s_word(0x0000, name="ancount", fuzzable=False)
    s_word(0x0000, name="nscount", fuzzable=False)
    s_word(0x0000, name="arcount", fuzzable=False)

    # -------- QUESTION --------
    if s_block_start("question"):
        
        # --- הטריק שמפיל את השרת ---
        # במקום לתת ל-Boofuzz לחשב אורך אוטומטית (s_size), אנחנו מגדירים את האורך כ"סתם בייט" (s_byte).
        # זה אומר ש-Boofuzz ינסה לשים שם ערכים מטורפים (כמו 255, 0, -1) בלי קשר למחרוזת האמיתית.
        s_byte(10, name="label_len", fuzzable=True) 
        
        # המחרוזת עצמה - אנחנו כמעט לא נוגעים בה, רק באורך שלה
        s_string("AAAAAA", name="domain_label", fuzzable=True)

        # סיומת (בלי Fuzzing, כדי שהשרת יחשוב שזו פאקטה לגיטימית עד שיהיה מאוחר מדי)
        s_byte(3, name="tld_len", fuzzable=False)
        s_string("com", name="tld", fuzzable=False)
        s_byte(0, name="terminator", fuzzable=False)

        # סוגים סטנדרטיים
        s_word(1, name="qtype", fuzzable=False)  # A Record
        s_word(1, name="qclass", fuzzable=False) # IN
        s_block_end()
    session.connect(s_get("dns_request"))

    print("[*] Starting DNS Fuzzing...")
    session.fuzz()

if __name__ == "__main__":
    main()
