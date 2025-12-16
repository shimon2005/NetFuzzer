from boofuzz import *
import socket
import time
import subprocess

# =========================
# Target / Docker Settings
# =========================
TARGET_IP = "127.0.0.1"
TARGET_PORT = 9000

DOCKER_IMAGE_NAME = "vuln-dnsmasq"
CONTAINER_NAME = "dns-victim"

START_CMD = [
    "docker", "run", "-d", "--rm",
    "--name", CONTAINER_NAME,
    "-p", f"{TARGET_PORT}:53/udp",
    DOCKER_IMAGE_NAME,
    "./src/dnsmasq", "-k",
    "--log-facility=-",
    "--no-daemon",
    "--no-hosts",
    "--no-resolv",
    "--address=/#/1.2.3.4"
]

# =========================
# Target Control
# =========================
def restart_target():
    print("[*] Restarting target...")
    subprocess.run(
        ["docker", "kill", CONTAINER_NAME],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )
    time.sleep(0.5)

    try:
        subprocess.run(
            START_CMD,
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        time.sleep(1)
        print("[*] Target is UP")
    except subprocess.CalledProcessError:
        print("[!!!] Failed to start target")
        exit(1)

# =========================
# Crash Reporting
# =========================
def generate_readable_report(session, filename_base):
    path = f"{filename_base}.txt"

    with open(path, "w") as f:
        f.write("=== DNS FUZZING CRASH REPORT ===\n")
        f.write(f"Timestamp: {time.ctime()}\n")
        f.write(f"Mutant Index: {session.total_mutant_index}\n\n")

        mutant = session.fuzz_node.mutant

        if mutant and mutant.element:
            f.write(f"[+] Attacked Field : {mutant.element.name}\n")
            f.write(f"[+] Mutation Type : {mutant.name}\n")

            try:
                val = mutant.element.render()
                f.write(f"[+] Field Value  : {val}\n")
            except Exception:
                f.write("[+] Field Value  : <binary data>\n")
        else:
            f.write("[!] Could not retrieve mutation details\n")

        f.write("\n=== FULL PAYLOAD (HEX) ===\n")
        if session.last_send:
            f.write(session.last_send.hex())
        else:
            f.write("<no payload captured>")

    print(f"[+] Report saved: {path}")

def save_crash_evidence(session):
    ts = int(time.time())
    base = f"crash_{session.total_mutant_index}_{ts}"

    # Docker logs
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
        s_size("domain_label", length=1, fuzzable=True)
        s_string("fuzz", name="domain_label", fuzzable=True)

        s_byte(3, name="tld_len", fuzzable=False)
        s_string("com", name="tld", fuzzable=False)
        s_byte(0, name="null_term", fuzzable=False)

        s_word(1, name="qtype", fuzzable=False)
        s_word(1, name="qclass", fuzzable=False)
    s_block_end()

    session.connect(s_get("dns_request"))

    print("[*] Starting DNS Fuzzing...")
    session.fuzz()

if __name__ == "__main__":
    main()
