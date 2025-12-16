from boofuzz import *
import socket
import sys

# --- הגדרות חיבור (שנה כאן אם צריך) ---
TARGET_IP = "127.0.0.1"
TARGET_PORT = 9000 # שינינו ל-9000 כדי לעקוף את השגיאה

# --- פונקציית בדיקת דופק ---
def check_is_alive(target, fuzz_data_logger, session, *args, **kwargs):
    try:
        # פתיחת סוקט חדש ונקי לבדיקה
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(1.0) # אם אין תשובה תוך שניה, נניח שהשרת מת
        
        # בניית פאקטה תקינה לחלוטין (שאילתה על google.com)
        valid_dns_query = (
            b"\x00\x00"  # Transaction ID
            b"\x01\x00"  # Flags (Standard Query)
            b"\x00\x01"  # Questions: 1
            b"\x00\x00"  # Answer RRs: 0
            b"\x00\x00"  # Authority RRs: 0
            b"\x00\x00"  # Additional RRs: 0
            b"\x06google\x03com\x00" # Query: google.com
            b"\x00\x01"  # Type: A
            b"\x00\x01"  # Class: IN
        )
        
        # שליחה לפורט המוגדר למעלה
        sock.sendto(valid_dns_query, (TARGET_IP, TARGET_PORT))
        
        # ניסיון לקבל תשובה
        data, addr = sock.recvfrom(1024)
        sock.close()
        
        # אם הגענו לפה, השרת חי. ממשיכים.
        return

    except socket.timeout:
        print("\n[!!!] CRASH DETECTED! Server stopped responding. [!!!]")
        sys.exit(1)
    except Exception as e:
        print(f"Error in health check: {e}")

# --- הסקריפט הראשי ---
def main():
    session = Session(
        target=Target(
            connection=SocketConnection(TARGET_IP, TARGET_PORT, proto='udp')
        ),
        post_test_case_callbacks=[check_is_alive], 
        sleep_time=0.05
    )

    s_initialize(name="dns_request")

    # --- Header Fuzzing ---
    s_word(0xAAAA, name="transaction_id", fuzzable=False) 
    s_word(0x0100, name="flags", fuzzable=True) 
    
    # Fuzzing על הכמויות
    s_word(0x0001, name="qdcount", fuzzable=True) 
    s_word(0x0000, name="ancount", fuzzable=True) 
    s_word(0x0000, name="nscount", fuzzable=False)
    s_word(0x0000, name="arcount", fuzzable=False)

    # --- Question Fuzzing ---
    if s_block_start("question_block"):
        s_size("label1", length=1, fuzzable=True) # אורך הלייבל
        s_string("fuzz", name="label1", fuzzable=True) # המחרוזת עצמה
        
        s_byte(3, name="len_suffix", fuzzable=False)
        s_string("com", name="suffix", fuzzable=False)
        s_byte(0, name="terminator", fuzzable=False)

        # Fuzzing על סוג השאילתה (Type)
        s_word(1, name="qtype", fuzzable=True) 
        s_word(1, name="qclass", fuzzable=False)
    s_block_end()

    session.connect(s_get("dns_request"))
    print(f"[*] Starting Smart DNS Fuzzing on {TARGET_IP}:{TARGET_PORT}...")
    session.fuzz()

if __name__ == "__main__":
    main()