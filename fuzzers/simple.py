import socket

# === שים פה את ה-IP של ה-WSL שעבד לך ב-nslookup ===
TARGET_IP = "172.29.112.1" 
TARGET_PORT = 5533

print(f"Firing packet to {TARGET_IP}...")

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.sendto(b"CAN_YOU_SEE_ME", (TARGET_IP, TARGET_PORT))
sock.close()

print("Fired.")