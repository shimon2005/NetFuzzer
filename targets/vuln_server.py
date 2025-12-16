import socket
import threading

# זהו השרת הפגיע שלנו.
# הוא מדמה שרת שמקבל פקודות טקסטואליות.
# יש לו חולשה בפקודה "TRUN".

def handle_client(client_socket):
    try:
        welcome_msg = "WELCOME TO VULN SERVER 1.0\n"
        client_socket.send(welcome_msg.encode())
        
        while True:
            # קבלת נתונים מהלקוח
            request = client_socket.recv(1024).decode(errors='ignore')
            
            if not request:
                break
                
            print(f"[>] Received: {request.strip()}")

            # --- כאן נמצאת החולשה ---
            # אם הפקודה היא TRUN והאורך של הקלט גדול מ-2000 תווים -> קריסה!
            if request.startswith("TRUN"):
                if len(request) > 2000:
                    print("[!] CRASH! Buffer Overflow Detected!")
                    # אנחנו מדמים קריסה על ידי סגירת התוכנית או זריקת שגיאה
                    raise RuntimeError("Server Crashed due to Buffer Overflow")
                else:
                    client_socket.send("TRUN COMPLETE\n".encode())
            
            # פקודות רגילות
            elif request.startswith("HELP"):
                client_socket.send("COMMANDS: HELP, TRUN, EXIT\n".encode())
            elif request.startswith("EXIT"):
                client_socket.close()
                break
            else:
                client_socket.send("UNKNOWN COMMAND\n".encode())
                
    except Exception as e:
        print(f"[-] Server Error: {e}")
        client_socket.close()

def start_server():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("0.0.0.0", 9999))
    server.listen(5)
    print("[*] Listening on port 9999...")
    
    while True:
        client, addr = server.accept()
        print(f"[*] Accepted connection from {addr[0]}")
        client_handler = threading.Thread(target=handle_client, args=(client,))
        client_handler.start()

if __name__ == "__main__":
    start_server()