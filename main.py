import argparse
import sys
from fuzzers import dns_fuzzer, http_fuzzer 
# הערה: וודא שיש לך קבצים בשם dns_fuzzer.py ו-http_fuzzer.py בתיקיית fuzzers
# או שתייצר קבצים ריקים בשם הזה בינתיים כדי שהקוד ירוץ

def parse_arguments():
    """
    מגדיר את התפריט של התוכנית ואת האפשרויות שהמשתמש יכול לבחור
    """
    parser = argparse.ArgumentParser(description="NetFuzzer - A Protocol Fuzzing Tool")

    # 1. כתובת היעד (חובה)
    parser.add_argument("-t", "--target", required=True, help="Target IP address (e.g., 127.0.0.1)")

    # 2. בחירת פרוטוקול (חובה)
    parser.add_argument("-p", "--protocol", required=True, choices=["dns", "http"], 
                        help="Protocol to fuzz (dns or http)")

    # 3. בחירת שדות לתקיפה (אופציונלי - אם לא נבחר, נתקוף הכל)
    # nargs='+' אומר שאפשר להכניס רשימה של שדות עם רווחים ביניהם
    parser.add_argument("--fields", nargs='+', default=["all"],
                        help="Specific fields to fuzz (e.g., 'qname', 'flags', 'headers'). Default: all")

    # 4. פורט (אופציונלי - אם לא נבחר, נשתמש בברירת מחדל לפי הפרוטוקול)
    parser.add_argument("--port", type=int, help="Target port (Default: 53 for DNS, 80 for HTTP)")

    return parser.parse_args()

def main():
    # 1. קליטת הבחירה מהמשתמש
    args = parse_arguments()
    
    print(f"""
    [+] Starting NetFuzzer...
    [+] Target:   {args.target}
    [+] Protocol: {args.protocol.upper()}
    [+] Fields:   {args.fields}
    """)

    # 2. לוגיקה לבחירת הפרוטוקול והפעלת הפאזר המתאים
    if args.protocol == "dns":
        # קביעת פורט ברירת מחדל אם המשתמש לא סיפק
        target_port = args.port if args.port else 53
        print(f"[*] Invoking DNS Fuzzer on port {target_port}...")
        
        # כאן אנחנו קוראים לפונקציה של החבר שלך (שצריכה לקבל את הפרמטרים האלו)
        # שים לב: אתה צריך לוודא עם החבר שהפונקציה שלו יודעת לקבל 'fields'
        try:
            dns_fuzzer.fuzz(target_ip=args.target, port=target_port, fields=args.fields)
        except AttributeError:
            print("[!] Error: 'fuzz' function not found in dns_fuzzer.py yet.")

    elif args.protocol == "http":
        target_port = args.port if args.port else 80
        print(f"[*] Invoking HTTP Fuzzer on port {target_port}...")
        # http_fuzzer.fuzz(args.target, target_port, args.fields) (כשיהיה מוכן)

    else:
        print("[-] Unknown protocol.")
        sys.exit(1)

if __name__ == "__main__":
    main()