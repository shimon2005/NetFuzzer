from boofuzz import *

def main():
    # 1. הגדרת הכתובת והפורט של היעד
    target_ip = "127.0.0.1"
    target_port = 9999

    # 2. פתיחת Session (ניהול התהליך)
    # web_port=26000 מאפשר לראות דשבורד יפה בדפדפן
    session = Session(
        target=Target(
            connection=SocketConnection(target_ip, target_port, proto='tcp')
        ),
        sleep_time=0.5 # מחכים קצת בין בדיקות כדי לא להפיל את השרת מהר מדי מעומס רגיל
    )

    # 3. הגדרת הפרוטוקול (The Grammar)
    # אנחנו מגדירים הודעה בשם "trun_attack"
    s_initialize(name="trun_attack")
    
    # החלקים הקבועים (Static) והמשתנים (Fuzzable)
    s_string("TRUN", name="command")   # הפקודה עצמה - לא משתנה בדרך כלל
    s_delim(" ", name="space")         # רווח מפריד
    s_string("fuzzme", name="parameter") # זה החלק שאנחנו רוצים לתקוף! Boofuzz יחליף את "fuzzme" באלפי וריאציות
    s_static("\r\n")                   # סוף שורה (CRLF)

    # 4. חיבור ההודעה ל-Session
    session.connect(s_get("trun_attack"))

    # 5. התחלת ההתקפה
    print("[*] Starting Fuzzing Session on port 26000 (Check Browser)")
    session.fuzz()

if __name__ == "__main__":
    main()