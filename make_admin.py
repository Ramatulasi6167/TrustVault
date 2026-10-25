
import sqlite3

conn = sqlite3.connect("trustvault.db")
email = input("Enter your registered email: ").strip().lower()

cursor = conn.execute(
    "UPDATE users SET role = 'admin' WHERE email = ?",
    (email,)
)

if cursor.rowcount == 1:
    conn.commit()
    print("Admin role assigned successfully!")
else:
    print("Account not found. Register first.")

conn.close()
