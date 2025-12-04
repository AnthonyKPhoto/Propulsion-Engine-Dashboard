import os
import smtplib
import ssl

SMTP_HOST = os.getenv("SMTP_HOST", "smtp.gmail.com")
SMTP_PORT = int(os.getenv("SMTP_PORT", 587))

SMTP_USERNAME = os.getenv("SMTP_USERNAME")
SMTP_PASSWORD = os.getenv("SMTP_PASSWORD")

if not SMTP_USERNAME or not SMTP_PASSWORD:
    raise RuntimeError("SMTP_USERNAME and SMTP_PASSWORD must be set in the environment for SMTP testing.")

FROM_EMAIL = os.getenv("SMTP_FROM", SMTP_USERNAME)
TO_EMAIL = os.getenv("SMTP_TO", SMTP_USERNAME)     # send test email to yourself by default

subject = "SMTP Test"
body = "SMTP test successful. Jet Dashboard is ready for email sending."

message = f"Subject: {subject}\nTo: {TO_EMAIL}\nFrom: {FROM_EMAIL}\n\n{body}"

try:
    print("[*] Connecting to SMTP server...")
    context = ssl.create_default_context()
    server = smtplib.SMTP(SMTP_HOST, SMTP_PORT)
    server.starttls(context=context)

    print("[*] Logging in...")
    server.login(SMTP_USERNAME, SMTP_PASSWORD)

    print("[*] Sending test email...")
    server.sendmail(FROM_EMAIL, TO_EMAIL, message)

    server.quit()
    print("[+] Success! Test email sent.")

except Exception as e:
    print("[!] SMTP Error:", e)
