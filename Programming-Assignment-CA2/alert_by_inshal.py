import smtplib
import datetime
from email.message import EmailMessage
from database_by_arun import get_user_email

EMAIL_SENDER = "inshal.rizwan2024@gmail.com"
EMAIL_PASSWORD = "xzzx fepo mwfl sgve"



def send_alert(u, ip, location, reason="", otp=""):
    to = get_user_email(u)
    if not to:
        return

    msg = f"""
 Security Alert

Reason: {reason}

Your OTP: {otp}

IP Address: {ip}
Location: {location}

If this was not you, please secure your account immediately.
"""

    print(" Sending email to:", to)

    email = EmailMessage()
    email.set_content(msg)
    email["Subject"] = "Security Alert"
    email["From"] = EMAIL_SENDER
    email["To"] = to

    with smtplib.SMTP_SSL("smtp.gmail.com", 465) as s:
        s.login(EMAIL_SENDER, EMAIL_PASSWORD)
        s.send_message(email)