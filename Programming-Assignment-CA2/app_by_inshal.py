from flask import Flask, request, render_template, redirect, session
from database_by_arun import *
from alert_by_inshal import send_alert
import requests, csv, random, time

print("🔐 Suspicious Login Detection System Started")

app = Flask(__name__)
app.secret_key = "secret123"

init_db()

# 🌍 GET IP + LOCATION
def get_location():
    try:
        data = requests.get("https://ipinfo.io/json").json()
        ip = data.get("ip", "Unknown")
        location = data.get("country", "Unknown")
        return ip, location
    except:
        return "Unknown", "Unknown"


# HOME
@app.route("/")
def home():
    return render_template("login.html")


# SIGNUP
@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        u = request.form["username"]
        p = request.form["password"]
        e = request.form["email"]

        if not u or not p or not e:
            return render_template("signup.html", error="All fields required")

        if not create_user(u, p, e):
            return render_template("signup.html", error="Email exists")

        return redirect("/")

    return render_template("signup.html")


# LOGIN + OTP
@app.route("/login", methods=["POST"])
def login():
    print("➡️ Login request received")

    # 🔐 OTP VERIFY
    if "otp" in session:
        user_otp = request.form.get("otp")

        if user_otp:
            if time.time() - session["otp_time"] > 120:
                session.clear()
                return render_template("login.html", error="OTP expired")

            if user_otp == session["otp"]:
                session["user"] = session["otp_user"]
                session.pop("otp", None)
                session.pop("otp_user", None)
                session.pop("otp_time", None)
                return redirect("/dashboard")
            else:
                return render_template("login.html", error="Invalid OTP", otp_required=True)

    email = request.form.get("email")
    pwd = request.form.get("password")

    ip, location = get_location()
    device = request.headers.get("User-Agent")

    print(f"User: {email}, IP: {ip}, Location: {location}")

    if not email or not pwd:
        return render_template("login.html", error="All fields required")

    user = get_user_by_email(email)
    if not user:
        return render_template("login.html", error="User not found")

    username = user[0]
    valid = check_user(username, pwd)
    role = get_user_role(username)

    last_ip = get_last_ip(username)
    last_location = get_last_location(username)

    ip_changed = last_ip is not None and last_ip != ip
    location_changed = last_location is not None and last_location != location

    log_attempt(username, ip, device, location, valid)

    # 🚨 SUSPICIOUS LOGIN (FOR DEMO ALWAYS TRUE)
    if role != "admin" and valid:
        otp = str(random.randint(100000, 999999))
        print(f"OTP generated: {otp}")
        print("⚠️ Suspicious login detected")

        session["otp"] = otp
        session["otp_user"] = username
        session["otp_time"] = time.time()

        send_alert(
            username,
            ip,
            location,
            reason="Suspicious login",
            otp=otp
        )

        return render_template(
            "login.html",
            otp_required=True,
            error="⚠️ Suspicious login detected. OTP required"
        )

    # 🚨 FAILED ATTEMPTS
    if role != "admin" and not valid and get_failed_attempts(username) >= 3:
        otp = str(random.randint(100000, 999999))
        print(f"OTP generated: {otp}")
        print("⚠️ Multiple failed login attempts detected")

        session["otp"] = otp
        session["otp_user"] = username
        session["otp_time"] = time.time()

        send_alert(
            username,
            ip,
            location,
            reason="Multiple failed login attempts",
            otp=otp
        )

        return render_template(
            "login.html",
            otp_required=True,
            error="⚠️ Multiple failed attempts. OTP required"
        )

    # ✅ NORMAL LOGIN
    if valid:
        session["user"] = username
        print("✅ Login successful")
        return redirect("/dashboard")

    print("❌ Invalid login")
    return render_template("login.html", error="Invalid credentials")


# DASHBOARD
@app.route("/dashboard")
def dashboard():
    if "user" not in session:
        return redirect("/")
    return render_template("dashboard.html", user=session["user"])


# LOGOUT
@app.route("/logout")
def logout():
    session.pop("user", None)
    return redirect("/")


# ADMIN PANEL
@app.route("/admin")
def admin():
    if "user" not in session:
        return redirect("/")

    if get_user_role(session["user"]) != "admin":
        return "Access Denied"

    return render_template("admin.html", logs=get_logs())


# EXPORT LOGS
@app.route("/export")
def export():
    if "user" not in session or get_user_role(session["user"]) != "admin":
        return "Access Denied"

    with open("logs.csv", "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["User", "IP", "Device", "Location", "Status", "Time"])
        writer.writerows(get_logs())

    return "CSV Exported!"


if __name__ == "__main__":
    app.run(debug=False)
