from functools import wraps
from flask import Flask, render_template, request, redirect, session, flash
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import mysql.connector
import os
from dotenv import load_dotenv
import random

# 🔐 LOAD ENV VARIABLES
load_dotenv()

# 🔹 DB CONNECTION
db = mysql.connector.connect(
    host=os.getenv("DB_HOST"),
    user=os.getenv("DB_USER"),
    password=os.getenv("DB_PASSWORD"),
    database=os.getenv("DB_NAME")
)
cursor = db.cursor(dictionary=True)

app = Flask(__name__)

# 🔐 SECRET KEY
app.secret_key = os.getenv("SECRET_KEY")

# 🔐 COOKIE SECURITY
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax"
)

# 🔔 MAKE NOTIFICATIONS AVAILABLE IN ALL TEMPLATES
@app.context_processor
def inject_notifications():
    return dict(notifications=session.get("notifications", []))

# 🔹 LOGIN REQUIRED
def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'email' not in session:
            flash("Please login first", "warning")
            return redirect("/login")
        return f(*args, **kwargs)
    return decorated

# 🔹 CURRENT USER
def current_user():
    return session.get("email")

# 🔹 HOME
@app.route("/")
def home():
    if current_user():
        return redirect("/tasks")
    return render_template("home.html")

# 🔐 REGISTER
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        fname = request.form["first_name"]
        lname = request.form["last_name"]
        email = request.form["email"]
        password = request.form["password"]
        confirm = request.form["confirm_password"]

        if password != confirm:
            flash("Passwords do not match", "danger")
            return redirect("/register")

        cursor.execute("SELECT * FROM users WHERE email=%s", (email,))
        if cursor.fetchone():
            flash("Email already exists", "warning")
            return redirect("/register")

        hashed = generate_password_hash(password)

        cursor.execute("""
            INSERT INTO users (first_name, last_name, email, password)
            VALUES (%s, %s, %s, %s)
        """, (fname, lname, email, hashed))

        db.commit()
        flash("Registration successful!", "success")
        return redirect("/login")

    return render_template("register.html")

# 🔑 LOGIN
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form["email"]
        password = request.form["password"]

        cursor.execute("SELECT * FROM users WHERE email=%s", (email,))
        user = cursor.fetchone()

        if not user or not check_password_hash(user["password"], password):
            flash("Invalid login", "danger")
            return redirect("/login")

        session.clear()
        session["email"] = email

        flash("Login successful!", "success")
        return redirect("/tasks")

    return render_template("login.html")

# 🔓 LOGOUT
@app.route("/logout")
@login_required
def logout():
    session.clear()
    flash("Logged out successfully", "info")
    return redirect("/login")

# ➕ ADD TASK
@app.route("/add_task", methods=["GET", "POST"])
@login_required
def add_task():
    if request.method == "POST":
        cursor.execute("""
            INSERT INTO tasks 
            (topic, title, start, end, status, owner, category, priority)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
        """, (
            request.form["topic"],
            request.form["title"],
            request.form["start"],
            request.form["end"],
            request.form["status"],
            current_user(),
            request.form["category"],
            request.form["priority"]
        ))

        db.commit()
        flash("Task added successfully!", "success")
        return redirect("/tasks")

    return render_template("add_task.html")

# 📋 VIEW TASKS + SEARCH + FILTER + NOTIFICATIONS
@app.route("/tasks")
@login_required
def view_tasks():
    now = datetime.now()

    # 🔔 INIT NOTIFICATIONS
    if "notifications" not in session:
        session["notifications"] = []

    # 🔍 SEARCH & FILTER
    search = request.args.get("search")
    status_filter = request.args.get("status")
    priority_filter = request.args.get("priority")

    query = "SELECT * FROM tasks WHERE owner=%s"
    params = [current_user()]

    if search:
        query += " AND title LIKE %s"
        params.append(f"%{search}%")

    if status_filter:
        query += " AND status=%s"
        params.append(status_filter)

    if priority_filter:
        query += " AND priority=%s"
        params.append(priority_filter)

    cursor.execute(query, tuple(params))
    tasks = cursor.fetchall()

    # ⏰ AUTO MISS + ADD NOTIFICATION
    for t in tasks:
        if t["status"] not in ["Completed", "Missed"] and t["end"] < now:
            cursor.execute(
                "UPDATE tasks SET status='Missed' WHERE id=%s",
                (t["id"],)
            )

            msg = f"Task '{t['title']}' missed!"
            if msg not in session["notifications"]:
                session["notifications"].append(msg)

    db.commit()

    # 🔁 REFRESH TASK LIST
    cursor.execute(query, tuple(params))
    tasks = cursor.fetchall()

    return render_template(
        "tasks.html",
        tasks=tasks,
        now=now
    )

# 🔔 CLEAR NOTIFICATIONS
@app.route("/clear_notifications", methods=["POST"])
@login_required
def clear_notifications():
    session["notifications"] = []
    flash("Notifications cleared", "info")
    return redirect("/tasks")

# 🔄 UPDATE TASK
@app.route("/update_status/<int:id>", methods=["POST"])
@login_required
def update_status(id):
    status = request.form["status"]

    if status.lower() == "completed":
        cursor.execute(
            "DELETE FROM tasks WHERE id=%s AND owner=%s",
            (id, current_user())
        )
        flash("Task completed and removed!", "success")
    else:
        cursor.execute(
            "UPDATE tasks SET status=%s WHERE id=%s AND owner=%s",
            (status, id, current_user())
        )
        flash(f"Task updated to '{status}'", "success")

    db.commit()
    return redirect("/tasks")

# 🔐 FORGOT PASSWORD
@app.route("/forgot", methods=["GET", "POST"])
def forgot():
    if request.method == "POST":
        email = request.form["email"]

        cursor.execute("SELECT * FROM users WHERE email=%s", (email,))
        if not cursor.fetchone():
            flash("Email not found", "danger")
            return redirect("/forgot")

        session["reset_email"] = email

        otp = str(random.randint(1000, 9999))
        session["otp"] = otp

        print("DEBUG OTP:", otp)

        flash("OTP generated! Check terminal", "info")
        return redirect("/otp")

    return render_template("forgot.html")

# 🔐 OTP
@app.route("/otp", methods=["GET", "POST"])
def otp():
    if request.method == "POST":
        if request.form["otp"] == session.get("otp"):
            return redirect("/reset")
        else:
            flash("Invalid OTP", "danger")
            return redirect("/otp")

    return render_template("otp.html")

# 🔐 RESET PASSWORD
@app.route("/reset", methods=["GET", "POST"])
def reset():
    if request.method == "POST":
        p1 = request.form["password"]
        p2 = request.form["confirm_password"]

        if p1 != p2:
            flash("Passwords do not match", "danger")
            return redirect("/reset")

        hashed = generate_password_hash(p1)

        cursor.execute(
            "UPDATE users SET password=%s WHERE email=%s",
            (hashed, session.get("reset_email"))
        )
        db.commit()

        flash("Password reset successful!", "success")
        return redirect("/login")

    return render_template("reset.html")

# 🚀 RUN
if __name__ == "__main__":
    app.run(debug=True)