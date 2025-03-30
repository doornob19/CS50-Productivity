import os
from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from werkzeug.security import check_password_hash, generate_password_hash
from helpers import apology, login_required

app = Flask(__name__)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)
db = SQL("sqlite:///project.db")

@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


@app.route("/", methods=["GET", "POST"])
@login_required
def index():
    if request.method == "GET":
        # uncompleted tasks get value 0 and are at the top since sorting by ASC. completed tasks have value 1 and are at bottom
        task_rows = db.execute("SELECT * FROM tasks WHERE user_id = ? ORDER BY CASE status WHEN 'uncompleted' THEN 0 ELSE 1 END", session["user_id"])
        habit_rows = db.execute("SELECT * FROM habits WHERE user_id = ?", session["user_id"])
        return render_template("index.html", tasks=task_rows, habits=habit_rows)

    if request.method == "POST":
        if "toggle_task" in request.form:
            # task_id is going to be the value from <input> which is task.id
            task_id = request.form.get("toggle_task")

            # current_status will either be "completed" or "uncompleted"
            current_status = db.execute("SELECT status FROM tasks WHERE user_id = ? AND id = ?", session["user_id"], task_id)[0]["status"]

            # flip the status of that task
            new_status = "uncompleted" if current_status == "completed" else "completed"
            db.execute("UPDATE tasks SET status = ? WHERE user_id = ? AND id = ?", new_status, session["user_id"], task_id)

        if "delete" in request.form:
            delete_task_id = request.form.get("delete")
            db.execute("DELETE FROM tasks WHERE user_id = ? AND id = ?", session["user_id"], delete_task_id)

        elif "clear" in request.form:
            db.execute("DELETE FROM tasks WHERE user_id = ?", session["user_id"])


        task_rows = db.execute("SELECT * FROM tasks WHERE user_id = ? ORDER BY CASE status WHEN 'uncompleted' THEN 0 ELSE 1 END", session["user_id"])
        habit_rows = db.execute("SELECT * FROM habits WHERE user_id = ?", session["user_id"])
        return render_template("index.html", tasks=task_rows, habits=habit_rows)


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    session.clear()
    if request.method == "POST":
        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))

        # Ensure username exists and password is correct
        # len(rows) must be 1 because the SQL query should return exactly 1 row because each username should be unique
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    if request.method == "GET":
        return render_template("register.html")

    username = request.form.get("username")
    password = request.form.get("password")
    confirmation = request.form.get("confirmation")

    if not username:
        return apology("missing username")
    if not password or not confirmation:
        return apology("missing password")
    if password != confirmation:
        return apology("passwords do not match")

    try:
        db.execute("INSERT INTO users (username, hash) VALUES (?, ?)",
                   username, generate_password_hash(password))
    except ValueError:
        return apology("username already taken")

    user = db.execute("SELECT id FROM users WHERE username = ?", username)
    session["user_id"] = user[0]["id"]
    flash("Registered!")
    return render_template("index.html")


@app.route("/change", methods=["GET", "POST"])
@login_required
def change():
    if request.method == "GET":
        return render_template("change.html")

    old = request.form.get("oldpassword")
    new = request.form.get("newpassword")
    confirmation = request.form.get("confirmation")

    if not old or not new or not confirmation:
        return apology("missing password")

    password = db.execute("SELECT hash FROM users WHERE id = ?", session["user_id"])
    password = password[0]["hash"]

    if not check_password_hash(password, old):
        return apology("wrong password")
    if old == new:
        return apology("old password cannot be new password")
    if new != confirmation:
        return apology("passwords do not match")

    db.execute("UPDATE users SET hash = ? WHERE id = ?",
               generate_password_hash(new), session["user_id"])

    flash("Password Changed!")
    return redirect("/")


@app.route("/todo", methods=["GET", "POST"])
@login_required
def todo():
    if request.method == "GET":
        return render_template("todo.html")

    task = request.form.get("task")
    if not task or task.strip() == "":
        return apology("Please provide a task")

    db.execute("INSERT INTO tasks (user_id, task, status) VALUES (?, ?, ?)", session["user_id"], task, "uncompleted")
    flash("Task Added!")
    return redirect("/")

@app.route("/habit", methods=["GET", "POST"])
@login_required
def habit():
    if request.method == "GET":
        return render_template("habit.html")

    if "habit" in request.form:
        habit = request.form.get("habit")
        if not habit or habit.strip() == "":
            return apology("Please provide a habit")

        db.execute("INSERT INTO habits (user_id, habit, days) VALUES (?, ?, ?)", session["user_id"], habit, "0")
        flash("Habit Added!")

        return redirect("/")

    if "increment" in request.form:
        habit_id = request.form.get("increment")
        days = db.execute("SELECT days FROM habits WHERE user_id = ? AND id = ?", session["user_id"], habit_id)[0]["days"]
        db.execute("UPDATE habits SET days = ? WHERE user_id = ? AND id = ?", days + 1, session["user_id"], habit_id)

        return redirect("/")

    if "delete" in request.form:
        deleted_habit_id = request.form.get("delete")
        db.execute("DELETE FROM habits WHERE user_id = ? AND id = ?", session["user_id"], deleted_habit_id)
        return redirect("/")

    if "clear" in request.form:
        db.execute("DELETE FROM habits WHERE user_id = ?", session["user_id"])
        return redirect("/")


@app.route("/mousesay", methods=["GET", "POST"])
@login_required
def mousesay():
    if request.method == "GET":
        return render_template("mousesay.html")

    text = request.form.get("text")
    return render_template("apology.html", top="_", bottom=text)
