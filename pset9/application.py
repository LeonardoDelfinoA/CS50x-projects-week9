import os

from cs50 import SQL
from flask import Flask, flash, jsonify, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash
import time

from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True

# Ensure responses aren't cached


@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")

# Make sure API key is set
if not os.environ.get("API_KEY"):
    raise RuntimeError("API_KEY not set")


@app.route("/")
@login_required
def index():

    headings = ['Symbol', 'Name', 'Shares', 'Price', 'TOTAL']
    data = db.execute("SELECT share, SUM(amount), price FROM shares WHERE personid = :idsession GROUP BY share",
                      idsession=session["user_id"])
    total_cash = db.execute("SELECT cash FROM users WHERE id = :idsession",
                            idsession=session["user_id"])

    total_money = total_cash[0]["cash"]
    for line in data:
        company_data = lookup(line["share"])
        present_price = company_data["price"]
        line["price"] = present_price
        line["company_name"] = company_data["name"]
        line["total_price"] = line["price"] * line["SUM(amount)"]
        total_money += line["total_price"]

        line["price"] = usd(line["price"])
        line["total_price"] = usd(line["total_price"])

    return render_template("table.html", headings=headings, data=data, total_cash=usd(total_cash[0]["cash"]),
                                total_money=usd(total_money))


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():

    if request.method == "GET":

        return render_template("buy.html")

    if request.method == "POST":

        company = request.form.get("symbol")
        company = company.upper()
        share = request.form.get("shares")
        personid = session["user_id"]
        result = lookup(company)

        if not share.isdigit():

            return apology("You must use a number to choose the number of shares you want to buy!", 400)

        if int(share) <= 0:

            return apology("You must buy a positive numbers of shares.", 400)


        if result == None:

            return apology("No company with that name :(", 400)

        total_price = float(result["price"]) * float(share)
        user = db.execute("SELECT id, cash FROM users WHERE id = :username", username=session["user_id"])

        if total_price > user[0]["cash"]:
            return apology("You don't have enough money", 400)

        date_brute = time.localtime()
        date_info = time.strftime("%m-%d-%Y %H:%M:%S", date_brute)
        userid = user[0]["id"]
        less = user[0]["cash"] - total_price
        db.execute("UPDATE users SET cash = ? WHERE id = ?", less, userid)
        db.execute("CREATE TABLE IF NOT EXISTS 'shares'('id' INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL, 'share' TEXT NOT NULL, 'amount' INTEGER NOT NULL, 'price' FLOAT NOT NULL, 'time' TEXT NOT NULL, 'personid' INTEGER NOT NULL,FOREIGN KEY (personid) REFERENCES users(id))")
        db.execute("INSERT INTO shares (personid, share, amount, price, time) VALUES(?, ?, ?, ?, ?)",
                      userid, company, share, total_price, date_info)

        db.execute("CREATE TABLE IF NOT EXISTS 'history'('id' INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL, 'share' TEXT NOT NULL, 'amount' INTEGER NOT NULL, 'price' FLOAT NOT NULL, 'time' TEXT NOT NULL, 'personid' INTEGER NOT NULL,FOREIGN KEY (personid) REFERENCES users(id))")
        db.execute("INSERT INTO history (personid, share, amount, price, time) VALUES(?, ?, ?, ?, ?)",
                      userid, company, share, result["price"], date_info)

        return redirect("/")


@app.route("/history")
@login_required
def history():
    if request.method == "GET":

        headings = ['Symbol', 'Shares', 'Price', 'Transacted']
        data = db.execute("SELECT * FROM history WHERE personid = :idsession",
                            idsession=session["user_id"])
        for line in data:
            line["price"] = usd(line["price"])


        return render_template("history.html", headings=headings, data=data)

    """Show history of transactions"""
    return apology("TODO")


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = :username",
                          username=request.form.get("username"))

        # Ensure username exists and password is correct
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


@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():

    if request.method == "GET":

        return render_template("quote.html")

    if request.method == "POST":

        company = request.form.get("symbol")
        company = company.upper()
        confirmation = lookup(company)

        if confirmation == None:

            return apology("No company with that name :(", 400)

        result = confirmation
        share_price = usd(result["price"])
        return render_template('quoted.html', name=result["name"], symbol=result["symbol"], price=share_price)


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "GET":

        return render_template("register.html")

    if request.method == "POST":

        if not request.form.get("username"):

            return apology("must provide username", 400)

        if not request.form.get("password"):

            return apology("must provide password", 400)

        password = request.form.get("password")
        username = request.form.get("username")

        if password != request.form.get("confirmation"):

            return apology("The two passwords must match!")

        if password == request.form.get("confirmation"):

            rows = db.execute("SELECT * FROM users WHERE username = :username",
                               username=request.form.get("username"))

            if len(rows) != 1:
                hashed_password = generate_password_hash(password, method='pbkdf2:sha256',
                                                         salt_length=8)

                db.execute("INSERT INTO users (username, hash) VALUES(?, ?)",
                           username, hashed_password)

                cookie = db.execute("SELECT id FROM users WHERE username = :username",
                                    username=request.form.get("username"))
                session["user_id"] = cookie[0]["id"]

                return redirect("/")

            return apology("username already exists", 400)


@app.route("/change_pass", methods=["GET", "POST"])
def change_password():

    if request.method == "GET":

        return render_template("change_pass.html")

    if request.method == "POST":

        password = request.form.get("password")
        password1 = request.form.get("password1")
        password2 = request.form.get("password2")
        user_pass = db.execute("SELECT hash FROM users WHERE id = ?", session["user_id"])

        if not check_password_hash(user_pass[0]["hash"], request.form.get("password")):
            return apology("invalid password")

        if password == password1:

            return apology("New password must be different from old password!")

        if password1 != password2:

            return apology("New passwords don't match!")

        hashed_password = generate_password_hash(password1, method='pbkdf2:sha256',
                                                 salt_length=8)

        db.execute("UPDATE users SET hash = ? WHERE id = ?", hashed_password, session["user_id"])

        return redirect("/")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():

    data = db.execute("SELECT share, SUM(amount), price FROM shares WHERE personid = :idsession GROUP BY share",
                       idsession=session["user_id"])
    total_cash = db.execute("SELECT cash FROM users WHERE id = :idsession",
                            idsession=session["user_id"])

    total_money = total_cash[0]["cash"]

    for line in data:
        company_data = lookup(line["share"])
        present_price = company_data["price"]
        line["price"] = present_price

    if request.method == "GET":
        return render_template("sell.html", data=data)


    if request.method == "POST":

        share = request.form.get("symbol")
        shares = request.form.get("shares")

        if not shares.isdigit():

            return apology("You must use a number to choose the number of shares you want to buy!")

        amount_shares = db.execute("SELECT SUM(amount), share FROM shares WHERE personid = :idsession AND share = :share GROUP BY SHARE",
                                    idsession=session["user_id"], share=share)

        if int(shares) <= 0:

            return apology("There is no share being sold!")

        if int(shares) > amount_shares[0]["SUM(amount)"]:

            return apology("You don't have that many shares!")

        date_brute = time.localtime()
        date_info = time.strftime("%m-%d-%Y %H:%M:%S", date_brute)

        company_info = lookup(share)
        present_worth = company_info["price"]

        share_history = int(shares) - int(shares) * 2
        db.execute("CREATE TABLE IF NOT EXISTS 'history'('id' INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL, 'share' TEXT NOT NULL, 'amount' INTEGER NOT NULL, 'price' FLOAT NOT NULL, 'time' TEXT NOT NULL, 'personid' INTEGER NOT NULL,FOREIGN KEY (personid) REFERENCES users(id))")
        db.execute("INSERT INTO history (personid, share, amount, price, time) VALUES(?, ?, ?, ?, ?)",
                   session["user_id"], share, share_history, present_worth, date_info)


        remain = float(present_worth) * float(shares) + total_cash[0]["cash"]
        user_info = db.execute("SELECT id, cash FROM users WHERE id = :username",
                               username=session["user_id"])

        db.execute("UPDATE users SET cash = ? WHERE id = ?", remain, user_info[0]["id"])
        if int(shares) == amount_shares[0]["SUM(amount)"]:

            db.execute("DELETE FROM shares WHERE share = ? AND personid = ?", amount_shares[0]["share"], user_info[0]["id"])

        reduction = amount_shares[0]["SUM(amount)"] - int(shares)
        db.execute("UPDATE shares SET amount = ? WHERE share = ? AND personid = ?",
                   reduction, share, session["user_id"])
        return redirect("/")


def errorhandler(e):
    """Handle error"""
    if not isinstance(e, HTTPException):
        e = InternalServerError()
    return apology(e.name, e.code)


# Listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)
