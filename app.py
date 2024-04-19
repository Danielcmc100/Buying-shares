import os

from cs50 import SQL
from datetime import datetime
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")


@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""

    stocks = db.execute("SELECT symbol, shares FROM stocks WHERE user_id = ?", session["user_id"])

    total = 0

    for stock in stocks:
        stock["price"] = lookup(stock["symbol"])["price"]
        total += (stock["price"] * stock["shares"])

    cash = db.execute("SELECT cash FROM users WHERE id = ?", session["user_id"])[0]["cash"]
    total += cash

    return render_template("index.html", stocks=stocks, cash=cash, total=total)


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""

    if request.method == "POST":

        if not request.form.get("symbol"):
            return apology("must provide symbol", 403)

        elif not request.form.get("shares"):
            return apology("must provide shares", 403)

        shares = 0

        try:
            shares = int(request.form.get("shares"))
        except ValueError:
            return apology("invalid shares number", 400)

        if not shares > 0:
            return apology("must provide a positive number", 400)

        quote = lookup(request.form.get("symbol"))
        if quote is None:
            return apology("invalid symbol", 400)

        cash = db.execute("SELECT cash FROM users WHERE id = ?", session["user_id"])[0]["cash"]

        if cash < quote["price"] * shares:
            return apology("not have money", 403)

        cash -= quote["price"] * shares

        db.execute("UPDATE users SET cash = ? WHERE id = ?", cash, session["user_id"])

        stocks = db.execute("SELECT * FROM stocks WHERE user_id =? AND symbol =?", session["user_id"], quote["symbol"])

        if stocks:
            db.execute("UPDATE stocks SET shares = shares + ? WHERE user_id =? AND symbol =?",
                       int(request.form.get("shares")), session["user_id"], quote["symbol"])
        else:
            db.execute("INSERT INTO stocks (user_id, symbol, shares) VALUES(?, ?, ?)",
                session["user_id"], quote["symbol"], shares)

        db.execute("INSERT INTO transactions (user_id, symbol, shares, price, date) VALUES(?, ?, ?, ?, ?)",
        session["user_id"], quote["symbol"], shares, quote["price"], datetime.now())

        return redirect("/")

    else:
        return render_template("buy.html")



@app.route("/history")
@login_required
def history():
    """Show history of transactions"""

    transactions = db.execute("SELECT * FROM transactions WHERE user_id = ?", session["user_id"])

    return render_template("history.html", transactions=transactions)


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
        rows = db.execute(
            "SELECT * FROM users WHERE username = ?", request.form.get("username")
        )

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(
            rows[0]["hash"], request.form.get("password")
        ):
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
    """Get stock quote."""

    if request.method == "POST":

        if not request.form.get("symbol"):
            return apology("must provide symbol", 400)

        quote = lookup(request.form.get("symbol"))
        if quote is None:
            return apology("invalid symbol", 400)

        return render_template("quoted.html", quote=quote)
    else:
        return render_template("quote.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""

    if request.method == "POST":

        if not request.form.get("username"):
            return apology("must provide username", 400)

        elif not request.form.get("password"):
            return apology("must provide password", 400)

        elif not request.form.get("confirmation"):
            return apology("must confirm password", 400)

        elif not request.form.get("password") == request.form.get("confirmation"):
            return apology("password confirmation must be the same as password", 400)


        users = db.execute("SELECT * FROM users")
        for user in users:
            if request.form.get("username") in user["username"]:
                return apology("username in use", 400)


        db.execute(
            "INSERT INTO users (username, hash) VALUES(?, ?)",
            request.form.get("username"),
            generate_password_hash(password=request.form.get("password")))

        return redirect("/login")
    else:
        return render_template("register.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""


    if request.method == "POST":

        if not request.form.get("symbol"):
            return apology("must provide symbol", 400)

        elif not request.form.get("shares"):
            return apology("must provide shares", 400)


        shares = 0

        try:
            shares = int(request.form.get("shares"))
        except ValueError:
            return apology("invalid shares number", 400)

        if not shares > 0:
            return apology("must provide a positive number", 400)


        # Verifica se possui a stock na "conta"
        stock = db.execute("SELECT symbol, shares FROM stocks WHERE user_id = ? AND symbol = ?", session["user_id"], request.form.get("symbol"))

        if stock is None:
            return apology("must provide a stock symbol valid", 400)

        symbol = request.form.get("symbol")
        if not stock:
            return apology(f"stock {symbol} not found", 400)


        if not stock[0]["shares"] >= shares:
                    return apology("stock quantity unavailable", 400)


        quote = lookup(request.form.get("symbol"))

        if stock[0]["shares"] == shares:
            db.execute("DELETE FROM stocks WHERE user_id =? AND symbol =?", session["user_id"], quote["symbol"])
        else:
            db.execute("UPDATE stocks SET shares = shares - ? WHERE user_id =? AND symbol =?", shares, session["user_id"], quote["symbol"])

        db.execute("UPDATE users SET cash = cash + ? WHERE id = ?", quote["price"] * shares, session["user_id"])


        db.execute("INSERT INTO transactions (user_id, symbol, shares, price, date) VALUES(?, ?, ?, ?, ?)",
        session["user_id"], quote["symbol"], shares * -1, quote["price"], datetime.now())


        return redirect("/")
    else:
        stocks = db.execute("SELECT symbol, shares FROM stocks WHERE user_id = ?", session["user_id"])

        return render_template("sell.html", stocks=stocks)

