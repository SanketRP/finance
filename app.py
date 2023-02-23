import os

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd, unusd

# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True

# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")

# Make sure API key is set
if not os.environ.get("API_KEY"):
    raise RuntimeError("API_KEY not set")


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

    stocks = db.execute(
        "SELECT * FROM shares WHERE user_id = ? AND share > 0", session["user_id"]
    )
    cash = db.execute("SELECT cash FROM users WHERE id = ?", session["user_id"])[0][
        "cash"
    ]

    money = 0
    for stock in stocks:
        total = unusd(stock["price"]) * stock["share"]
        money += total

    total = cash + money

    return render_template(
        "index.html", stocks=stocks, cash=usd(cash), total=usd(total)
    )


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""
    if request.method == "POST":
        symbol = request.form.get("symbol")
        shares = request.form.get("shares")
        user_id = session["user_id"]

        info = lookup(symbol)

        if symbol == "":
            return apology("Missing Symbol")

        if info == None:
            return apology("Invalid Symbol")

        if not shares.isdigit():
            return apology("Invalid Share")

        if int(shares) < 0:
            return apology("Invalid Share")

        shares = int(float(shares))

        if shares == 0:
            return apology("Too Few Shares")

        cash = db.execute("SELECT cash FROM users WHERE id = ?", user_id)[0]["cash"]

        if info["price"] * shares > cash:
            return apology("Can't Afford")

        total = info["price"] * shares

        # Registring the buy on the shares database
        # Insert if symbol not available for user_id else update

        if (
            len(
                db.execute(
                    "SELECT * FROM shares WHERE user_id = ? AND symbol = ?",
                    user_id,
                    info["symbol"],
                )
            )
            > 0
        ):

            initial_shares = db.execute(
                "SELECT share FROM shares WHERE user_id = ? AND symbol = ?",
                user_id,
                info["symbol"],
            )[0]["share"]

            shares += initial_shares

            total = info["price"] * shares

            db.execute(
                "UPDATE shares SET share = ?, price = ?, total = ?, total_money = ? WHERE user_id = ? AND symbol = ?",
                shares,
                usd(info["price"]),
                usd(total),
                total,
                user_id,
                info["symbol"],
            )

        else:
            db.execute(
                "INSERT INTO shares (user_id, price, share, symbol, name, total, total_money) VALUES (?, ?, ?, ?, ?, ?, ?)",
                user_id,
                usd(info["price"]),
                shares,
                info["symbol"],
                info["name"],
                usd(total),
                total,
            )

        money = cash - total

        # Deducting money from users database
        db.execute("UPDATE users SET cash = ? WHERE id = ?", money, user_id)

        # Saving it in history
        db.execute(
            "INSERT INTO history (user_id, symbol, share, price) VALUES (?, ?, ?, ?)",
            user_id,
            info["symbol"],
            shares,
            usd(info["price"]),
        )

        return redirect("/")

    return render_template("buy.html")


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    user_id = session["user_id"]

    histories = db.execute("SELECT * FROM history WHERE user_id = ?", user_id)
    return render_template("history.html", histories=histories)


@app.route("/add", methods=["GET", "POST"])
@login_required
def add():
    """Add Money"""
    user_id = session["user_id"]

    if request.method == "POST":
        money = request.form.get("money")

        if money == "" or int(money) < 0:
            return apology("Invalid Amount")

        money = int(money)

        cash = db.execute("SELECT cash FROM users WHERE id = ?", user_id)[0]["cash"]

        # Upadte the users cash
        db.execute("UPDATE users SET cash = ?", cash + money)

        return redirect("/")

    return render_template("add_money.html")


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

        symbol = request.form.get("symbol")

        if symbol == "":
            return apology("Missing Symbol")

        info = lookup(symbol)
        if info == None:
            return apology("Invalid Symbol")

        return render_template(
            "quoted.html",
            name=info["name"],
            price=usd(info["price"]),
            symbol=info["symbol"],
        )

    return render_template("quote.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    if request.method == "POST":

        username = request.form.get("username")
        password = request.form.get("password")
        confirmation = request.form.get("confirmation")

        # Validate input
        if (
            username == ""
            or len(db.execute("SELECT * FROM users WHERE username = ?", username)) > 0
        ):
            return apology("Invalid Username")

        if password == "" or password != confirmation:
            return apology("Passwords Do Not Match")

        db.execute(
            "INSERT INTO users (username, hash) VALUES (?, ?)",
            username,
            generate_password_hash(password),
        )

        rows = db.execute("SELECT * FROM users WHERE username = ?", username)

        session["user_id"] = rows[0]["id"]

        return redirect("/")

    return render_template("register.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""
    user_id = session["user_id"]
    stocks = db.execute("SELECT * FROM shares WHERE user_id = ?", user_id)

    if request.method == "POST":
        symbol = request.form.get("symbol")
        shares = request.form.get("shares")
        symbols = db.execute("SELECT symbol FROM shares WHERE user_id = ?", user_id)

        symbols_list = []

        for symbol_name in symbols:
            symbols_list.append(symbol_name["symbol"])

        if symbol == "" or symbol not in symbols_list:
            return apology("Invalid Symbol")
        if shares == "":
            return apology("Blank Field Shares")

        shares = int(shares)
        owned_shares = int(
            db.execute(
                "SELECT share FROM shares WHERE user_id = ? AND symbol = ?",
                user_id,
                symbol,
            )[0]["share"]
        )

        if shares > owned_shares:
            return apology("Invalid Number of Shares")

        # Registring the sale on the shares database

        info = lookup(symbol)

        total = (owned_shares - shares) * info["price"]
        db.execute(
            "UPDATE shares SET share = ?, total = ?, total_money = ? WHERE user_id = ? AND symbol = ?",
            (owned_shares - shares),
            usd(total),
            total,
            user_id,
            symbol,
        )

        cash = db.execute("SELECT cash FROM users WHERE id = ?", user_id)[0]["cash"]

        money = cash + (shares * info["price"])

        # Adding money to users database
        db.execute("UPDATE users SET cash = ? WHERE id = ?", money, user_id)

        # Saving it in history
        db.execute(
            "INSERT INTO history (user_id, symbol, share, price) VALUES (?, ?, ?, ?)",
            user_id,
            info["symbol"],
            -abs(shares),
            usd(info["price"]),
        )

        return redirect("/")

    return render_template("sell.html", stocks=stocks)
