import os

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session, url_for
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

    # Select data
    id = session["user_id"]
    unique_symbols = db.execute("SELECT DISTINCT symbol FROM history WHERE user_id = ?;", id)
    share_tally = {}
    price = {}
    total_holding_value = {}

    for symbol in unique_symbols:
        # Share tally
        shares = db.execute(
            "SELECT SUM(shares) FROM history WHERE symbol = ? AND user_id = ?;", symbol["symbol"], id)
        if symbol["symbol"] not in share_tally:
            share_tally[symbol["symbol"]] = 0
        if shares[0]["SUM(shares)"] == None:
            shares[0]["SUM(shares)"] = 0
        share_tally[symbol["symbol"]] += shares[0]["SUM(shares)"]
        if share_tally[symbol["symbol"]] == 0:
            continue

        # Price of one share
        if symbol["symbol"] not in price:
            price[symbol["symbol"]] = 0
        price[symbol["symbol"]] += lookup(symbol["symbol"])["price"]

        # Value of all shares held of that symbol
        if symbol["symbol"] not in total_holding_value:
            total_holding_value[symbol["symbol"]] = 0
        total_holding_value[symbol["symbol"]] = float(
            price[symbol["symbol"]]) * float(shares[0]["SUM(shares)"])

    cash = db.execute("SELECT cash FROM users WHERE id = ?;", id)
    total_holdings_value = db.execute("SELECT SUM(total_cost) FROM history WHERE user_id = ?;", id)
    if total_holdings_value[0]["SUM(total_cost)"] == None:
        total_holdings_value[0]["SUM(total_cost)"] = 0
    grand_total = float(total_holdings_value[0]["SUM(total_cost)"]) + float(cash[0]["cash"])

    return render_template("index.html", usd=usd, unique_symbols=unique_symbols, share_tally=share_tally, price=price, total_holding_value=total_holding_value, cash=cash, total_holdings_value=total_holdings_value, grand_total=grand_total)


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""

    if request.method == "GET":
        return render_template("buy.html")

    if request.method == "POST":
        # Get values
        shares = request.form.get("shares")
        try:
            if int(shares) < 0:
                return apology("must provide shares", 400)
        except ValueError:
            return apology("invalid value type", 400)

        symbol = request.form.get("symbol")
        if not symbol:
            return apology("must provide symbol", 403)

        stock = lookup(symbol)
        if stock == None:
            return apology("symbol is invalid", 400)
        price = stock["price"]

        id = session["user_id"]
        cash = db.execute("SELECT cash FROM users WHERE id = ?;", id)
        total_cost = float(price) * float(shares)

        # Create table
        db.execute("""CREATE TABLE IF NOT EXISTS history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                symbol TEXT NOT NULL,
                shares INTEGER NOT NULL,
                price NUMERIC NOT NULL,
                total_cost NUMERIC NOT NULL,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(user_id) REFERENCES users(id));""")

        # Check if user can afford purchase
        if int(total_cost) > cash[0]["cash"]:
            return apology("you cannot afford this", 403)

        # Update purchase history
        db.execute("INSERT INTO history (user_id, shares, symbol, price, total_cost) VALUES(?, ?, ?, ?, ?)",
                   id, shares, symbol, price, total_cost)

        # Update balance
        db.execute("UPDATE users SET cash = cash - ? WHERE id = ?;", total_cost, id)

        # Return to homepage
        return redirect(url_for("index"))

    return apology("TODO")


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""

    id = session["user_id"]
    unique_symbols = db.execute("SELECT DISTINCT symbol FROM history WHERE user_id = ?;", id)
    transacted = db.execute("SELECT timestamp FROM history WHERE user_id = ?;", id)
    history = db.execute("SELECT * FROM history WHERE user_id = ?;", id)
    # Start code from index
    share_tally = {}
    price = {}

    for symbol in unique_symbols:
        # Share tally
        shares = db.execute(
            "SELECT SUM(shares) FROM history WHERE symbol = ? AND user_id = ?;", symbol["symbol"], id)
        if symbol["symbol"] not in share_tally:
            share_tally[symbol["symbol"]] = 0
        if shares[0]["SUM(shares)"] == None:
            shares[0]["SUM(shares)"] = 0
        share_tally[symbol["symbol"]] += shares[0]["SUM(shares)"]

        # Price of one share
        if symbol["symbol"] not in price:
            price[symbol["symbol"]] = 0
        price[symbol["symbol"]] += lookup(symbol["symbol"])["price"]
    return render_template("history.html", usd=usd, unique_symbols=unique_symbols, share_tally=share_tally, price=price, transacted=transacted, history=history)


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
    if request.method == "GET":
        return render_template("quote.html")

    if request.method == "POST":
        symbol = request.form.get("symbol")
        if not symbol:
            return apology("must require symbol", 400)
        lookupResults = lookup(symbol)
        if lookupResults == None:
            return apology("invalid ticker", 400)
        return render_template("quoted.html", lookupResults=lookupResults, usd=usd)

    return apology("must require symbol", 400)


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""

    # Get username, password, password confirmation
    username = request.form.get("username")
    password = request.form.get("password")
    confirmation = request.form.get("confirmation")

    if request.method == "POST":
        # Check for valid username
        if not username:
            return apology("must provide username", 400)
        if db.execute("SELECT username FROM users WHERE username = ?;", username):
            return apology("invalid username", 400)

        # Check for valid password and confirmation
        if not password:
            return apology("must provide password", 400)
        if not confirmation:
            return apology("must provide confirmation", 400)
        if password != confirmation:
            return apology("password must match confirmation", 400)

        # Generate password hash
        passwordHash = generate_password_hash(password)

        # Insert username and hash into database
        try:
            db.execute("INSERT INTO users (username, hash) VALUES (?, ?);", username, passwordHash)
        except ValueError:
            return apology("invalid username", 403)

        # Start cookies
        id = db.execute("SELECT id FROM users WHERE username = ? AND hash = ?;",
                        username, passwordHash)
        session["user_id"] = id[0]["id"]

        # Redirect to homepage
        return redirect(url_for("index"))

    return render_template("register.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""

    id = session["user_id"]
    unique_symbols = db.execute("SELECT DISTINCT symbol FROM history WHERE user_id = ?;", id)

    # Start code from index
    share_tally = {}
    price = {}
    total_holding_value = {}

    for symbol in unique_symbols:
        # Share tally
        shares = db.execute(
            "SELECT SUM(shares) FROM history WHERE symbol = ? AND user_id = ?;", symbol["symbol"], id)
        if symbol["symbol"] not in share_tally:
            share_tally[symbol["symbol"]] = 0
        if shares[0]["SUM(shares)"] == None:
            shares[0]["SUM(shares)"] = 0
        share_tally[symbol["symbol"]] += shares[0]["SUM(shares)"]

        # Price of one share
        if symbol["symbol"] not in price:
            price[symbol["symbol"]] = 0
        price[symbol["symbol"]] += lookup(symbol["symbol"])["price"]

        # Value of all shares held of that symbol
        if symbol["symbol"] not in total_holding_value:
            total_holding_value[symbol["symbol"]] = 0
        total_holding_value[symbol["symbol"]] = float(
            price[symbol["symbol"]]) * float(shares[0]["SUM(shares)"])

    cash = db.execute("SELECT cash FROM users WHERE id = ?;", id)
    total_holdings_value = db.execute("SELECT SUM(total_cost) FROM history WHERE user_id = ?;", id)
    if total_holdings_value[0]["SUM(total_cost)"] == None:
        total_holdings_value[0]["SUM(total_cost)"] = 0
    grand_total = float(total_holdings_value[0]["SUM(total_cost)"]) + float(cash[0]["cash"])
    # End code from index

    # Grab submitted values
    selected_stock = request.form.get("symbol")
    selected_shares = request.form.get("shares")

    # Handle GET and POST
    if request.method == "GET":
        return render_template("sell.html", usd=usd, share_tally=share_tally, unique_symbols=unique_symbols)

    if request.method == "POST":
        if not selected_stock:
            return apology("must select stock", 403)
        if int(selected_shares) > share_tally[selected_stock]:
            return apology("too many shares selected", 400)
        if int(selected_shares) < 0:
            return apology("shares must be greater than 0", 400)

        total_cost = float(price[selected_stock]) * float(selected_shares)

        # Update purchase history
        db.execute("INSERT INTO history (user_id, shares, symbol, price, total_cost) VALUES(?, ?, ?, ?, ?)",
                   id, -int(selected_shares), selected_stock, price[selected_stock], -float(total_cost))

        # Update balance
        db.execute("UPDATE users SET cash = cash + ? WHERE id = ?;", total_cost, id)

        unique_symbols = db.execute("SELECT DISTINCT symbol FROM history WHERE user_id = ?;", id)

        # Start code from index
        share_tally = {}
        price = {}
        total_holding_value = {}

        for symbol in unique_symbols:
            # Share tally
            shares = db.execute(
                "SELECT SUM(shares) FROM history WHERE symbol = ? AND user_id = ?;", symbol["symbol"], id)
            if symbol["symbol"] not in share_tally:
                share_tally[symbol["symbol"]] = 0
            if shares[0]["SUM(shares)"] == None:
                shares[0]["SUM(shares)"] = 0
            share_tally[symbol["symbol"]] += shares[0]["SUM(shares)"]

            # Price of one share
            if symbol["symbol"] not in price:
                price[symbol["symbol"]] = 0
            price[symbol["symbol"]] += lookup(symbol["symbol"])["price"]

            # Value of all shares held of that symbol
            if symbol["symbol"] not in total_holding_value:
                total_holding_value[symbol["symbol"]] = 0
            total_holding_value[symbol["symbol"]] = float(
                price[symbol["symbol"]]) * float(shares[0]["SUM(shares)"])

        cash = db.execute("SELECT cash FROM users WHERE id = ?;", id)
        total_holdings_value = db.execute(
            "SELECT SUM(total_cost) FROM history WHERE user_id = ?;", id)
        if total_holdings_value[0]["SUM(total_cost)"] == None:
            total_holdings_value[0]["SUM(total_cost)"] = 0

        total_holdings = 0
        for holding in total_holding_value:
            total_holdings += total_holding_value[holding]
        grand_total = float(total_holdings) + float(cash[0]["cash"])
        # End code from index

        return render_template("index.html", usd=usd, unique_symbols=unique_symbols, share_tally=share_tally, price=price, total_holding_value=total_holding_value, cash=cash, total_holdings_value=total_holdings_value, grand_total=grand_total)
