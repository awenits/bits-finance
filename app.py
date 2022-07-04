from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

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


@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""
    syms_shares = db.execute("SELECT symbol, shares FROM portfolio WHERE id = :id", id=session["user_id"])
    total = 0
    for record in syms_shares:
        symbol = record["symbol"]
        shares = record["shares"]
        stock = lookup(symbol)
        price = stock["price"]
        if not stock:
            shares_total = 0
        else:
            shares_total = price * shares
        total += shares_total
        # updating portfolio
        db.execute("UPDATE portfolio SET price = :nprice, total = :ntotal WHERE id = :id AND symbol = :sym",
                   nprice=usd(price), ntotal=usd(shares_total), id=session["user_id"], sym=symbol)
    cash = db.execute("SELECT cash FROM users WHERE id = :id", id=session["user_id"])[0]["cash"]
    total += cash
    updated_portfolio = db.execute("SELECT * FROM portfolio WHERE id = :id", id=session["user_id"])
    return render_template("portfolio.html", portfolio=updated_portfolio, cash=usd(cash), total=usd(total))


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""
    if request.method == "GET":
        return render_template("buy.html")
    else:
        symbol = request.form.get("symbol")
        if not symbol:
            return apology("Missing Symbol")
        try:
            shares = int(request.form.get("shares"))
            if shares < 0:
                return apology("Shares must be positive integer")
        except:
            return apology("Shares must be positive integer")
        stock = lookup(symbol)
        if not stock:
            return apology("Symbol doesn't exist.")
        else:
            name = stock["name"]
            price = stock["price"]
            symbol = stock["symbol"]
            total = float(shares) * price
            cash = db.execute("SELECT cash FROM users WHERE id = :id", id=session["user_id"])[0]["cash"]
            if cash < total:
                return apology("No enough cash available!")
            # Adding history
            db.execute("INSERT INTO history(id, symbol, shares, price) VALUES (:id, :symbol, :shares, :price)",
                       id=session["user_id"], symbol=symbol, shares=shares, price=usd(price))
            # update users cash
            db.execute("UPDATE users SET cash = cash - :total WHERE id = :id", total=total, id=session["user_id"])
            users_shares = db.execute("SELECT shares FROM portfolio WHERE id = :id AND symbol = :symbol",
                                      id=session["user_id"], symbol=symbol)
            if not users_shares:
                # storing to portfolio
                db.execute("INSERT INTO portfolio(id, symbol, name, shares, total, price) VALUES(:id, :symbol, :name, :shares, :total, :price)",
                           id=session["user_id"], symbol=symbol, name=name, shares=shares, total=usd(total), price=usd(price))
            else:
                # updating shares and price and total
                total_shares = users_shares[0]["shares"] + shares
                ntotal = float(total_shares) * price
                db.execute("UPDATE portfolio SET shares = :news, price = :newp, total = :newt WHERE id = :id AND symbol = :symbol",
                           news=total_shares, newp=usd(price), newt=usd(ntotal), id=session["user_id"], symbol=symbol)
        flash("Bought!")
        return redirect("/")


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    records = db.execute("SELECT * FROM history WHERE id = :id", id=session["user_id"])
    return render_template("history.html", records=records)


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
    """Get stock quote."""
    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":
        symbol = request.form.get("symbol")
        if not symbol:
            return apology("must provide symbol", 400)
        else:
            stock = lookup(symbol)
            if not stock:
                return apology("Invalid symbol", 400)
            else:
                return render_template("quoted.html", stock=stock, price=usd(stock["price"]))
    else:
        return render_template("quote.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    # Forget any user_id
    session.clear()
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        password_again = request.form.get("confirmation")
        # Ensure username was submitted
        if not username:
            return apology("Missing username", 400)

        # Ensure password was submitted
        elif not password or not password_again:
            return apology("must provide password", 400)

        # Ensure password matches with password again(password confirmation)
        elif password != password_again:
            return apology("password doesn't match", 400)
        pw_hash = generate_password_hash(password)
        result = db.execute("SELECT * FROM users WHERE username = :uname", uname=username)
        if int(len(result)) > 0:
            return apology("Username is already taken!", 400)
        else:
            row = db.execute("INSERT INTO users (username, hash) VALUES(:uname, :hash)", uname=username, hash=pw_hash)
        session["user_id"] = row
        return redirect("/")
    else:
        return render_template("register.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""
    if request.method == "GET":
        symbols = db.execute("SELECT symbol FROM portfolio WHERE id = :id", id=session["user_id"])
        return render_template("sell.html", symbols=symbols)
    else:
        # ensuring valid symbol
        stock = lookup(request.form.get("symbol"))
        if not stock:
            return apology("Invalid Symbol")
        # ensuring valid shares
        try:
            shares = int(request.form.get("shares"))
            if shares < 0:
                return apology("Shares must be positive integer")
        except:
            return apology("Shares must be positive integer")
        # current user shares
        user_shares = db.execute("SELECT shares FROM portfolio WHERE id = :id AND symbol = :sym",
                                 id=session["user_id"], sym=stock["symbol"])
        if not user_shares or user_shares[0]["shares"] < shares:
            return apology("Not enough shares to sell!")
        totalp = stock["price"] * shares
        rshares = user_shares[0]["shares"] - shares
        # add transaction to history
        db.execute("INSERT INTO history(id, symbol, shares, price) VALUES (:id, :symbol, :shares, :price)",
                   id=session["user_id"], symbol=stock["symbol"], shares=-shares, price=usd(stock["price"]))
        if rshares != 0:
            # update portfolio
            db.execute("UPDATE portfolio SET shares= :r_shares WHERE id = :id AND symbol = :sym",
                       r_shares=rshares, id=session["user_id"], sym=stock["symbol"])
        else:
            db.execute("DELETE FROM portfolio WHERE id = :id AND symbol = :sym", id=session["user_id"], sym=stock["symbol"])
        # update users cash
        db.execute("UPDATE users SET cash = cash + :total WHERE id = :id", total=totalp, id=session["user_id"])
        flash("Sold!")
        return redirect("/")


def errorhandler(e):
    """Handle error"""
    return apology(e.name, e.code)


# listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)
