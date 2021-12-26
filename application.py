import os

from cs50 import SQL
from flask import Flask, flash, jsonify, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash

from datetime import datetime
from re import fullmatch

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
    """Show portfolio of stocks"""

    getValues = db.execute("SELECT symbol, name, SUM(shares) as totalShares FROM buySell WHERE user_id = :user_id GROUP BY symbol", user_id = session["user_id"])

    db.execute("DELETE FROM owned")

    for value in getValues:
        val = lookup(value['symbol'])
        totAmount = value['totalShares'] * val['price']
        db.execute("INSERT INTO owned (symbol, name, shares, currentPrice, total) VALUES (:symbol, :name, :shares, :currentPrice,:total)",
        symbol = value['symbol'], name = value['name'], shares = value['totalShares'], currentPrice = format(val['price'], '.2f'), total = format(totAmount, '.2f'))

    ownedLists = db.execute("SELECT * FROM owned")

    cashOwnedDict = db.execute("SELECT round(cash, 2) as cash FROM users where id = :user_id", user_id = session["user_id"])
    cashOwned = usd(cashOwnedDict[0]['cash'])
    temp = 0
    for li in ownedLists:
        temp = temp + li['total']

    totalCash = usd(cashOwnedDict[0]['cash'] + temp)

    ownedListsImprov = ownedLists

    for li in ownedListsImprov:
        li['currentPrice'] = usd(li['currentPrice'])
        li['total'] = usd(li['total'])

    return render_template("index.html", ownedLists = ownedListsImprov, cashOwned = cashOwned, totalCash = totalCash)


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""

    if request.method == "POST":
        symbol = request.form.get("symbol")
        shares = request.form.get("shares")
        lookupVal = lookup(symbol)

        if not symbol:
            return apology("missing symbol", 400)

        elif not shares:
            return apology("missing shares", 400)

        elif lookupVal == None:
            return apology("invalid symbol", 400)

        elif int(shares) < 1:
            return apology("shares must be greater than or equal to 1", 400)

        else:
            idof = db.execute("SELECT cash FROM users WHERE id = :id", id = session['user_id'])
            amount = int(shares) * lookupVal['price']
            if idof[0]['cash'] - amount < 0:
                return apology("can't afford", 400)
            else:
                deduct = idof[0]['cash'] - amount
                dateTimeObj = datetime.now().replace(microsecond=0)
                lookupVal['price'] = format(lookupVal['price'], '.2f')
                db.execute("UPDATE users SET cash = :deduct WHERE id = :id", deduct = deduct, id = session['user_id'])
                db.execute("INSERT INTO buySell (user_id, name, symbol, shares, price) VALUES(:user_id, :name, :symbol, :shares, :price)",
                user_id = session['user_id'],  name = lookupVal['name'], symbol = lookupVal['symbol'], shares = int(shares), price = lookupVal['price'])
                flash('Bought!')
                return redirect("/")
    else:
        return render_template("buy.html")


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""

    transactions = db.execute("SELECT symbol, shares, dateTimeStamp FROM buySell where user_id = :user_id", user_id = session["user_id"])
    historyList = []
    dictionary = {}
    for temp in transactions:
        lookupVal = lookup(temp['symbol'])
        dictionary = {
            'symbol': temp['symbol'],
            'shares': temp['shares'],
            'price': usd(lookupVal['price']),
            'timeTransacted': temp['dateTimeStamp']
            }
        historyList.append(dictionary)

    return render_template("history.html", historys = historyList)


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
        session["username"] = rows[0]["username"]

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
        lookupVal = lookup(symbol)
        if not symbol:
            return apology("Missing Symbol", 400)
        elif lookupVal == None:
            return apology("Invalid Symbol", 400)
        else:
            return render_template("quoted.html", name = lookupVal["name"], symbol = lookupVal["symbol"], cost = format(lookupVal["price"], '.2f'))
    else:
        return render_template("quote.html")

@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    session.clear()

    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        confirmPassword = request.form.get("confirmation")
        if not username:
            return apology('Must Provide A Username', 403)

        elif username.find(' ') >= 0:
            return apology('No Spaces allowed in username', 403)
        rows = db.execute("SELECT * FROM users WHERE username = :username",
                           username=request.form.get("username"))
        if len(rows) == 1:
            return apology("Please provide a different Username", 403)
        elif not password:
            return apology("missing password", 403)

        elif not fullmatch(r'[A-Za-z0-9@#$%^&+=]{8,}', password):
            return apology("Minimum 8 characters,Atleast one:uppercase(A-Z),lowercase(a-z),number(0-9) and special character among @#$%^&+=", 403)

        elif password != confirmPassword:
            return apology("password dont match", 400)
        else:
            hashedPass = generate_password_hash(password)
            db.execute("INSERT INTO users (username, hash) VALUES (:username, :password)",username = username, password = hashedPass)
            rows = db.execute("SELECT * FROM users WHERE username = :username", username = username)
            session['user_id'] = rows[0]['id']
            session["username"] = rows[0]["username"]
            flash('Registered!')
            return redirect("/")

    else:
        return render_template("register.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""
    if request.method == "POST":
        symbol = request.form.get("symbol")
        shares = request.form.get("shares")
        if not symbol:
            return apology("missing symbol", 400)

        elif not shares:
            return apology("missing shares", 400)

        shares = int(shares)
        ownedShares = db.execute("SELECT shares from owned WHERE symbol = :symbol", symbol = symbol)

        if shares < 1:
            return apology("shares must be greater than or equal to 1", 400)

        elif shares > ownedShares[0]['shares']:
            return apology("too many shares", 400)

        else:
            lookupVal = lookup(symbol)
            idof = db.execute("SELECT cash FROM users WHERE id = :id", id = session['user_id'])
            addAmt = format((lookupVal['price'] * shares + idof[0]['cash']), '.2f')
            db.execute("UPDATE users SET cash = :addAmt WHERE id = :id", addAmt = addAmt, id = session['user_id'])
            db.execute("INSERT INTO buySell (user_id, name, symbol, shares, price) VALUES (:user_id, :name, :symbol, :shares, :price)",
            user_id = session["user_id"], name = lookupVal["name"], symbol = lookupVal["symbol"], shares = (-shares) ,price = lookupVal["price"])
            flash('Sold!')
            return redirect("/")

    else:
        symbols = db.execute("SELECT symbol FROM owned")
        return render_template("sell.html", symbols = symbols)

@app.route("/changePassword", methods=["GET", "POST"])
@login_required
def changePassword():
    if request.method == "POST":
        oldPassword = request.form.get("oldPassword")
        newPassword = request.form.get("newPassword")
        confirmPassword = request.form.get("confirmation")

        if not (oldPassword or newPassword or confirmPassword):
            return apology("Missing Password", 403)

        rows = db.execute("SELECT * FROM users where id = :user_id", user_id = session["user_id"])

        if not check_password_hash(rows[0]["hash"], oldPassword):
            return apology("Wrong password", 403)

        elif not fullmatch(r'[A-Za-z0-9@#$%^&+=]{8,}', newPassword):
            return apology("Minimum 8 characters,Atleast one:uppercase(A-Z),lowercase(a-z),number(0-9) and special character among @#$%^&+=", 403)

        elif newPassword != confirmPassword:
            return apology("password mismatch", 403)

        else:
            hashedPass = generate_password_hash(newPassword)
            db.execute("UPDATE users SET hash = :hashedPass WHERE id = :user_id", hashedPass = hashedPass, user_id = session["user_id"])
            flash("Password Updated!")
            return redirect("/")

    else:
        return render_template("changePassword.html")

def errorhandler(e):
    """Handle error"""
    if not isinstance(e, HTTPException):
        e = InternalServerError()
    return apology(e.name, e.code)


# Listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)
