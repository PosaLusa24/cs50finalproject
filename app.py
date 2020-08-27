"""Flask app."""
from flask import Flask, render_template, request

# Config key-value pairs are stored in config.py
app = Flask(__name__)
app.config.from_pyfile('config.py')

# Homepage
@app.route("/")
def index():
    return render_template("index.html")

# User dashboard
@app.route("/dashboard")
def login():
    return render_template("dashboard.html")

# Login page
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        # TODO: Implement login using database
        pass
    else:
        return render_template("login.html")

# Register page
@app.route("/register", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        # TODO: Implement register using database
        pass
    else:
        return render_template("register.html")
