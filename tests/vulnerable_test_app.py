"""
vulnerable_test_app.py — An intentionally vulnerable Flask app for testing scanners.
Never deploy this anywhere.
"""

import os
import sqlite3
import uuid
from html import escape

from flask import Flask, request, make_response

app = Flask(__name__)

# Store the database next to this file — it should be writable
_HERE = os.path.abspath(os.path.dirname(__file__))
DB = os.path.join(_HERE, "vulntest_scanners.db")


def init_db():
    conn = sqlite3.connect(DB)
    conn.execute("DROP TABLE IF EXISTS users")
    conn.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, password TEXT)")
    conn.execute("INSERT INTO users (username, password) VALUES ('admin', 'secret123')")
    conn.commit()
    conn.close()


@app.route("/")
def home():
    return """
    <html><body><h1>Vulnerable Test App</h1>
    <ul>
      <li><a href="/search?q=admin">search</a></li>
      <li><a href="/search_safe?q=admin">search (safe)</a></li>
      <li><a href="/blind?name=admin">blind lookup</a></li>
      <li><a href="/dynamic?q=a">dynamic page</a></li>
      <li><a href="/greet?name=World">greet</a></li>
      <li><a href="/greet_safe?name=World">greet (safe)</a></li>
      <li><a href="/login">login</a></li>
      <li><a href="/private">private (disallowed by robots.txt)</a></li>
      <li><a href="/sql_docs?q=x">SQL tutorial page</a></li>
      <li><a href="/login_safe">login (safe)</a></li>
      <li><a href="https://example.com/">external site (out of scope)</a></li>
      <li><a href="mailto:test@example.com">mail</a></li>
    </ul>
    </body></html>
    """


# --- SQLi (vulnerable) ---

@app.route("/search")
def search():
    q = request.args.get("q", "")
    conn = sqlite3.connect(DB)
    try:
        cur = conn.execute(f"SELECT username FROM users WHERE username = '{q}'")
        rows = cur.fetchall()
        result = f"<p>Results: {rows}</p>"
    except sqlite3.OperationalError as e:
        result = f"<p>Database error: {e}</p>"
    conn.close()
    return f"<html><body>{result}</body></html>"


# --- SQLi (safe) ---

@app.route("/search_safe")
def search_safe():
    q = request.args.get("q", "")
    conn = sqlite3.connect(DB)
    try:
        cur = conn.execute("SELECT username FROM users WHERE username = ?", (q,))
        rows = cur.fetchall()
        result = f"<p>Results: {rows}</p>"
    except sqlite3.OperationalError:
        result = "<p>Error</p>"
    conn.close()
    return f"<html><body>{result}</body></html>"


# --- robots.txt and a page it disallows ---

@app.route("/robots.txt")
def robots():
    return "User-agent: *\nDisallow: /private\n", 200, {"Content-Type": "text/plain"}


@app.route("/private")
def private():
    return "<html><body><p>Private area</p></body></html>"


# --- A page that merely TALKS about SQL errors (must not be flagged) ---

@app.route("/sql_docs")
def sql_docs():
    return ("<html><body><p>Tip: if you see 'You have an error in your SQL syntax' "
            "your query is malformed.</p></body></html>")


# --- Blind SQLi (vulnerable, but never shows database errors) ---

@app.route("/blind")
def blind():
    name = request.args.get("name", "")
    conn = sqlite3.connect(DB)
    try:
        found = conn.execute(f"SELECT 1 FROM users WHERE username = '{name}'").fetchone()
    except sqlite3.Error:
        found = None
    conn.close()
    return f"<html><body><p>{'User found' if found else 'User not found'}</p></body></html>"


# --- Dynamic page: content changes on every request (must not look like SQLi) ---

@app.route("/dynamic")
def dynamic():
    words = " ".join(uuid.uuid4().hex for _ in range(60))
    return f"<html><body><p>{words}</p></body></html>"


# --- XSS (vulnerable) ---

@app.route("/greet")
def greet():
    name = request.args.get("name", "")
    return f"<html><body><h1>Hello, {name}!</h1></body></html>"


# --- XSS (safe) ---

@app.route("/greet_safe")
def greet_safe():
    name = request.args.get("name", "")
    return f"<html><body><h1>Hello, {escape(name)}!</h1></body></html>"


# --- Login ---

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return """
        <html><body>
        <form method="post" action="/login">
          <input type="text" name="username">
          <input type="password" name="password">
          <input type="submit" value="Login">
        </form>
        </body></html>
        """

    username = request.form.get("username", "")
    password = request.form.get("password", "")

    conn = sqlite3.connect(DB)
    cur = conn.execute("SELECT * FROM users WHERE username = ?", (username,))
    user = cur.fetchone()
    conn.close()

    if user is None:
        return "<p>No such user.</p>"
    if user[2] != password:
        return "<p>Invalid password.</p>"

    resp = make_response("<p>Logged in!</p>")
    resp.set_cookie("session", "fake-session-token")
    return resp


# --- Login (safe: generic error message and a CSRF token) ---

@app.route("/login_safe", methods=["GET", "POST"])
def login_safe():
    if request.method == "GET":
        return """
        <html><body>
        <form method="post" action="/login_safe">
          <input type="hidden" name="csrf_token" value="abc123">
          <input type="text" name="username">
          <input type="password" name="password">
          <input type="submit" value="Login">
        </form>
        </body></html>
        """
    return "<p>Invalid username or password.</p>"


if __name__ == "__main__":
    init_db()
    app.run(host="127.0.0.1", port=5097)