"""Recipe Box API — BE104 course skeleton.

A working Flask + SQLite CRUD API for recipes. It stores data perfectly —
and it trusts everyone. There is no authentication and no authorization yet.
That is the point: you will add both, lesson by lesson, in Units 2 and 3.
"""

import sqlite3

import os

import jwt

from jwt import PyJWTError, ExpiredSignatureError

from datetime import datetime, timedelta

from dotenv import load_dotenv

from flask import Flask, g, jsonify, request

from werkzeug.security import generate_password_hash, check_password_hash

DATABASE = "recipes.db"

load_dotenv()

SECRET_KEY = os.getenv("SECRET_KEY")
if not SECRET_KEY:
    raise RuntimeError("SECRET_KEY is not set")

app = Flask(__name__)
app.config["SECRET_KEY"] = SECRET_KEY

"""User registration endpoint."""
@app.post("/register")
def register():
    data = request.get_json(silent=True) or {}

    username = (data.get("username") or "").strip()
    email = (data.get("email") or "").strip()
    password = (data.get("password") or "").strip()

    if not username or not email or not password:
        return jsonify({"error": "username, email, and password are required"}), 400

    db = get_db()

    password_hash = generate_password_hash(password)

    try:
        cursor = db.execute(
            """
            INSERT INTO users (username, email, password_hash)
            VALUES (?, ?, ?)
            """,
            (username, email, password_hash),
        )
        db.commit()
    except sqlite3.IntegrityError:
        return jsonify({"error": "username or email already exists"}), 409

    new_id = cursor.lastrowid

    return jsonify({
        "id": new_id,
        "username": username,
        "email": email
    }), 201

@app.post("/login")
def login():
    data = request.get_json(silent=True) or {}

    username = (data.get("username") or "").strip()
    password = (data.get("password") or "").strip()

    if not username or not password:
        return jsonify({"error": "username and password are required"}), 400

    db = get_db()
    cursor = db.execute(
        "SELECT id, username, password_hash FROM users WHERE username = ?",
        (username,),
    )
    user = cursor.fetchone()

    # Unknown username or wrong password → same 401 response
    if user is None or not verify_password(user["password_hash"], password):
        return jsonify({"error": "Invalid credentials"}), 401

    # ✅ Success: issue a signed JWT carrying identity + expiry
    payload = {
    "sub": str(user["id"]),     # 👈 make subject a string
    "username": user["username"],
    "exp": datetime.utcnow() + timedelta(seconds=60),
    }       

    token = jwt.encode(payload, SECRET_KEY, algorithm="HS256")

    return jsonify({
        "token": token,
    }), 200

"""Password hashing functions."""
def hash_password(plain_password: str) -> str:
    return generate_password_hash(plain_password)

def verify_password(stored_hash: str, candidate_password: str) -> bool:
    return check_password_hash(stored_hash, candidate_password)

"""Database connection functions."""
def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DATABASE)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db

""" this function is called automatically when the request context ends, and it closes the database connection if it was opened. """
@app.teardown_appcontext
def close_db(exception):
    db = g.pop("db", None)
    if db is not None:
        db.close()

"""Helper function to convert a recipe row to a dictionary."""
def recipe_to_dict(row):
    return {
        "id": row["id"],
        "title": row["title"],
        "ingredients": row["ingredients"],
        "instructions": row["instructions"],
        "is_public": bool(row["is_public"]),
    }

"""API endpoints."""
@app.get("/")
def hello():
    return jsonify({"message": "Recipe Box API", "recipes": "/recipes"})

"""List all recipes."""
@app.get("/recipes")
def list_recipes():
    rows = get_db().execute("SELECT * FROM recipes ORDER BY id").fetchall()
    return jsonify([recipe_to_dict(r) for r in rows])

"""Get a single recipe by ID."""
@app.get("/recipes/<int:recipe_id>")
def get_recipe(recipe_id):
    row = get_db().execute(
        "SELECT * FROM recipes WHERE id = ?", (recipe_id,)
    ).fetchone()
    if row is None:
        return jsonify({"error": "recipe not found"}), 404
    return jsonify(recipe_to_dict(row))

"""Create a new recipe."""
@app.post("/recipes")
def create_recipe():
    auth_header = request.headers.get("Authorization", "")
    print("AUTH HEADER:", repr(auth_header))  # 👈 debug

    parts = auth_header.split()
    print("PARTS:", parts)  # 👈 debug

    if len(parts) != 2 or parts[0] != "Bearer":
        print("BAD FORMAT")  # 👈 debug
        return jsonify({"error": "authentication required"}), 401

    token = parts[1]
    print("TOKEN START:", token[:40], "LEN:", len(token))  # 👈 debug

    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        print("DECODED PAYLOAD:", payload)  # 👈 debug
    except PyJWTError as e:
        print("JWT ERROR TYPE:", type(e), "MSG:", str(e))  # 👈 debug
        return jsonify({"error": "invalid token"}), 401

    user_id = int(payload.get("sub"))  # or just leave as string
    username = payload.get("username")

    # (no ownership checks yet, just proving we *know* who's calling)

    # ⬇️ your existing recipe creation logic
    data = request.get_json(silent=True)
    if not data or not data.get("title") or not data.get("ingredients"):
        return jsonify({"error": "title and ingredients are required"}), 400
    db = get_db()
    try:
        cur = db.execute(
            "INSERT INTO recipes (title, ingredients, instructions, is_public)"
            " VALUES (?, ?, ?, ?)",
            (
                data["title"],
                data["ingredients"],
                data.get("instructions", ""),
                1 if data.get("is_public", True) else 0,
            ),
        )
        db.commit()
    except sqlite3.IntegrityError:
        return jsonify({"error": "a recipe with that title already exists"}), 409
    row = db.execute(
        "SELECT * FROM recipes WHERE id = ?", (cur.lastrowid,)
    ).fetchone()
    return jsonify(recipe_to_dict(row)), 201

"""Update an existing recipe."""
@app.patch("/recipes/<int:recipe_id>")
def update_recipe(recipe_id):
    # 🔐 Require a valid Bearer token
    auth_header = request.headers.get("Authorization", "")
    parts = auth_header.split()

    if len(parts) != 2 or parts[0] != "Bearer":
        return jsonify({"error": "authentication required"}), 401

    token = parts[1]

    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
    except ExpiredSignatureError:
        return jsonify({"error": "token expired, please log in again"}), 401
    except PyJWTError:
        return jsonify({"error": "invalid token"}), 401

    user_id = payload.get("sub")
    username = payload.get("username")
    # (we're not using these yet for ownership — just proving identity)

    # ⬇️ existing update logic
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "a JSON body is required"}), 400
    fields, values = [], []
    for column in ("title", "ingredients", "instructions"):
        if column in data:
            fields.append(f"{column} = ?")
            values.append(data[column])
    if "is_public" in data:
        fields.append("is_public = ?")
        values.append(1 if data["is_public"] else 0)
    if not fields:
        return jsonify({"error": "nothing to update"}), 400
    values.append(recipe_id)
    db = get_db()
    try:
        cur = db.execute(
            f"UPDATE recipes SET {', '.join(fields)} WHERE id = ?", values
        )
        db.commit()
    except sqlite3.IntegrityError:
        return jsonify({"error": "a recipe with that title already exists"}), 409
    if cur.rowcount == 0:
        return jsonify({"error": "recipe not found"}), 404
    row = db.execute(
        "SELECT * FROM recipes WHERE id = ?", (recipe_id,)
    ).fetchone()
    return jsonify(recipe_to_dict(row))

"""Delete a recipe."""
@app.delete("/recipes/<int:recipe_id>")
def delete_recipe(recipe_id):
    # 🔐 Require a valid Bearer token
    auth_header = request.headers.get("Authorization", "")
    parts = auth_header.split()

    if len(parts) != 2 or parts[0] != "Bearer":
        return jsonify({"error": "authentication required"}), 401

    token = parts[1]

    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
    except PyJWTError:
        return jsonify({"error": "invalid token"}), 401

    user_id = payload.get("sub")
    username = payload.get("username")
    # (still no ownership checks yet)

    # ⬇️ your existing delete logic here
    db = get_db()
    cur = db.execute("DELETE FROM recipes WHERE id = ?", (recipe_id,))
    db.commit()

    if cur.rowcount == 0:
        return jsonify({"error": "recipe not found"}), 404

    return "", 204

"""Run the app."""
if __name__ == "__main__":
    app.run(debug=True)
