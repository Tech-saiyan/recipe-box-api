"""Recipe Box API — BE104 course skeleton.

Authorization model for recipes:

- Every recipe has an `owner_id` that points to the user who created it.
- When a logged-in user creates a recipe, we take their user ID from the
  verified JWT `sub` claim and store it as `owner_id`. The client cannot
  choose or change this.

- For update and delete:
    1. Authenticate the request (Bearer token + JWT verification).
    2. Load the target recipe from the database.
    3. If the recipe doesn't exist, return 404.
    4. Compare `recipe.owner_id` to the user ID from the token.
       - If they differ -> return 403 Forbidden (user is authenticated but
         not allowed to modify/delete this resource).
       - If they match -> perform the update or delete.

- 401 Unauthorized = token missing/invalid/expired (we don't know who you are).
- 403 Forbidden   = token valid but user doesn't own the resource
                    (we know who you are; you still can't do this).

This prevents one authenticated user from changing or deleting another
user's recipes.
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

    # Strip whitespace and handle None values
    username = (data.get("username") or "").strip()
    password = (data.get("password") or "").strip()

    # Check for missing username or password
    if not username or not password:
        return jsonify({"error": "username and password are required"}), 400

    # Query the database for the user by username
    db = get_db()
    cursor = db.execute(
    "SELECT id, username, password_hash, role FROM users WHERE username = ?",
    (username,),
)

    user = cursor.fetchone()

    # Unknown username or wrong password → same 401 response
    if user is None or not verify_password(user["password_hash"], password):
        return jsonify({"error": "Invalid credentials"}), 401

    # ✅ Success: issue a signed JWT carrying identity + expiry
    payload = {
    "sub": str(user["id"]),
    "username": user["username"],
    "role": user["role"],  # 👈 new claim
    "exp": datetime.utcnow() + timedelta(minutes=55),
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

@app.post("/recipes")
def create_recipe():
    """
    Create a new recipe owned by the authenticated user.

    - Requires a valid Bearer token.
    - Extracts user ID from the JWT `sub` claim.
    - Inserts a recipe row with `owner_id` set to that user ID.
    - The client cannot set or override `owner_id`.
    """

    auth_header = request.headers.get("Authorization", "")
    parts = auth_header.split()

    if len(parts) != 2 or parts[0] != "Bearer":
        return jsonify({"error": "authentication required"}), 401

    token = parts[1]

    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
    except PyJWTError:
        return jsonify({"error": "invalid token"}), 401

    user_id = int(payload.get("sub"))

    data = request.get_json(silent=True)
    if not data or not data.get("title") or not data.get("ingredients"):
        return jsonify({"error": "title and ingredients are required"}), 400

    db = get_db()
    try:
        cur = db.execute(
            "INSERT INTO recipes (title, ingredients, instructions, is_public, owner_id)"
            " VALUES (?, ?, ?, ?, ?)",
            (
                data["title"],
                data["ingredients"],
                data.get("instructions", ""),
                1 if data.get("is_public", True) else 0,
                user_id,  # 👈 from token
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
    """
    Update a recipe only if the caller owns it.

    Steps:
    1. Authenticate the request (Bearer token + JWT verify).
    2. Load the recipe by `recipe_id`.
       - If not found -> 404.
    3. Check `recipe.owner_id` against user ID from JWT.
       - If mismatch -> 403 Forbidden.
    4. If owner -> apply requested field updates.
    """

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

    user_id = int(payload.get("sub"))
    role = payload.get("role")

    db = get_db()
    # 1️⃣ Load the recipe first
    recipe = db.execute(
        "SELECT * FROM recipes WHERE id = ?",
        (recipe_id,),
    ).fetchone()

    if recipe is None:
        return jsonify({"error": "recipe not found"}), 404

    # 2️⃣ Enforce ownership and determine role
    if recipe["owner_id"] != user_id and role != "admin":
        return jsonify({"error": "forbidden: you do not own this recipe"}), 403

    # 3️⃣ Existing update logic
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

    try:
        cur = db.execute(
            f"UPDATE recipes SET {', '.join(fields)} WHERE id = ?",
            values,
        )
        db.commit()
    except sqlite3.IntegrityError:
        return jsonify({"error": "a recipe with that title already exists"}), 409

    row = db.execute(
        "SELECT * FROM recipes WHERE id = ?", (recipe_id,)
    ).fetchone()
    return jsonify(recipe_to_dict(row))

"""Delete a recipe."""
@app.delete("/recipes/<int:recipe_id>")
def delete_recipe(recipe_id):
    """
    Delete a recipe only if the caller owns it.

    Steps:
    1. Authenticate via Bearer token + JWT.
    2. Load the recipe:
       - If not found -> 404.
    3. If `owner_id` != user ID from token -> 403 Forbidden.
    4. If owner -> delete the recipe and return 204 No Content.
    """
    
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

    user_id = int(payload.get("sub"))
    role = payload.get("role")

    db = get_db()

    # 1️⃣ Load the recipe first
    recipe = db.execute(
        "SELECT * FROM recipes WHERE id = ?",
        (recipe_id,),
    ).fetchone()

    if recipe is None:
        return jsonify({"error": "recipe not found"}), 404

    # 2️⃣ Enforce ownership and determine role
    if recipe["owner_id"] != user_id and role != "admin":
        return jsonify({"error": "forbidden: you do not own this recipe"}), 403

    # 3️⃣ Only owner can delete
    cur = db.execute("DELETE FROM recipes WHERE id = ?", (recipe_id,))
    db.commit()

    return "", 204

"""Run the app."""
if __name__ == "__main__":
    app.run(debug=True)
