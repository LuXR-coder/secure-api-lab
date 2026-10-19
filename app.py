import os
import sqlite3
import html
from datetime import timedelta

import bcrypt
from flask import Flask, request, jsonify, g
from flask_jwt_extended import (
    JWTManager, create_access_token, jwt_required, get_jwt_identity
)

app = Flask(__name__)

# 安全配置：JWT 密钥 (严格超过 32 字节)
app.config["JWT_SECRET_KEY"] = os.environ.get("JWT_SECRET", "dev-only-secret-key-must-be-longer-than-32-bytes")
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(minutes=30)
jwt = JWTManager(app)

DATABASE = os.path.join(os.path.dirname(__file__), "app.db")

def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DATABASE)
        g.db.row_factory = sqlite3.Row
    return g.db

@app.teardown_appcontext
def close_db(exc):
    db = g.pop("db", None)
    if db is not None:
        db.close()

def init_db():
    """初始化数据库并写入种子用户"""
    with sqlite3.connect(DATABASE) as db:
        db.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash BLOB NOT NULL
            )
        """)
        db.execute("""
            CREATE TABLE IF NOT EXISTS notes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                owner_id INTEGER NOT NULL,
                content TEXT NOT NULL,
                FOREIGN KEY (owner_id) REFERENCES users(id)
            )
        """)
        # 种子用户
        seed = [("admin", "Admin#2024!"), ("alice", "Alice@Pass123")]
        for username, password in seed:
            existing = db.execute("SELECT id FROM users WHERE username = ?", (username,)).fetchone()
            if existing is None:
                hashed = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt(rounds=12))
                db.execute("INSERT INTO users (username, password_hash) VALUES (?, ?)", (username, hashed))
        db.commit()

# 端点 1：登录 (防 SQLi)
@app.post("/auth/login")
def login():
    data = request.get_json(silent=True) or {}
    username = str(data.get("username", "")).strip()
    password = data.get("password", "")

    if not username or not password:
        return jsonify({"error": "username and password are required"}), 400

    # 参数化查询 (防 SQLi)
    row = get_db().execute("SELECT id, username, password_hash FROM users WHERE username = ?", (username,)).fetchone()

    # 统一错误信息防用户枚举 + bcrypt 校验
    if row is None or not bcrypt.checkpw(password.encode("utf-8"), row["password_hash"]):
        return jsonify({"error": "invalid_credentials"}), 401

    token = create_access_token(identity=str(row["id"]))
    return jsonify({"access_token": token, "token_type": "Bearer", "expires_in": 1800})

# 端点 2：受保护数据 (防 XSS)
@app.get("/api/data")
@jwt_required()
def get_data():
    rows = get_db().execute("SELECT id, username FROM users ORDER BY id").fetchall()
    users = [
        # html.escape 防 XSS
        {"id": r["id"], "username": html.escape(r["username"])}
        for r in rows
    ]
    return jsonify({"users": users})

# 端点 3：自选笔记功能 (防越权 + 防 SQLi + 防 XSS)
@app.post("/api/notes")
@jwt_required()
def create_note():
    user_id = int(get_jwt_identity())
    data = request.get_json(silent=True) or {}
    content = str(data.get("content", "")).strip()

    if not content or len(content) > 5000:
        return jsonify({"error": "invalid content"}), 400

    db = get_db()
    db.execute("INSERT INTO notes (owner_id, content) VALUES (?, ?)", (user_id, content))
    db.commit()
    return jsonify({"message": "note created"}), 201

@app.get("/api/notes")
@jwt_required()
def list_notes():
    user_id = int(get_jwt_identity())
    rows = get_db().execute("SELECT id, content FROM notes WHERE owner_id = ? ORDER BY id", (user_id,)).fetchall()
    notes = [{"id": r["id"], "content": html.escape(r["content"])} for r in rows]
    return jsonify({"notes": notes})

if __name__ == "__main__":
    with app.app_context():
        init_db()
    app.run(debug=False, host="127.0.0.1", port=5000)