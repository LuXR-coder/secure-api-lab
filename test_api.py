import os
import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault("JWT_SECRET", "test-secret-key-must-be-longer-than-32-bytes")

import pytest
from app import app, init_db

@pytest.fixture
def client():
    app.config["TESTING"] = True
    with app.app_context():
        init_db()
    with app.test_client() as c:
        yield c

def test_login_success(client):
    r = client.post("/auth/login", json={"username": "admin", "password": "Admin#2024!"})
    assert r.status_code == 200
    assert "access_token" in r.get_json()

def test_sql_injection_login_fails(client):
    r = client.post("/auth/login", json={"username": "admin' OR 1=1 --", "password": "x"})
    assert r.status_code == 401

def test_protected_requires_token(client):
    r = client.get("/api/data")
    assert r.status_code == 401

def test_xss_escaped(client):
    login = client.post("/auth/login", json={"username": "alice", "password": "Alice@Pass123"})
    token = login.get_json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}
    client.post("/api/notes", json={"content": "<script>alert(1)</script>"}, headers=headers)
    r = client.get("/api/notes", headers=headers)
    assert "&lt;script&gt;" in r.get_json()["notes"][0]["content"]