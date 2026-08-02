import hashlib
import hmac
import os
import secrets

import httpx
from dotenv import load_dotenv
from fastapi import Body, FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from pymongo import MongoClient

load_dotenv()

CASINO_BASE_URL = "https://api.aicvgdbi.win/api/casinoapi"
CASINO_TOKEN = os.environ["CASINO_TOKEN"]
CASINO_AGENT = os.environ["CASINO_AGENT"]
CURRENCY_CODE = "IDR"

mongo_client = MongoClient(os.environ["DATABASE_URL"])
db = mongo_client.get_default_database()

app = FastAPI(title="Dashboard Member")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


# ---------- password hashing (stdlib only, no extra dependency) ----------
def hash_password(password: str, salt: str = None) -> str:
    salt = salt or secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 100_000).hex()
    return f"{salt}${digest}"


def verify_password(password: str, stored: str) -> bool:
    salt, _, _ = stored.partition("$")
    return hmac.compare_digest(hash_password(password, salt), stored)


# ---------- casino operator API (calls we make outward) ----------
def call_casino(method: str, params: dict):
    body = {"method": method, "token": CASINO_TOKEN, "agentCode": CASINO_AGENT, **params}
    body = {key: value for key, value in body.items() if value not in ("", None)}
    try:
        response = httpx.post(CASINO_BASE_URL, json=body, timeout=15)
        response.raise_for_status()
    except httpx.HTTPError as error:
        raise HTTPException(status_code=502, detail=f"Casino API error: {error}") from error
    return response.json()


def get_live_balance(username: str) -> float:
    # Balance selalu ditanyakan langsung ke vendor (Transfer method) - kita
    # tidak menyimpan/mengelola balance sendiri di DB sama sekali.
    data = call_casino("GetUserInfo", {"userCode": username})
    users = data.get("users") or []
    if not users:
        return 0
    return users[0].get("balances", {}).get(CURRENCY_CODE, 0)


def serialize_user(username: str) -> dict:
    return {"username": username, "balance": get_live_balance(username)}


# ---------- member auth ----------
@app.post("/register")
def register(payload: dict = Body(...)):
    username = payload.get("username")
    password = payload.get("password")
    if not username or not password:
        raise HTTPException(status_code=400, detail="username dan password wajib diisi")
    if db.users.find_one({"username": username}):
        raise HTTPException(status_code=400, detail="username sudah dipakai")
    # Daftarkan juga ke vendor supaya GetGameUrl/GetUserInfo nanti bisa dipakai untuk user ini.
    data = call_casino("CreateUser", {"userCode": username})
    msg = str(data.get("msg", "")).lower()
    already_exists = "already exist" in msg or "duplicate" in msg
    if data.get("status") not in (0, 7) and not already_exists:
        raise HTTPException(status_code=400, detail=data.get("msg", "CreateUser failed"))
    db.users.insert_one({"username": username, "password": hash_password(password)})
    return serialize_user(username)


@app.post("/login")
def login(payload: dict = Body(...)):
    username = payload.get("username")
    password = payload.get("password", "")
    user = db.users.find_one({"username": username})
    if not user or not verify_password(password, user["password"]):
        raise HTTPException(status_code=401, detail="Username atau password salah")
    return serialize_user(username)


@app.get("/balance")
def get_balance(username: str = Query(...)):
    if not db.users.find_one({"username": username}):
        raise HTTPException(status_code=404, detail="User tidak ditemukan")
    return serialize_user(username)


# ---------- game browsing / launch ----------
@app.get("/vendors")
def get_vendors():
    return call_casino("GetVendors", {})


@app.get("/games")
def get_games(vendor: str = ""):
    return call_casino("GetVendorGames", {"vendorCode": vendor})


@app.post("/launch")
def launch_game(payload: dict = Body(...)):
    username = payload.get("username")
    vendor_code = payload.get("vendorCode")
    game_code = payload.get("gameCode")
    if not username or not vendor_code:
        raise HTTPException(status_code=400, detail="username dan vendorCode wajib diisi")
    if not db.users.find_one({"username": username}):
        raise HTTPException(status_code=404, detail="User tidak ditemukan")
    params = {"userCode": username, "vendorCode": vendor_code, "currencyCode": CURRENCY_CODE}
    if game_code:
        params["gameCode"] = game_code
    return call_casino("GetGameUrl", params)


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000)
