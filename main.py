import hashlib
import hmac
import os
import secrets

import httpx
from dotenv import load_dotenv
from fastapi import Body, FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from pymongo import MongoClient, ReturnDocument

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


def serialize_user(doc: dict) -> dict:
    return {"username": doc["username"], "balance": doc.get("balance", 0)}


def serialize_log(doc: dict) -> dict:
    doc["_id"] = str(doc["_id"])
    return doc


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


# ---------- member auth ----------
@app.post("/register")
def register(payload: dict = Body(...)):
    username = payload.get("username")
    password = payload.get("password")
    if not username or not password:
        raise HTTPException(status_code=400, detail="username dan password wajib diisi")
    if db.users.find_one({"username": username}):
        raise HTTPException(status_code=400, detail="username sudah dipakai")
    # Daftarkan juga ke vendor supaya GetGameUrl nanti bisa launch untuk user ini.
    data = call_casino("CreateUser", {"userCode": username})
    msg = str(data.get("msg", "")).lower()
    already_exists = "already exist" in msg or "duplicate" in msg
    if data.get("status") not in (0, 7) and not already_exists:
        raise HTTPException(status_code=400, detail=data.get("msg", "CreateUser failed"))
    db.users.insert_one({"username": username, "password": hash_password(password), "balance": 0})
    return serialize_user(db.users.find_one({"username": username}))


@app.post("/login")
def login(payload: dict = Body(...)):
    username = payload.get("username")
    password = payload.get("password", "")
    user = db.users.find_one({"username": username})
    if not user or not verify_password(password, user["password"]):
        raise HTTPException(status_code=401, detail="Username atau password salah")
    return serialize_user(user)


@app.get("/balance")
def get_balance(username: str = Query(...)):
    user = db.users.find_one({"username": username})
    if not user:
        raise HTTPException(status_code=404, detail="User tidak ditemukan")
    return serialize_user(user)


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


# ---------- Wallet Callback API: dipanggil OLEH vendor saat user bermain ----------
# Endpoint ini yang didaftarkan di backoffice vendor sebagai "site endpoint".
# Setiap bet/win/cancel lewat sini secara real-time - inilah yang dites di project ini.
@app.post("/wallet-callback")
def wallet_callback(payload: dict = Body(...)):
    method = payload.get("method")

    if payload.get("token") != CASINO_TOKEN:
        return {"status": 3, "msg": "INVALID_AGENT"}

    if method == "GetBalance":
        user = db.users.find_one({"username": payload.get("userCode")})
        response = (
            {"status": 5, "msg": "INVALID_USER"}
            if not user
            else {"status": 0, "msg": "SUCCESS", "balance": user.get("balance", 0)}
        )
        db.wallet_log.insert_one({"method": method, "request": payload, "response": response})
        return response

    if method == "ChangeBalance":
        amount = payload.get("amount", 0)
        updated = db.users.find_one_and_update(
            {"username": payload.get("userCode")},
            {"$inc": {"balance": amount}},
            return_document=ReturnDocument.AFTER,
        )
        response = (
            {"status": 5, "msg": "INVALID_USER"}
            if not updated
            else {"status": 0, "msg": "SUCCESS", "balance": updated.get("balance", 0)}
        )
        db.wallet_log.insert_one({"method": method, "request": payload, "response": response})
        return response

    if method == "UpdateDetail":
        response = {"status": 0, "msg": "SUCCESS"}
        db.wallet_log.insert_one({"method": method, "request": payload, "response": response})
        return response

    return {"status": 2, "msg": "INVALID_ACTION"}


@app.get("/wallet-log")
def get_wallet_log(limit: int = 50):
    return [serialize_log(doc) for doc in db.wallet_log.find().sort("_id", -1).limit(limit)]


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000)
