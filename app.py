# Owner : @vaibhavff570
# Join  : @vaibhavapix, @vaibhavapisx

import asyncio
import time
import httpx
import json
from collections import defaultdict
from flask import Flask, request, jsonify
from flask_cors import CORS
from proto import main_pb2, AccountPersonalShow_pb2
from google.protobuf import json_format
from google.protobuf.message import Message
from Crypto.Cipher import AES

# ---------------- Config ----------------

MAIN_KEY = bytes([89, 103, 38, 116, 99, 37, 68, 69, 117, 104, 54, 37, 90, 99, 94, 56])
MAIN_IV  = bytes([54, 111, 121, 90, 68, 114, 50, 50, 69, 51, 121, 99, 104, 106, 77, 37])

RELEASEVERSION = "OB55"
USERAGENT      = "UnityPlayer/2018.4.12f1 (UnityWebRequest/1.0, libcurl/8.5.0-DEV)"
UNITY_VERSION  = "2018.4.12f1"
X_GA_SV        = "1789534056"

# External JWT provider
JWT_PROVIDER_URL = "http://148.113.25.200:6293/Tok"
JWT_UID          = "7866781860"
JWT_PASSWORD     = "E973FDA3DDEAC4625468E0222249776C27112CA8C1040589651BEF0854E5DC17"

# Credits
OWNER = "@vaibhavff570"
JOIN  = "@vaibhavapix, @vaibhavapisx"

REGIONS = {
    "IND", "BR", "US", "SAC", "NA", "SG", "RU", "ID",
    "TW", "VN", "TH", "ME", "PK", "CIS", "BD", "EUROPE",
}

# Fallback game servers (only used if provider doesn't return `addr`)
DEFAULT_SERVERS = {
    "IND":    "https://client.ind.freefiremobile.com",
    "BR":     "https://client.br.freefiremobile.com",
    "US":     "https://client.us.freefiremobile.com",
    "SAC":    "https://client.sac.freefiremobile.com",
    "NA":     "https://client.na.freefiremobile.com",
    "SG":     "https://client.sg.freefiremobile.com",
    "RU":     "https://client.ru.freefiremobile.com",
    "ID":     "https://client.id.freefiremobile.com",
    "TW":     "https://client.tw.freefiremobile.com",
    "VN":     "https://client.vn.freefiremobile.com",
    "TH":     "https://client.th.freefiremobile.com",
    "ME":     "https://client.me.freefiremobile.com",
    "PK":     "https://client.pk.freefiremobile.com",
    "CIS":    "https://client.cis.freefiremobile.com",
    "BD":     "https://client.bd.freefiremobile.com",
    "EUROPE": "https://client.europe.freefiremobile.com",
}

app = Flask(__name__)
CORS(app)

TOKENS = defaultdict(dict)
UID_MEMORY = {}

# ---------------- Crypto helpers ----------------

def _pad(d: bytes) -> bytes:
    l = AES.block_size - (len(d) % AES.block_size)
    return d + bytes([l] * l)

def _enc(k: bytes, i: bytes, d: bytes) -> bytes:
    return AES.new(k, AES.MODE_CBC, i).encrypt(_pad(d))

def _parse(b: bytes, mt):
    m = mt()
    m.ParseFromString(b)
    return m

async def _json_to_proto(jt: str, pt: Message) -> bytes:
    json_format.ParseDict(json.loads(jt), pt)
    return pt.SerializeToString()

# ---------------- External JWT fetch ----------------

async def fetch_jwt_from_provider():
    """
    Query the external JWT provider.
    Handles fields: Tok / token / jwt / access_token
    Server:         addr / serverUrl / server / server_url
    """
    params = {"uid": JWT_UID, "pw": JWT_PASSWORD}
    async with httpx.AsyncClient(timeout=15) as cl:
        r = await cl.get(JWT_PROVIDER_URL, params=params)
        r.raise_for_status()
        text = r.text.strip()

        try:
            data = r.json()

            token = (
                data.get("Tok")
                or data.get("token")
                or data.get("jwt")
                or data.get("access_token")
            )
            server = (
                data.get("addr")
                or data.get("serverUrl")
                or data.get("server")
                or data.get("server_url")
            )
            region = (
                data.get("region")
                or data.get("lockRegion")
                or "IND"
            ).upper()

            if token:
                return token, region, (server or "").rstrip("/") or None

        except Exception:
            pass

        # Fallback: plain JWT string
        if text.startswith("eyJ"):
            return text, "IND", None

        raise RuntimeError(f"Unexpected JWT provider response: {text[:200]}")


async def get_token(reg: str = "IND"):
    """
    Returns (token, region, server).
    Cached for 7 hours.
    """
    info = TOKENS.get(reg)
    if info and time.time() < info["expires"] - 60:
        return info["token"], info["region"], info["server"]

    token, lock_region, server = await fetch_jwt_from_provider()

    if not server:
        server = DEFAULT_SERVERS.get(lock_region, DEFAULT_SERVERS["IND"])

    TOKENS[reg] = {
        "token":   token if token.startswith("Bearer ") else f"Bearer {token}",
        "region":  lock_region,
        "server":  server.rstrip("/"),
        "expires": time.time() + 25200,
    }
    print(f"✅ [{reg}] JWT ready -> {server} | region={lock_region}")
    return TOKENS[reg]["token"], TOKENS[reg]["region"], TOKENS[reg]["server"]


async def _refresh_all():
    try:
        # Only IND here since provider is India-only
        await get_token("IND")
    except Exception as e:
        print(f"⚠️ JWT refresh failed: {e}")


async def _refresh_loop():
    while True:
        await asyncio.sleep(25200)   # 7 hours
        await _refresh_all()


# ---------------- Player lookup ----------------

async def _lookup(uid: str, unk: str, reg: str, ep: str):
    payload = await _json_to_proto(
        json.dumps({"a": uid, "b": unk}),
        main_pb2.GetPlayerPersonalShow(),
    )
    data_enc = _enc(MAIN_KEY, MAIN_IV, payload)
    token, lock, server = await get_token(reg)

    headers = {
        "User-Agent": USERAGENT,
        "Connection": "keep-alive",
        "Accept-Encoding": "deflate, gzip",
        "Content-Type": "application/octet-stream",
        "Expect": "100-continue",
        "Authorization": token,
        "X-Unity-Version": UNITY_VERSION,
        "X-GA": "v1 1",
        "X-Ga-Sv": X_GA_SV,
        "ReleaseVersion": RELEASEVERSION,
    }

    async with httpx.AsyncClient(timeout=15) as cl:
        res = await cl.post(server + ep, data=data_enc, headers=headers)
        if res.status_code != 200:
            raise RuntimeError(f"[{reg}] lookup status {res.status_code}")
        return json.loads(
            json_format.MessageToJson(
                _parse(res.content, AccountPersonalShow_pb2.AccountPersonalShowInfo)
            )
        )


# ---------------- Routes ----------------

@app.route("/Bmw")
def _route_bmw():
    uid    = (request.args.get("uid") or "").strip()
    region = (request.args.get("region") or "").strip().upper()

    # --- Validate UID ---
    if not uid:
        return jsonify({
            "error": "Please provide UID",
            "example": "/Bmw?uid=4455816879&region=IND",
            "credit": OWNER,
            "join": JOIN,
        }), 400

    if not uid.isdigit():
        return jsonify({"error": "UID must be a valid number", "credit": OWNER}), 400

    if len(uid) > 15:
        return jsonify({"error": "UID is too long", "credit": OWNER}), 400

    # --- If region provided explicitly ---
    if region:
        if region not in REGIONS:
            return jsonify({
                "error": f"Invalid region: {region}",
                "valid_regions": sorted(REGIONS),
                "credit": OWNER,
            }), 400

        try:
            data = asyncio.run(_lookup(uid, "7", region, "/GetPlayerPersonalShow"))
            UID_MEMORY[uid] = region
            data["credit"] = OWNER
            data["join"]   = JOIN
            data["region"] = region
            return json.dumps(data, indent=2, ensure_ascii=False), 200, {
                "Content-Type": "application/json; charset=utf-8"
            }
        except Exception as e:
            return jsonify({
                "error": f"Failed to fetch UID {uid} in region {region}",
                "details": str(e),
                "credit": OWNER,
            }), 404

    # --- Region not provided: try cache first ---
    if uid in UID_MEMORY:
        try:
            reg  = UID_MEMORY[uid]
            data = asyncio.run(_lookup(uid, "7", reg, "/GetPlayerPersonalShow"))
            data["credit"] = OWNER
            data["join"]   = JOIN
            data["region"] = reg
            return json.dumps(data, indent=2, ensure_ascii=False), 200, {
                "Content-Type": "application/json; charset=utf-8"
            }
        except Exception:
            pass

    # --- Region not provided: auto-scan all ---
    errors = {}
    for reg in REGIONS:
        try:
            data = asyncio.run(_lookup(uid, "7", reg, "/GetPlayerPersonalShow"))
            UID_MEMORY[uid] = reg
            data["credit"] = OWNER
            data["join"]   = JOIN
            data["region"] = reg
            return json.dumps(data, indent=2, ensure_ascii=False), 200, {
                "Content-Type": "application/json; charset=utf-8"
            }
        except Exception as e:
            errors[reg] = str(e)
            continue

    return jsonify({
        "error": "UID not found in any region",
        "hint": "Try specifying region explicitly, e.g. /Bmw?uid=...&region=IND",
        "credit": OWNER,
        "details": errors,
    }), 404


@app.route("/regions")
def _route_regions():
    """List all valid region codes."""
    return jsonify({
        "regions": sorted(REGIONS),
        "credit": OWNER,
        "join": JOIN,
    })


@app.route("/refresh", methods=["GET", "POST"])
def _route_refresh():
    try:
        asyncio.run(_refresh_all())
        return jsonify({"message": "JWT token refreshed.", "credit": OWNER}), 200
    except Exception as e:
        return jsonify({"error": f"Refresh failed: {e}", "credit": OWNER}), 500


@app.route("/health")
def _route_health():
    ready = {
        reg: bool(TOKENS.get(reg) and time.time() < TOKENS[reg]["expires"])
        for reg in REGIONS
    }
    return jsonify({
        "status": "ok",
        "tokens_ready": ready,
        "credit": OWNER,
        "join": JOIN,
    })


@app.route("/")
def _route_home():
    return jsonify({
        "api": "Free Fire Info API (External JWT + Region Select)",
        "version": RELEASEVERSION,
        "credit": OWNER,
        "join": JOIN,
        "endpoints": {
            "/Bmw?uid=<UID>&region=<REGION>": "Player info with explicit region",
            "/Bmw?uid=<UID>":                 "Player info with auto region scan",
            "/regions":                       "List all valid region codes",
            "/refresh":                       "Refresh JWT from provider",
            "/health":                        "Health check",
        },
        "valid_regions": sorted(REGIONS),
    })


# ---------------- Startup ----------------

async def _startup():
    await _refresh_all()
    asyncio.create_task(_refresh_loop())

asyncio.run(_startup())

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False, threaded=True)
