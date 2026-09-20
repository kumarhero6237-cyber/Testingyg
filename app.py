# Owner : @vaibhavff570
# Join  : @vaibhavapix, @vaibhavapisx

import asyncio
import time
import httpx
import json
import copy
import threading
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
JWT_PROVIDER_URL = "https://jwtob55.vercel.app/token"
JWT_UID          = "4732484418"
JWT_PASSWORD     = "BP_E7AKQ4YVHCB"

# Credits
OWNER = "@vaibhavff570"
JOIN  = "@vaibhavapix, @vaibhavapisx"

# Compatibility API key used by the previous website integration
API_KEY = "RAM-SAGAR"

REGIONS = {"IND"}

# India-only game server.
DEFAULT_SERVERS = {
    "IND": "https://client.ind.freefiremobile.com",
}

app = Flask(__name__)
CORS(app)

TOKENS = defaultdict(dict)
UID_MEMORY = {}

# Short response cache prevents repeated requests for the same UID from
# hammering the game endpoint.  It is intentionally short so data stays fresh.
RESULT_CACHE = {}
RESULT_CACHE_TTL = 60

# Free Fire can return 429 when requests arrive in bursts.  Keep game
# requests serialized and enforce a small gap between them.
GAME_REQUEST_LOCK = threading.Lock()
TOKEN_LOCK = threading.Lock()
LAST_GAME_REQUEST = 0.0
UPSTREAM_COOLDOWN_UNTIL = 0.0

# If the JWT provider itself is temporarily rate-limited, don't immediately
# hammer it again.  Lazy refresh + cooldown greatly reduces cold-start bursts.
TOKEN_RETRY_AFTER = 0.0

# Retry only a small number of times on transient 429/5xx responses.
LOOKUP_RETRIES = 1
MIN_GAME_REQUEST_GAP = 1.25

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
    params = {"uid": JWT_UID, "password": JWT_PASSWORD}
    async with httpx.AsyncClient(timeout=15) as cl:
        r = await cl.get(JWT_PROVIDER_URL, params=params)
        r.raise_for_status()
        text = r.text.strip()

        try:
            data = r.json()

            # This provider returns both `access_token` and the game JWT in
            # `token`. Prefer the game JWT; access_token is only a fallback.
            token = (
                data.get("token")
                or data.get("Tok")
                or data.get("jwt")
                or data.get("access_token")
            )
            if isinstance(token, str):
                token = token.strip()
            if not token and isinstance(data.get("data"), dict):
                nested = data["data"]
                token = (
                    nested.get("token")
                    or nested.get("Tok")
                    or nested.get("jwt")
                    or nested.get("access_token")
                )
                if isinstance(token, str):
                    token = token.strip()
                data = {**data, **nested}

            server = (
                data.get("addr")
                or data.get("serverUrl")
                or data.get("server")
                or data.get("server_url")
            )
            region = str(
                data.get("region")
                or data.get("lockRegion")
                or "IND"
            ).upper().strip()

            if token:
                return token, region, (server or "").rstrip("/") or None

        except Exception:
            pass

        # Fallback: plain JWT string
        if text.startswith("eyJ"):
            return text, "IND", None

        raise RuntimeError(f"Unexpected JWT provider response: {text[:200]}")


async def get_token(reg: str = "IND", force_refresh: bool = False):
    """
    Returns (token, region, server).
    Token is cached for 7 hours.  Refreshes are serialized so concurrent
    requests cannot create a JWT-provider burst.
    """
    global TOKEN_RETRY_AFTER

    info = TOKENS.get(reg)
    if not force_refresh and info and time.time() < info["expires"] - 60:
        return info["token"], info["region"], info["server"]

    # The lock is deliberately a normal threading lock because Flask may
    # execute requests in different threads and each route uses asyncio.run().
    with TOKEN_LOCK:
        info = TOKENS.get(reg)
        if not force_refresh and info and time.time() < info["expires"] - 60:
            return info["token"], info["region"], info["server"]

        now = time.time()
        if now < TOKEN_RETRY_AFTER:
            raise RuntimeError(
                f"JWT provider is temporarily rate-limited; retry in "
                f"{max(1, int(TOKEN_RETRY_AFTER - now))}s"
            )

        try:
            token, lock_region, server = await fetch_jwt_from_provider()
            TOKEN_RETRY_AFTER = 0.0
        except httpx.HTTPStatusError as e:
            if e.response is not None and e.response.status_code == 429:
                TOKEN_RETRY_AFTER = time.time() + 30
                raise RuntimeError("JWT provider returned 429 (rate limited)") from e
            raise

        if not server:
            server = DEFAULT_SERVERS.get(lock_region, DEFAULT_SERVERS["IND"])

        TOKENS[reg] = {
            "token": token if token.startswith("Bearer ") else f"Bearer {token}",
            "region": lock_region,
            "server": server.rstrip("/"),
            "expires": time.time() + 25200,
        }
        print(f"JWT ready -> {server} | region={lock_region}")
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
    """India-only lookup with caching and a global request throttle."""
    global LAST_GAME_REQUEST, UPSTREAM_COOLDOWN_UNTIL

    # This deployment is intentionally India-only.
    reg = "IND"
    cache_key = (uid, reg, ep)
    cached = RESULT_CACHE.get(cache_key)
    if cached and time.time() - cached["time"] < RESULT_CACHE_TTL:
        return copy.deepcopy(cached["data"])

    now = time.time()
    if now < UPSTREAM_COOLDOWN_UNTIL:
        raise RuntimeError(
            f"India game server is temporarily rate-limited; retry in "
            f"{max(1, int(UPSTREAM_COOLDOWN_UNTIL - now))}s"
        )

    payload = await _json_to_proto(
        json.dumps({"a": uid, "b": unk}),
        main_pb2.GetPlayerPersonalShow(),
    )
    data_enc = _enc(MAIN_KEY, MAIN_IV, payload)

    # Only one upstream request at a time. This also prevents concurrent
    # requests for different UIDs from producing a burst.
    with GAME_REQUEST_LOCK:
        now = time.time()
        if now < UPSTREAM_COOLDOWN_UNTIL:
            raise RuntimeError(
                f"India game server is temporarily rate-limited; retry in "
                f"{max(1, int(UPSTREAM_COOLDOWN_UNTIL - now))}s"
            )

        # Minimum spacing between all India game requests.
        wait = MIN_GAME_REQUEST_GAP - (now - LAST_GAME_REQUEST)
        if wait > 0:
            time.sleep(wait)

        token, lock_region, server = await get_token("IND")
        headers = {
            "User-Agent": USERAGENT,
            "Connection": "keep-alive",
            "Accept-Encoding": "deflate, gzip",
            "Content-Type": "application/octet-stream",
            "Authorization": token,
            "X-Unity-Version": UNITY_VERSION,
            "X-GA": "v1 1",
            "X-Ga-Sv": X_GA_SV,
            "ReleaseVersion": RELEASEVERSION,
        }

        try:
            async with httpx.AsyncClient(timeout=httpx.Timeout(15.0, connect=8.0)) as cl:
                res = await cl.post(
                    server + ep,
                    data=data_enc,
                    headers=headers,
                )
        finally:
            LAST_GAME_REQUEST = time.time()

        if res.status_code == 200:
            result = json.loads(
                json_format.MessageToJson(
                    _parse(res.content, AccountPersonalShow_pb2.AccountPersonalShowInfo)
                )
            )
            RESULT_CACHE[cache_key] = {
                "time": time.time(),
                "data": copy.deepcopy(result),
            }
            return result

        if res.status_code == 429:
            # Never retry a 429 immediately. Retrying a rate-limited request
            # is exactly what can extend the upstream limit window.
            retry_after = 30
            try:
                retry_after = max(10, int(float(res.headers.get("Retry-After", "30"))))
            except Exception:
                pass
            UPSTREAM_COOLDOWN_UNTIL = time.time() + min(retry_after, 120)
            raise RuntimeError(
                f"[IND] lookup status 429; upstream cooldown {min(retry_after, 120)}s"
            )

        if res.status_code in (401, 403):
            # Auth failures are the only game response that justifies dropping
            # the cached JWT. The next request will obtain a fresh one.
            TOKENS.pop("IND", None)
            raise RuntimeError(f"[IND] lookup status {res.status_code}")

        raise RuntimeError(f"[IND] lookup status {res.status_code}: {res.text[:200]}")

# ---------------- Routes ----------------

@app.route("/Bmw")
@app.route("/uc-info")
def _route_bmw():
    supplied_key = request.args.get("key") or request.headers.get("x-api-key")
    if supplied_key != API_KEY:
        return jsonify({"error": "Invalid or missing API key"}), 403
    uid    = (request.args.get("uid") or "").strip()
    region = (request.args.get("region") or "").strip().upper()

    # --- Validate UID ---
    if not uid:
        return jsonify({
            "error": "Please provide UID",
            "example": "/uc-info?uid=4455816879&key=RAM-SAGAR&region=IND",
            "credit": OWNER,
            "join": JOIN,
        }), 400

    if not uid.isdigit():
        return jsonify({"error": "UID must be a valid number", "credit": OWNER}), 400

    if len(uid) > 15:
        return jsonify({"error": "UID is too long", "credit": OWNER}), 400

    # --- India only ---
    if region and region != "IND":
        return jsonify({
            "error": "This API is India-only",
            "region": "IND",
            "credit": OWNER,
        }), 400

    try:
        data = asyncio.run(_lookup(uid, "7", "IND", "/GetPlayerPersonalShow"))
        UID_MEMORY[uid] = "IND"
        data["credit"] = OWNER
        data["join"]   = JOIN
        data["region"] = "IND"
        return json.dumps(data, indent=2, ensure_ascii=False), 200, {
            "Content-Type": "application/json; charset=utf-8"
        }
    except Exception as e:
        msg = str(e)
        status = 429 if "429" in msg or "rate-limited" in msg.lower() or "rate limited" in msg.lower() else 404
        return jsonify({
            "error": f"Failed to fetch UID {uid} in region IND",
            "details": msg,
            "credit": OWNER,
        }), status

    # All requests are handled as IND; there is no multi-region scan.


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
        "api": "Free Fire Info API (India Only)",
        "version": RELEASEVERSION,
        "credit": OWNER,
        "join": JOIN,
        "endpoints": {
            "/uc-info?uid=<UID>&key=RAM-SAGAR": "Player info (India only)",
            "/Bmw?uid=<UID>&key=RAM-SAGAR":     "Player info (India only; alias)",
            "/regions":                       "India region only",
            "/refresh":                       "Refresh JWT from provider",
            "/health":                        "Health check",
        },
        "valid_regions": ["IND"],
    })


# ---------------- Startup ----------------

async def _startup():
    # Do not fetch JWT during every server cold start.  Vercel/serverless
    # instances can cold-start frequently, and doing so can itself trigger
    # the JWT provider's rate limit.  Token is fetched lazily on first lookup.
    return

asyncio.run(_startup())

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False, threaded=True)