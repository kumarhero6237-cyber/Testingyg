"""
Free Fire India-only player information API.

Important deployment note:
- This app keeps its token/cache warm only while the Python process is alive.
- Vercel Python functions are serverless and may be frozen/restarted, so no Python
  background thread can guarantee "always on" there.
- For true always-on behaviour, run this app as a persistent Gunicorn service
  (VPS / paid always-on container / similar).
"""

import asyncio
import base64
import json
import os
import threading
import time
from functools import wraps
from typing import Tuple

import httpx
from flask import Flask, jsonify, request
from flask_cors import CORS
from google.protobuf import json_format, message
from Crypto.Cipher import AES

#  PART 1 — protobuf modules
# ============================================================
# Keep the project's existing generated protobuf module.  This avoids making
# the Vercel runtime depend on a specific protobuf compiler/runtime version.
from proto import FreeFire_pb2, main_pb2, AccountPersonalShow_pb2

# ============================================================

# ---------------- Config ----------------

MAIN_KEY = base64.b64decode("WWcmdGMlREV1aDYlWmNeOA==")
MAIN_IV = base64.b64decode("Nm95WkRyMjJFM3ljaGpNJQ==")

RELEASEVERSION = "OB55"
USERAGENT = "UnityPlayer/2018.4.12f1 (UnityWebRequest/1.0, libcurl/8.5.0-DEV)"

# Hard India-only policy.
INDIA_REGIONS = {"IND", "INDIA", "IN"}

# Keep your existing key; preferably move it to an environment variable in production.
API_KEY = "RAM-SAGAR"

TOKEN_REFRESH_SAFETY = 300          # refresh 5 minutes before expiry
TOKEN_FALLBACK_TTL = 25200          # 7 hours if server does not provide TTL
REQUEST_TIMEOUT = httpx.Timeout(8.0, connect=3.0)
MAX_CONNECTIONS = 50
MAX_KEEPALIVE = 20

app = Flask(__name__)
CORS(app)

# ---------------- Persistent async worker ----------------

_loop = None
_loop_ready = threading.Event()
_loop_lock = threading.Lock()
_http_client = None
_token_lock = None
_cached_token = None


def _start_async_worker():
    global _loop

    with _loop_lock:
        if _loop is not None:
            return
        _loop = asyncio.new_event_loop()

    def runner():
        asyncio.set_event_loop(_loop)
        _loop.run_until_complete(_async_startup())
        _loop_ready.set()
        _loop.run_forever()

    threading.Thread(target=runner, name="ff-api-async", daemon=True).start()


async def _async_startup():
    global _http_client, _token_lock
    _http_client = httpx.AsyncClient(
        timeout=REQUEST_TIMEOUT,
        limits=httpx.Limits(
            max_connections=MAX_CONNECTIONS,
            max_keepalive_connections=MAX_KEEPALIVE,
            keepalive_expiry=30.0,
        ),
        http2=False,
        headers={
            "User-Agent": USERAGENT,
            "Connection": "keep-alive",
            "Accept-Encoding": "gzip",
        },
    )
    _token_lock = asyncio.Lock()
    # Warm token once, but do not make process startup fail if Garena is temporarily slow.
    try:
        await create_jwt()
    except Exception as exc:
        print(f"⚠️ Initial India token warm-up failed: {exc}")

    asyncio.create_task(refresh_tokens_periodically())


def _run(coro):
    """Run a coroutine on the single persistent event loop."""
    _start_async_worker()
    _loop_ready.wait(timeout=10)
    if _loop is None or not _loop.is_running():
        raise RuntimeError("Async worker is not running")
    future = asyncio.run_coroutine_threadsafe(coro, _loop)
    return future.result(timeout=15)


# ---------------- API key ----------------

def require_api_key(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        key = request.args.get("key") or request.headers.get("x-api-key")
        if key != API_KEY:
            return jsonify({"error": "Invalid or missing API key"}), 403
        return fn(*args, **kwargs)
    return wrapper


# ---------------- Crypto / protobuf ----------------

def pad(data: bytes) -> bytes:
    padding_length = AES.block_size - (len(data) % AES.block_size)
    return data + bytes([padding_length]) * padding_length


def aes_cbc_encrypt(key: bytes, iv: bytes, plaintext: bytes) -> bytes:
    return AES.new(key, AES.MODE_CBC, iv).encrypt(pad(plaintext))


def decode_protobuf(encoded_data: bytes, message_type: message.Message):
    instance = message_type()
    instance.ParseFromString(encoded_data)
    return instance


async def json_to_proto(json_data: str, proto_message: message.Message) -> bytes:
    json_format.ParseDict(json.loads(json_data), proto_message)
    return proto_message.SerializeToString()



# ---------------- India guest account pool ----------------

_ACCOUNTS_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "accounts.json")
_accounts_cache = None
_accounts_mtime = None


def _load_india_accounts():
    """Load all active India accounts from accounts.json in file order."""
    global _accounts_cache, _accounts_mtime

    try:
        mtime = os.path.getmtime(_ACCOUNTS_PATH)
        if _accounts_cache is not None and _accounts_mtime == mtime:
            return _accounts_cache

        with open(_ACCOUNTS_PATH, "r", encoding="utf-8") as fh:
            raw = json.load(fh)

        if isinstance(raw, dict):
            raw = raw.get("accounts", [])

        if not isinstance(raw, list):
            raise ValueError("accounts.json must contain a JSON array or an accounts[] object")

        accounts = []
        for item in raw:
            if not isinstance(item, dict):
                continue
            if item.get("activated", True) is False:
                continue
            if str(item.get("region", "IND")).upper() not in INDIA_REGIONS:
                continue
            if not (item.get("uid") or item.get("game_uid")):
                continue
            accounts.append(item)

        if not accounts:
            raise ValueError("No active India accounts found in accounts.json")

        _accounts_cache = accounts
        _accounts_mtime = mtime
        print(f"✅ Loaded {len(accounts)} India accounts from accounts.json")
        return accounts

    except FileNotFoundError:
        raise RuntimeError("accounts.json not found beside app.py")
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"Invalid accounts.json: {exc}")


def get_india_accounts():
    return _load_india_accounts()


def get_india_account() -> str:
    """Backward-compatible first-account credential string."""
    account = get_india_accounts()[0]
    uid = account.get("uid") or account.get("game_uid")
    password = account.get("password", "")
    return f"uid={uid}&password={password}"

# ---------------- Token generation ----------------

async def get_access_token(account: str):
    url = "https://ffmconnect.live.gop.garenanow.com/oauth/guest/token/grant"
    payload = (
        account
        + "&response_type=token&client_type=2"
        + "&client_secret=2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3"
        + "&client_id=100067"
    )
    headers = {
        "User-Agent": USERAGENT,
        "Connection": "keep-alive",
        "Accept-Encoding": "gzip",
        "Content-Type": "application/x-www-form-urlencoded",
    }

    resp = await _http_client.post(url, data=payload, headers=headers)
    resp.raise_for_status()
    data = resp.json()
    return data.get("access_token", "0"), data.get("open_id", "0")


async def create_jwt(account_override=None):
    """
    Create the India game token for one account.

    accounts.json is the source of the account pool. If an account already
    contains access_token/open_id, those stored values are tried first.
    If they are missing or rejected, UID/password are used to obtain fresh
    credentials. The account's stored jwt is intentionally not trusted as a
    complete session because accounts.json does not contain the matching
    server_url; a game JWT alone is not sufficient to know which game server
    endpoint to call.
    """
    global _cached_token

    async with _token_lock:
        if account_override is None:
            account = get_india_accounts()[0]
        else:
            account = account_override

        token_val = str(account.get("access_token") or "").strip()
        open_id = str(account.get("open_id") or "").strip()

        # Prefer the access_token/open_id already stored in accounts.json.
        # If those credentials are absent/invalid, fall back to UID/password.
        if not token_val or token_val == "0" or not open_id or open_id == "0":
            uid = account.get("uid") or account.get("game_uid")
            password = account.get("password")
            if not uid or not password:
                raise RuntimeError("Account is missing uid/game_uid or password")
            credential_string = f"uid={uid}&password={password}"
            token_val, open_id = await get_access_token(credential_string)

        if not token_val or token_val == "0" or not open_id or open_id == "0":
            raise RuntimeError("India guest token was not returned")

        body = json.dumps({
            "open_id": open_id,
            "open_id_type": "4",
            "login_token": token_val,
            "orign_platform_type": "4",
        })

        proto_bytes = await json_to_proto(body, FreeFire_pb2.LoginReq())
        payload = aes_cbc_encrypt(MAIN_KEY, MAIN_IV, proto_bytes)

        url = "https://loginbp.ppmainecoonghj.com/MajorLogin"
        headers = {
            "User-Agent": USERAGENT,
            "Accept": "*/*",
            "Accept-Encoding": "deflate, gzip",
            "X-Ga-Sv": "1789534056",
            "Authorization": "Bearer",
            "X-Ga": "v1 1",
            "Releaseversion": RELEASEVERSION,
            "Content-Type": "application/x-www-form-urlencoded",
            "X-Unity-Version": "2018.4.12f1",
            "PlAy_VeR": "1.132.1",
            "Ob_VeR": RELEASEVERSION,
        }

        resp = await _http_client.post(url, data=payload, headers=headers)
        if resp.status_code != 200:
            raise RuntimeError(f"MajorLogin status {resp.status_code}")

        # OB55-compatible response parsing.
        # The OB55 response can contain several protobuf/framed sections. A
        # naive ParseFromString() may successfully parse an unrelated section
        # (for example account_id) while silently missing token/server fields.
        # Therefore, keep scanning candidates until we find the candidate that
        # actually contains the game token and server URL.
        def _try_login(raw):
            try:
                candidate = FreeFire_pb2.LoginRes()
                candidate.ParseFromString(raw)
                return candidate
            except Exception:
                return None

        def _flatten_values(value, prefix=""):
            if isinstance(value, dict):
                for k, v in value.items():
                    yield from _flatten_values(v, f"{prefix}.{k}" if prefix else k)
            elif isinstance(value, list):
                for i, v in enumerate(value):
                    yield from _flatten_values(v, f"{prefix}[{i}]")
            else:
                yield prefix, value

        def _candidate_score(candidate):
            try:
                obj = json.loads(
                    json_format.MessageToJson(
                        candidate,
                        preserving_proto_field_name=True,
                    )
                )
            except Exception:
                return 0

            score = 0
            for key, value in _flatten_values(obj):
                k = key.lower()
                s = str(value or "")
                if not s:
                    continue
                if k.endswith("token") or k.endswith(".gametoken") or k == "token":
                    score += 10
                if "serverurl" in k or k.endswith(".server_url"):
                    score += 10
                if s.startswith("eyj") and s.count(".") >= 2:
                    score += 12
                if s.startswith("http://") or s.startswith("https://"):
                    score += 6
                if "lockregion" in k or k.endswith(".region"):
                    score += 2
            return score

        raw = resp.content
        candidates = []

        # Whole response.
        candidate = _try_login(raw)
        if candidate is not None:
            candidates.append(candidate)

        # Try protobuf boundaries. Do NOT stop at the first parseable message:
        # protobuf parsing is permissive and an unrelated embedded section can
        # parse successfully.
        idx = 0
        seen_offsets = set()
        while True:
            idx = raw.find(b"\x08", idx)
            if idx == -1:
                break
            if idx not in seen_offsets:
                seen_offsets.add(idx)
                candidate = _try_login(raw[idx:])
                if candidate is not None:
                    candidates.append(candidate)
            idx += 1

        decoded = None
        best_score = -1
        for candidate in candidates:
            score = _candidate_score(candidate)
            if score > best_score:
                best_score = score
                decoded = candidate

        if decoded is None or best_score <= 0:
            # Last-resort diagnostic only: report safe structural information,
            # never credentials or bearer tokens.
            raise RuntimeError(
                f"Could not locate OB55 LoginRes token/server in MajorLogin response "
                f"(bytes={len(raw)}, candidates={len(candidates)})"
            )

        # Protobuf field naming can differ between generated OB55 schemas.
        # Read both JSON names and direct protobuf attributes.
        msg = json.loads(
            json_format.MessageToJson(
                decoded,
                preserving_proto_field_name=True,
            )
        )

        def _first_value(message, mapping, *names):
            wanted = {n.lower().replace("-", "_") for n in names}

            # Direct top-level lookup first.
            for name in names:
                for candidate_name in (name, name.replace("_", "")):
                    value = mapping.get(candidate_name)
                    if value not in (None, "", 0):
                        return value
                    try:
                        value = getattr(message, candidate_name)
                        if value not in (None, "", 0):
                            return value
                    except Exception:
                        pass

            # Then search nested protobuf objects/dicts.
            for key, value in _flatten_values(mapping):
                normalized = key.split(".")[-1].replace("_", "").lower()
                if normalized in {n.replace("_", "") for n in wanted}:
                    if value not in (None, "", 0):
                        return value
            return ""

        lock_region = str(
            _first_value(
                decoded,
                msg,
                "lockRegion",
                "lock_region",
                "region",
                "lockregion",
            )
        ).upper().strip()

        server_url = _first_value(decoded, msg, "serverUrl", "server_url")
        game_token = _first_value(decoded, msg, "token", "gameToken", "game_token")

        if not server_url or not game_token:
            safe_keys = sorted(str(k) for k in msg.keys())
            raise RuntimeError(
                "MajorLogin parsed but OB55 token/server fields are missing "
                f"(region={lock_region or 'unknown'}, fields={safe_keys})"
            )

        # Some OB55 responses may not expose lockRegion in this protobuf.
        # In that case, rely on the returned game server host only if it
        # clearly identifies an India server; otherwise reject safely.
        if lock_region not in INDIA_REGIONS:
            server_host = str(server_url).lower()
            india_host_markers = (".ind.", "ind.", "india", "in-gp", "ind-gp")
            if not any(marker in server_host for marker in india_host_markers):
                raise RuntimeError(
                    f"India token returned unexpected region: {lock_region or 'unknown'}"
                )
            lock_region = "IND"
        if not server_url or not game_token:
            raise RuntimeError("MajorLogin did not return token/server")

        try:
            ttl = int(msg.get("ttl", TOKEN_FALLBACK_TTL))
        except (TypeError, ValueError):
            ttl = TOKEN_FALLBACK_TTL

        # Never trust an extremely long server TTL.
        ttl = max(600, min(ttl, TOKEN_FALLBACK_TTL))

        _cached_token = {
            "token": f"Bearer {game_token}",
            "region": lock_region,
            "server_url": server_url.rstrip("/"),
            "expires_at": time.time() + ttl,
        }

        print(f"✅ INDIA TOKEN READY -> {server_url} | TTL={ttl}s")
        return True


async def refresh_tokens_periodically():
    while True:
        try:
            await asyncio.sleep(60)
            if not _cached_token or time.time() >= _cached_token["expires_at"] - TOKEN_REFRESH_SAFETY:
                try:
                    await create_jwt()
                except Exception as exc:
                    print(f"⚠️ India token refresh failed: {exc}")
        except asyncio.CancelledError:
            return
        except Exception as exc:
            print(f"⚠️ Token refresh loop error: {exc}")
            await asyncio.sleep(10)


async def get_token_info() -> Tuple[str, str, str]:
    if _cached_token and time.time() < _cached_token["expires_at"] - 30:
        return (
            _cached_token["token"],
            _cached_token["region"],
            _cached_token["server_url"],
        )

    await create_jwt()
    if not _cached_token:
        raise RuntimeError("Failed to generate India token")

    return (
        _cached_token["token"],
        _cached_token["region"],
        _cached_token["server_url"],
    )


# ---------------- Player lookup ----------------


async def GetAccountInformation(uid, unk):
    payload = await json_to_proto(
        json.dumps({"a": uid, "b": unk}),
        main_pb2.GetPlayerPersonalShow(),
    )
    data_enc = aes_cbc_encrypt(MAIN_KEY, MAIN_IV, payload)

    accounts = get_india_accounts()
    failures = []

    # Account 1 -> Account 2 -> ... -> Account N.
    # A complete fetch failure moves to the next account.
    for index, account in enumerate(accounts, start=1):
        account_uid = str(account.get("uid") or account.get("game_uid") or "?")

        try:
            # Generate/use the token for THIS account only.
            await create_jwt(account)

            token, lock_region, server = await get_token_info()

            if lock_region.upper() not in INDIA_REGIONS:
                raise RuntimeError("Account token is not India region")

            headers = {
                "User-Agent": USERAGENT,
                "Connection": "keep-alive",
                "Accept-Encoding": "gzip",
                "Content-Type": "application/octet-stream",
                "Expect": "100-continue",
                "Authorization": token,
                "X-Unity-Version": "2018.4.12f1",
                "X-GA": "v1 1",
                "X-Ga-Sv": "1789534056",
                "PlAy_VeR": "1.132.1",
                "Ob_VeR": RELEASEVERSION,
                "ReleaseVersion": RELEASEVERSION,
            }

            endpoint = server.rstrip("/") + "/GetPlayerPersonalShow"

            # One refresh/retry for the SAME account on 401.
            for attempt in range(2):
                resp = await _http_client.post(
                    endpoint,
                    data=data_enc,
                    headers=headers,
                )

                if resp.status_code == 401 and attempt == 0:
                    await create_jwt(account)
                    token, _, server = await get_token_info()
                    headers["Authorization"] = token
                    endpoint = server.rstrip("/") + "/GetPlayerPersonalShow"
                    continue

                if resp.status_code != 200:
                    raise RuntimeError(
                        f"Game server returned status {resp.status_code}"
                    )

                content_type = resp.headers.get("content-type", "").lower()
                if "application/octet-stream" not in content_type:
                    raise RuntimeError(
                        f"Unexpected content type: {content_type}"
                    )

                decoded = decode_protobuf(
                    resp.content,
                    AccountPersonalShow_pb2.AccountPersonalShowInfo,
                )
                data = json.loads(json_format.MessageToJson(decoded))

                basic = data.get("basicInfo") or data.get("basic_info") or {}
                player_region = str(
                    basic.get("region", "")
                ).upper().strip()

                if player_region not in INDIA_REGIONS:
                    raise ValueError(
                        "UID is not an India-region Free Fire account"
                    )

                print(
                    f"✅ UID {uid} fetched successfully using account "
                    f"{index}/{len(accounts)} ({account_uid})"
                )
                return data

            raise RuntimeError("Player lookup failed")

        except ValueError:
            # A real non-India UID is a valid final result, not an account
            # authentication failure. Do not waste all accounts on it.
            raise

        except Exception as exc:
            failures.append(
                f"account {index} ({account_uid}): {type(exc).__name__}: {exc}"
            )
            print(f"⚠️ {failures[-1]}")
            continue

    # All accounts failed.
    raise RuntimeError(
        "All India accounts failed to fetch player information. "
        + " | ".join(failures[-10:])
    )


# Start the persistent worker as soon as this module is imported.
_start_async_worker()


# ---------------- Routes ----------------

@app.route("/uc-info")
@require_api_key
def get_account_info():
    uid = request.args.get("uid", "").strip()

    if not uid:
        return jsonify({
            "error": "Please provide UID",
            "example": "/uc-info?uid=123456789&key=RAM-SAGAR",
        }), 400

    if not uid.isdigit():
        return jsonify({"error": "UID must be a valid number"}), 400

    if len(uid) > 15:
        return jsonify({"error": "UID is too long"}), 400

    try:
        data = _run(GetAccountInformation(uid, "7"))
        return jsonify(data)
    except ValueError as exc:
        return jsonify({
            "error": "UID is not available in the India region",
            "message": str(exc),
        }), 404
    except Exception as exc:
        print(f"❌ ERROR fetching UID {uid}: {exc}")
        return jsonify({
            "error": "Failed to fetch India player info",
            "details": str(exc),
        }), 502


@app.route("/ref-token", methods=["GET", "POST"])
@require_api_key
def refresh_tokens_endpoint():
    try:
        _run(create_jwt())
        return jsonify({
            "message": "India token refreshed successfully",
            "region": "IND",
        }), 200
    except Exception as exc:
        return jsonify({"error": str(exc)}), 502


@app.route("/health")
def health():
    token_ready = bool(
        _cached_token and time.time() < _cached_token["expires_at"]
    )
    return jsonify({
        "status": "ok",
        "region": "IND",
        "token_ready": token_ready,
        "always_on_note": "Requires a persistent Python process; serverless platforms may sleep.",
    })


@app.route("/")
def home():
    return jsonify({
        "api": "UC India Only Free Fire Info API",
        "version": RELEASEVERSION,
        "region": "IND ONLY",
        "endpoints": {
            "/uc-info?uid=<UID>&key=RAM-SAGAR": "India player info only",
            "/ref-token?key=RAM-SAGAR": "Refresh India auth token",
            "/health": "Health check",
            "/": "API info",
        },
    })


# Graceful shutdown when the hosting process stops.
import atexit

@atexit.register
def _shutdown():
    global _loop, _http_client
    try:
        if _loop and _loop.is_running() and _http_client:
            future = asyncio.run_coroutine_threadsafe(_http_client.aclose(), _loop)
            future.result(timeout=2)
            _loop.call_soon_threadsafe(_loop.stop)
    except Exception:
        pass
