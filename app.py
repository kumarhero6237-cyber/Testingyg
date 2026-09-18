#  UNCOMMON CORE ON TOP BABY !!!
#  AUTO-REGION FINDER INFO API
#  CREDIT CHANGER MAA KI CHUT
#  FULLY FIXED VERSION
#  JOIN @uncommoncore FOR MORE LEAKS


import asyncio
import time
import httpx
import json
import random
import threading
from collections import defaultdict
from functools import wraps
from flask import Flask, request, jsonify
from flask_cors import CORS
from cachetools import TTLCache
from typing import Tuple
from proto import FreeFire_pb2, main_pb2, AccountPersonalShow_pb2
from google.protobuf import json_format, message
from google.protobuf.message import Message
from Crypto.Cipher import AES
import base64

# ---------- Config ----------

MAIN_KEY = base64.b64decode('WWcmdGMlREV1aDYlWmNeOA==')
MAIN_IV = base64.b64decode('Nm95WkRyMjJFM3ljaGpNJQ==')
RELEASEVERSION = "OB55"
USERAGENT = "UnityPlayer/2018.4.12f1 (UnityWebRequest/1.0, libcurl/8.5.0-DEV)"
SUPPORTED_REGIONS = ["IND"]

# Server prepends a 64-byte binary header to MajorLogin responses
MAJORLOGIN_PREFIX_LEN = 64

# ---------- API KEY SYSTEM ----------

API_KEY = "RAM-SAGAR"

# ---------- App Setup ----------

app = Flask(__name__)
CORS(app)
cache = TTLCache(maxsize=100, ttl=300)
cached_tokens = defaultdict(dict)
uid_region_cache = {}

# ---------- API KEY DECORATOR ----------

def require_api_key(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        key = request.args.get("key") or request.headers.get("x-api-key")

        if key != API_KEY:
            return jsonify({"error": "Invalid or missing API key"}), 403

        return fn(*args, **kwargs)
    return wrapper

# ----------- Helper Functions ------------

def pad(text: bytes) -> bytes:
    padding_length = AES.block_size - (len(text) % AES.block_size)
    return text + bytes([padding_length] * padding_length)

def aes_cbc_encrypt(key: bytes, iv: bytes, plaintext: bytes) -> bytes:
    aes = AES.new(key, AES.MODE_CBC, iv)
    return aes.encrypt(pad(plaintext))

def decode_protobuf(encoded_data: bytes, message_type: message.Message) -> message.Message:
    instance = message_type()
    instance.ParseFromString(encoded_data)
    return instance

async def json_to_proto(json_data: str, proto_message: Message) -> bytes:
    json_format.ParseDict(json.loads(json_data), proto_message)
    return proto_message.SerializeToString()

# ---------- Guest IDS --------------

def get_account_credentials(region: str) -> str:
    r = region.upper()

    if r == "IND":
        return "uid=7662858511&password=1B6C23AA1DF3A6B57D0F5B75E914AE5117E4A700866AB2EC70CAAD28F988E8AD"

    elif r in {"BR", "US", "SAC", "NA"}:
        return "uid=4774366356&password=UNCOMMON-7AAL7W1Z6-CORE"

    elif r == "VN":
        return "uid=4737714557&password=xMaSrY_5Pk5Wqyr_lgb"

    elif r == "SG":
        return "uid=4737718961&password=xMaSrY_fWkmTbea_zca"

    elif r == "ID":
        return "uid=4737720872&password=xMaSrY_bfZlbaoK_Iqt"

    elif r == "TH":
        return "uid=4774298073&password=UNCOMMON-PVFSS7AQR-CORE"

    elif r == "TW":
        return "uid=4774314170&password=UNCOMMON-7KPK0SBGG-CORE"

    elif r == "BD":
        return "uid=4774322299&password=UNCOMMON-0NYV9REVC-CORE"

    elif r == "PK":
        return "uid=4774330898&password=UNCOMMON-3YP9O6AQA-CORE"

    elif r == "ME":
        return "uid=4774339389&password=UNCOMMON-2YE6FUEYD-CORE"

    elif r == "RU":
        return "uid=4774345536&password=UNCOMMON-0VCU5OSI7-CORE"

    elif r == "CIS":
        return "uid=4774350397&password=UNCOMMON-UNB5CY7KS-CORE"

    elif r == "EUROPE":  #  ME SERVER ID GIVEN
        return "uid=4774375811&password=UNCOMMON-UEYUPSJGC-CORE"

    else:
        # fallback to ucguest.txt
        try:
            with open("ucguest.txt", "r") as f:
                lines = [line.strip() for line in f if line.strip()]
                if not lines:
                    raise ValueError("ucguest.txt is empty")

                uid, password = random.choice(lines).split()
                return f"uid={uid}&password={password}"

        except Exception as e:
            return f"ERROR: {e}"

# -------------- JWT API --------------

async def fetch_jwt_token(uid: str, password: str) -> dict:
    """
    Calls the JWT API and returns:
    { AccsTok, OpenId, addr, Tok (JWT), Ver, Ob, Uid }
    """
    url = "http://148.113.25.200:6293/Tok"
    params = {"uid": uid, "pw": password}

    async with httpx.AsyncClient(timeout=15) as client:
        resp = await client.get(url, params=params)
        resp.raise_for_status()
        return resp.json()

# -------------- Token Generation --------------

async def create_jwt(region: str):
    account = get_account_credentials(region)

    creds = dict(p.split("=", 1) for p in account.split("&") if "=" in p)
    uid = creds.get("uid", "")
    password = creds.get("password", "")

    # ---- 1) Fetch JWT ----
    try:
        api_resp = await fetch_jwt_token(uid, password)
    except Exception as e:
        print(f"❌ JWT API FAIL [{region}]: {e}")
        return

    jwt_token = api_resp.get("Tok", "")
    open_id   = api_resp.get("OpenId", "0")
    accs_tok  = api_resp.get("AccsTok", "0")
    err       = api_resp.get("Err", "")

    if err or not jwt_token or jwt_token.lower().startswith("acc ban"):
        print(f"⛔ JWT API BAN/BLOCK [{region}] uid={uid} err={err}")
        return

    if not accs_tok:
        print(f"❌ JWT API BAD RESP [{region}]")
        return

    # ---- 2) Build MajorLogin body ----
    body = json.dumps({
        "open_id": open_id,
        "open_id_type": "4",
        "login_token": accs_tok,
        "orign_platform_type": "4"
    })

    proto_bytes = await json_to_proto(body, FreeFire_pb2.LoginReq())
    payload = aes_cbc_encrypt(MAIN_KEY, MAIN_IV, proto_bytes)

    # ---- 3) MajorLogin ----
    url = "https://loginbp.ggpolarbear.com/MajorLogin"
    headers = {
        'User-Agent': USERAGENT,
        'Accept': "*/*",
        'Accept-Encoding': "deflate, gzip",
        'X-GA-SV': "1789536017",
        'Authorization': f"Bearer {jwt_token}",
        'X-GA': "v1 1",
        'ReleaseVersion': RELEASEVERSION,
        'Content-Type': "application/octet-stream",
        'X-Unity-Version': "2018.4.12f1",
    }

    async with httpx.AsyncClient(timeout=10) as client:
        resp = await client.post(url, data=payload, headers=headers)

        if resp.status_code != 200 or resp.headers.get("content-type") != "application/octet-stream":
            print(f"❌ TOKEN FAIL [{region}]: {resp.status_code}")
            return

        raw = resp.content

        if len(raw) < MAJORLOGIN_PREFIX_LEN + 1:
            print(f"❌ RESP TOO SHORT [{region}]")
            return

        # Strip the 64-byte server prefix before protobuf parse
        proto_payload = raw[MAJORLOGIN_PREFIX_LEN:]

        try:
            decoded = decode_protobuf(proto_payload, FreeFire_pb2.LoginRes)
            msg = json.loads(json_format.MessageToJson(decoded))
        except Exception as e:
            print(f"❌ PROTO FAIL [{region}]: {e}")
            return

        token_val = msg.get('token') or msg.get('Token')
        if not token_val:
            print(f"❌ NO TOKEN IN RESP [{region}]")
            return

        cached_tokens[region] = {
            'token': f"Bearer {token_val}",
            'region': msg.get('lockRegion') or msg.get('lock_region') or region,
            'server_url': msg.get('serverUrl') or msg.get('server_url') or '0',
            'expires_at': time.time() + 25200
        }

        print(f"✅ TOKEN OK [{region}]")


async def initialize_tokens():
    await asyncio.gather(*[create_jwt(r) for r in SUPPORTED_REGIONS])

async def refresh_tokens_periodically():
    while True:
        await asyncio.sleep(25200)
        await initialize_tokens()

async def get_token_info(region: str) -> Tuple[str,str,str]:
    info = cached_tokens.get(region)

    if info and time.time() < info['expires_at']:
        return info['token'], info['region'], info['server_url']

    await create_jwt(region)
    info = cached_tokens[region]
    return info['token'], info['region'], info['server_url']

async def GetAccountInformation(uid, unk, region, endpoint):
    payload = await json_to_proto(
        json.dumps({'a': uid, 'b': unk}),
        main_pb2.GetPlayerPersonalShow()
    )

    data_enc = aes_cbc_encrypt(MAIN_KEY, MAIN_IV, payload)
    token, lock, server = await get_token_info(region)

    headers = {
        'User-Agent': USERAGENT,
        'Connection': "Keep-Alive",
        'Accept-Encoding': "gzip",
        'Content-Type': "application/octet-stream",
        'Expect': "100-continue",
        'Authorization': token,
        'X-Unity-Version': "2018.4.11f1",
        'X-GA': "v1 1",
        'ReleaseVersion': RELEASEVERSION
    }

    async with httpx.AsyncClient() as client:
        resp = await client.post(server + endpoint, data=data_enc, headers=headers)

        return json.loads(
            json_format.MessageToJson(
                decode_protobuf(resp.content, AccountPersonalShow_pb2.AccountPersonalShowInfo)
            )
        )

# -------------- Cache Decorator --------------

def cached_endpoint(ttl=300):
    def decorator(fn):
        @wraps(fn)
        def wrapper(*a, **k):
            key = (request.path, tuple(request.args.items()))
            if key in cache:
                return cache[key]

            res = fn(*a, **k)
            cache[key] = res
            return res

        return wrapper
    return decorator

# -------------- Routes Endpoints --------------

@app.route('/uc-info')
@require_api_key
@cached_endpoint()
def get_account_info():
    uid = request.args.get('uid')

    if not uid:
        return jsonify({"error": "Please provide UID Else try correct endpoint."}), 400

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    # 🔁 If UID already cached with region
    if uid in uid_region_cache:
        try:
            data = loop.run_until_complete(
                GetAccountInformation(uid, "7", uid_region_cache[uid], "/GetPlayerPersonalShow")
            )
            return json.dumps(data, indent=2), 200, {'Content-Type': 'application/json'}
        except:
            pass  # fallback to scanning all regions

    # 🔍 Try all regions
    for region in SUPPORTED_REGIONS:
        try:
            data = loop.run_until_complete(
                GetAccountInformation(uid, "7", region, "/GetPlayerPersonalShow")
            )

            # India-only: do not return a non-India account even if the
            # upstream response contains a different region.
            basic = data.get("basicInfo") or data.get("basic_info") or {}
            player_region = str(
                basic.get("region", "") or basic.get("Region", "")
            ).upper().strip()
            if player_region not in {"IND", "INDIA", "IN"}:
                continue

            uid_region_cache[uid] = region

            return json.dumps(data, indent=2), 200, {'Content-Type': 'application/json'}

        except:
            continue

    return jsonify({"error": "UID not found"}), 404


@app.route('/ref-token', methods=['GET', 'POST'])
@require_api_key
def refresh_tokens_endpoint():
    try:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        loop.run_until_complete(initialize_tokens())

        return jsonify({'message': 'Tokens refreshed'}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# -------------- async Startup --------------

started = False

def start_background_loop():
    global started
    if started:
        return
    started = True

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    loop.run_until_complete(initialize_tokens())
    loop.create_task(refresh_tokens_periodically())
    loop.run_forever()

threading.Thread(target=start_background_loop, daemon=True).start()


# -------------- Run Flask --------------

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)