# INFO API SRC BYY
# POWERED BY : @STAR_GMR
# CHANNEL : @STAR_METHODE
import asyncio
import time
import httpx
import json
import os
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
SUPPORTED_REGIONS = [
    "IND", "SG", "ID", "BR", "VN", "US", "SAC", "NA",
    "RU", "TH", "TW", "BD", "PK", "ME", "CIS", "EUROPE"
]

# ---------- App Setup ----------

app = Flask(__name__)
CORS(app)
cache = TTLCache(maxsize=100, ttl=300)
cached_tokens = defaultdict(dict)
uid_region_cache = {}

# ---------- Guest Rotation Globals ----------

GUEST_CREDENTIALS = {}          # region -> list of credential strings
region_index = defaultdict(int) # current guest index per region
region_calls = defaultdict(int) # call counter per region
ROTATION_THRESHOLD = 2          # rotate after every N calls

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

def find_protobuf_start(data: bytes) -> int:
    """
    LoginRes protobuf hamesha field markers ke saath start hota hai.
    Yeh function response me se woh index dhoondhta hai jahan se valid
    protobuf start hota hai (junk bytes skip karne ke liye).
    """
    # Method 1: "IND" pattern (region field: \x12\x03IND) ke saath
    idx = data.find(b'\x12\x03IND')
    if idx != -1:
        for i in range(idx - 1, max(idx - 20, -1), -1):
            if data[i] == 0x08:
                return i

    # Method 2: JWT token marker (B\xe7\x05eyJ) ke saath
    jwt_marker = data.find(b'B\xe7\x05eyJ')
    if jwt_marker != -1:
        for i in range(jwt_marker - 1, max(jwt_marker - 200, -1), -1):
            if data[i] == 0x08:
                return i

    # Method 3: Fallback — pehla \x08 dhoondo
    return data.find(b'\x08')

# ---------- Load Guest Credentials (at module import) ----------

def load_guests_from_file():
    global GUEST_CREDENTIALS
    try:
        print(f"Current working directory: {os.getcwd()}")
        print(f"Files in directory: {os.listdir('.')}")
        with open('guests.json', 'r', encoding='utf-8') as f:
            data = json.load(f)
        for region in SUPPORTED_REGIONS:
            if region not in data or not data[region]:
                data[region] = []
        GUEST_CREDENTIALS = data
        print("✅ Guests loaded from guests.json")
        print(f"Loaded regions: {list(GUEST_CREDENTIALS.keys())}")
    except Exception as e:
        print(f"❌ Could not load guests.json: {e}")
        GUEST_CREDENTIALS = {}

load_guests_from_file()

# ---------- Guest Rotation Management ----------

def manage_rotation(region: str):
    global region_calls, region_index, cached_tokens
    region_calls[region] += 1
    if region_calls[region] % ROTATION_THRESHOLD == 0:
        guest_list = GUEST_CREDENTIALS.get(region, [])
        if guest_list:
            region_index[region] = (region_index[region] + 1) % len(guest_list)
            if region in cached_tokens:
                del cached_tokens[region]
            print(f"🔄 Rotated guest for {region} to index {region_index[region]}")

# ---------- Guest Credentials (No Hardcoded) ----------

def get_account_credentials(region: str) -> str:
    guest_list = GUEST_CREDENTIALS.get(region.upper(), [])
    idx = region_index[region.upper()]
    if guest_list and idx < len(guest_list):
        return guest_list[idx]
    raise ValueError(f"No guest credentials available for region {region}")

# -------------- Token Generation (async) --------------

async def get_access_token(account: str):
    url = "https://ffmconnect.live.gop.garenanow.com/oauth/guest/token/grant"
    payload = account + "&response_type=token&client_type=2&client_secret=2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3&client_id=100067"
    headers = {
        'User-Agent': USERAGENT,
        'Connection': "Keep-Alive",
        'Accept-Encoding': "gzip",
        'Content-Type': "application/x-www-form-urlencoded"
    }
    async with httpx.AsyncClient() as client:
        resp = await client.post(url, data=payload, headers=headers)
        data = resp.json()
        return data.get("access_token", "0"), data.get("open_id", "0")


async def create_jwt(region: str):
    """
    Naya token-gen logic:
    1. Guest credential se access_token + open_id laao
    2. LoginReq protobuf banao aur AES-CBC se encrypt karo
    3. MajorLogin pe POST karo
    4. Response me se SAHI protobuf start index dhoondo (junk bytes skip)
    5. LoginRes parse karo
    """
    try:
        account = get_account_credentials(region)
    except ValueError as e:
        print(f"❌ {e}")
        return

    token_val, open_id = await get_access_token(account)

    if token_val == "0" or open_id == "0":
        print(f"❌ INVALID GUEST CREDS [{region}] — no access token")
        return

    body = json.dumps({
        "open_id": open_id,
        "open_id_type": "4",
        "login_token": token_val,
        "orign_platform_type": "4"
    })

    proto_bytes = await json_to_proto(body, FreeFire_pb2.LoginReq())
    payload = aes_cbc_encrypt(MAIN_KEY, MAIN_IV, proto_bytes)

    url = "https://loginbp.ppmainecoonghj.com/MajorLogin"
    headers = {
        'User-Agent': USERAGENT,
        'Accept': "*/*",
        'Accept-Encoding': "deflate, gzip",
        'X-Ga-Sv': "1789534056",
        'Authorization': "Bearer",
        'X-Ga': "v1 1",
        'Releaseversion': RELEASEVERSION,
        'Content-Type': "application/x-www-form-urlencoded",
        'X-Unity-Version': "2018.4.12f1",
        'PlAy_VeR': "1.132.1",
        'Ob_VeR': RELEASEVERSION
    }

    async with httpx.AsyncClient(timeout=15) as client:
        resp = await client.post(url, data=payload, headers=headers)

        print(f"=== [{region}] HTTP {resp.status_code} | Content-Length: {len(resp.content)} ===")

        # === Sahi protobuf start index dhoondo ===
        start_idx = find_protobuf_start(resp.content)
        if start_idx == -1:
            print(f"❌ [{region}] Protobuf start not found. Raw: {resp.content[:300]}")
            return

        proto_data = resp.content[start_idx:]
        print(f"=== [{region}] Protobuf starts at index {start_idx} ===")

        try:
            msg = json.loads(json_format.MessageToJson(
                decode_protobuf(proto_data, FreeFire_pb2.LoginRes)
            ))
        except Exception as parse_err:
            print(f"❌ [{region}] PROTO FAIL from idx {start_idx}: {parse_err}")
            print(f"   Raw: {resp.content[start_idx:start_idx+300]}")
            return

        # Token mila?
        token_str = msg.get("token", "")
        if not token_str:
            print(f"❌ [{region}] Empty token in LoginRes")
            return

        cached_tokens[region] = {
            'token': f"Bearer {token_str}",
            'region': msg.get('lockRegion', region) or region,
            'server_url': msg.get('serverUrl', '0'),
            'expires_at': time.time() + 25200
        }

        print(f"✅ TOKEN OK [{region}] guest_idx={region_index[region]} | lock={msg.get('lockRegion','')}")

# -------------- Token Info (Lazy Generation) --------------

async def get_token_info(region: str) -> Tuple[str, str, str]:
    info = cached_tokens.get(region)

    if info and time.time() < info['expires_at']:
        return info['token'], info['region'], info['server_url']

    print(f"⏳ Generating token for {region} on demand...")
    await create_jwt(region)
    info = cached_tokens.get(region)
    if not info:
        raise ValueError(f"Failed to generate token for region {region}")
    return info['token'], info['region'], info['server_url']

# -------------- Account Information --------------

async def GetAccountInformation(uid, unk, region, endpoint):
    manage_rotation(region)

    payload = await json_to_proto(
        json.dumps({'a': uid, 'b': unk}),
        main_pb2.GetPlayerPersonalShow()
    )

    data_enc = aes_cbc_encrypt(MAIN_KEY, MAIN_IV, payload)

    try:
        token, lock, server = await get_token_info(region)
    except ValueError as e:
        raise e

    headers = {
        'User-Agent': USERAGENT,
        'Connection': "Keep-Alive",
        'Accept-Encoding': "gzip",
        'Content-Type': "application/octet-stream",
        'Expect': "100-continue",
        'Authorization': token,
        'X-Unity-Version': "2018.4.12f1",
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
@cached_endpoint()
def get_account_info():
    api_key = request.args.get('key')
    if api_key != 'RAM-SAGAR':
        return jsonify({"error": "Invalid API key"}), 401

    uid = request.args.get('uid')

    if not uid:
        return jsonify({"error": "Please provide UID"}), 400

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    if uid in uid_region_cache:
        try:
            data = loop.run_until_complete(
                GetAccountInformation(uid, "7", uid_region_cache[uid], "/GetPlayerPersonalShow")
            )
            return json.dumps(data, indent=2), 200, {'Content-Type': 'application/json'}
        except Exception as e:
            print(f"Error with cached region {uid_region_cache[uid]}: {e}")

    for region in SUPPORTED_REGIONS:
        try:
            data = loop.run_until_complete(
                GetAccountInformation(uid, "7", region, "/GetPlayerPersonalShow")
            )
            uid_region_cache[uid] = region
            return json.dumps(data, indent=2), 200, {'Content-Type': 'application/json'}
        except Exception as e:
            print(f"Failed for region {region}: {e}")
            continue

    return jsonify({"error": "UID not found or no guest available for any region"}), 404


@app.route('/ref-token', methods=['GET', 'POST'])
def refresh_tokens_endpoint():
    try:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        tasks = []
        for r in SUPPORTED_REGIONS:
            if GUEST_CREDENTIALS.get(r):
                tasks.append(create_jwt(r))
        if tasks:
            loop.run_until_complete(asyncio.gather(*tasks))
        return jsonify({'message': 'Tokens refreshed'}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/reload-guests', methods=['GET', 'POST'])
def reload_guests():
    try:
        load_guests_from_file()
        region_index.clear()
        region_calls.clear()
        cached_tokens.clear()
        return jsonify({'message': 'Guests reloaded and tokens invalidated'}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/status', methods=['GET'])
def status():
    return jsonify({
        "loaded_regions": list(GUEST_CREDENTIALS.keys()),
        "total_guests": {r: len(GUEST_CREDENTIALS[r]) for r in GUEST_CREDENTIALS},
        "cached_tokens": list(cached_tokens.keys())
    })


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5001, debug=True)