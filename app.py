from flask import Flask, request, jsonify
import asyncio
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from google.protobuf.json_format import MessageToJson
import binascii
import aiohttp
import requests
import os
import uid_generator_pb2
import json
import time
from zitado_pb2 import Users
from secret import key, iv
from google.protobuf.message import DecodeError

app = Flask(__name__)

def load_tokens(server_name, purpose="like"):
    try:
        file_name = "like.json" if purpose == "like" else "info.json"
        with open(file_name, "r") as f:
            tokens = json.load(f)
        return tokens
    except Exception as e:
        app.logger.error(f"không thể tải token")
        return None


def encrypt_message(plaintext):
    try:
        cipher = AES.new(b'Yg&tc%DEuh6%Zc^8', AES.MODE_CBC, b'6oyZDr22E3ychjM%')
        padded = pad(plaintext, AES.block_size)
        encrypted = cipher.encrypt(padded)
        return binascii.hexlify(encrypted).decode()
    except Exception as e:
        app.logger.error(f"Encryption error")
        return None

async def send_request(encrypted_uid, token, url):
    try:
        edata = bytes.fromhex(encrypted_uid)
        headers = {
            'User-Agent': "Dalvik/2.1.0 (Linux; U; Android 9; ASUS_Z01QD Build/PI)",
            'Connection': "Keep-Alive",
            'Accept-Encoding': "gzip",
            'Authorization': f"Bearer {token}",
            'Content-Type': "application/x-www-form-urlencoded",
            'Expect': "100-continue",
            'X-Unity-Version': "2018.4.11f1",
            'X-GA': "v1 1",
            'ReleaseVersion': "OB49"
        }
        async with aiohttp.ClientSession() as session:
            async with session.post(url, data=edata, headers=headers) as response:
                if response.status != 200:
                    app.logger.error(f"Request failed with status code: {response.status}")
                    return response.status
                return await response.text()
    except Exception as e:
        app.logger.error(f"Exception in send_request")
        return None


async def send_multiple_requests(encrypted_uid, server_name, url):
    try:
        tokens = load_tokens(server_name)
        if not tokens:
            app.logger.error("Failed to load tokens.")
            return None

        tasks = []
        for idx, token_entry in enumerate(tokens[:101]):
            token = token_entry.get("token")
            if token:
                app.logger.info(f"[Token {idx}] Gửi like với token: {token[:15]}...")
                tasks.append(send_request(encrypted_uid, token, url))

        if not tasks:
            app.logger.error("Không có token hợp lệ.")
            return None

        results = await asyncio.gather(*tasks, return_exceptions=True)
        return results
    except Exception as e:
        app.logger.error(f"Exception in send_multiple_requests")
        return None


def create_uid_protobuf(uid):
    try:
        message = uid_generator_pb2.uid_generator()
        message.akiru_ = int(uid)
        message.aditya = 1
        return message.SerializeToString()
    except Exception as e:
        app.logger.error(f"Error creating uid protobuf")
        return None

def enc(uid):
    protobuf_data = create_uid_protobuf(uid)
    if protobuf_data is None:
        return None
    encrypted_uid = encrypt_message(protobuf_data)
    return encrypted_uid




def hex_to_bytes(hex_string):
    return bytes.fromhex(hex_string)

def create_protobuf(akiru_, aditya):
    message = uid_generator_pb2.uid_generator()
    message.akiru_ = akiru_
    message.aditya = aditya
    return message.SerializeToString()

def protobuf_to_hex(protobuf_data):
    return binascii.hexlify(protobuf_data).decode()

def decode_hex(hex_string):
    byte_data = binascii.unhexlify(hex_string.replace(' ', ''))
    users = Users()
    users.ParseFromString(byte_data)
    return users

def encrypt_aes(hex_data, key, iv):
    key = key.encode()[:16]
    iv = iv.encode()[:16]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_data = pad(bytes.fromhex(hex_data), AES.block_size)
    encrypted_data = cipher.encrypt(padded_data)
    return binascii.hexlify(encrypted_data).decode()



  



@app.route('/player', methods=['GET'])
def main():
    start_time = time.time()  # ⏱️ Bắt đầu đếm thời gian

    uid = request.args.get('uid')
    region = request.args.get('region', '').upper()

    if not uid or not region:
        return jsonify({"error": "Thiếu Tham Số 'uid', 'region' hoặc"}), 400

    try:
        saturn_ = int(uid)
    except ValueError:
        return jsonify({"error": "UID phải là số"}), 400

    # Lấy token từ API thay vì file
    try:
        url = f"https://uditanshu-jwt-ob49.vercel.app/token?uid=3998533985&password=79D0F69663A7E5F5C8471F7E735DAC3C13EA80642916ED09E179BE4D6D5B80EC"
        response = requests.get(url)
        if response.status_code == 200:
            token_data = response.json()
            if 'token' in token_data:
                info_token = token_data['token']
            else:
                return jsonify({"error": "Không tìm thấy token trong phản hồi"}), 500
        else:
            return jsonify({"error": f"Lỗi khi gọi API lấy token, mã lỗi: {response.status_code}"}), 500
    except Exception as e:
        return jsonify({"error": f"Lỗi khi kết nối API token: {str(e)}"}), 500

    protobuf_data = create_protobuf(saturn_, 1)
    hex_data = protobuf_to_hex(protobuf_data)
    encrypted_hex = encrypt_aes(hex_data, key, iv)

    headers = {
        'User-Agent': 'Dalvik/2.1.0 (Linux; U; Android 9; ASUS_Z01QD Build/PI)',
        'Connection': 'Keep-Alive',
        'Expect': '100-continue',
        'Authorization': f'Bearer {info_token}',
        'X-Unity-Version': '2018.4.11f1',
        'X-GA': 'v1 1',
        'ReleaseVersion': 'OB49',
        'Content-Type': 'application/x-www-form-urlencoded',
    }

    try:
        res_before = requests.post(
            "https://clientbp.ggblueshark.com/GetPlayerPersonalShow",
            headers=headers,
            data=bytes.fromhex(encrypted_hex)
        )
        res_before.raise_for_status()
        user_data = decode_hex(res_before.content.hex())
    except Exception:
        return jsonify({"error": f"Không thể kết nối hoặc giải mã dữ liệu"}), 502

    encrypted_uid = enc(uid)
    if encrypted_uid:
        if region in {"BR", "US", "SAC", "VN"}:
            like_url = "https://client.us.freefiremobile.com/LikeProfile"
        else:
            like_url = "https://clientbp.ggblueshark.com/LikeProfile"

        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        results = loop.run_until_complete(send_multiple_requests(encrypted_uid, region, like_url))
        loop.close()

        if results is None:
            elapsed_time = round(time.time() - start_time, 2)
            return jsonify({
                "error": "Không thể gửi like vì lỗi hệ thống hoặc thiếu token.",
                "status": 2,
                "elapsed_time": f"{elapsed_time}s"
            }), 500

    try:
        res_after = requests.post(
            "https://clientbp.ggblueshark.com/GetPlayerPersonalShow",
            headers=headers,
            data=bytes.fromhex(encrypted_hex)
        )
        res_after.raise_for_status()
        user_data_after = decode_hex(res_after.content.hex())
    except Exception as e:
        return jsonify({"error": f"Không thể lấy dữ liệu sau khi like: {e}"}), 502

    try:
        player = user_data_after.basicinfo[0]
        before_like = user_data.basicinfo[0].likes
        after_like = player.likes
        like_diff = after_like - before_like
    except Exception:
        before_like = after_like = like_diff = 0
        player = None

    elapsed_time = round(time.time() - start_time, 2)

    if like_diff == 0:
        return jsonify({
            "error": f"UID {uid} has already received Max Likes for Today.",
            "UID": uid,
            "status": 2,
            "elapsed_time": f"{elapsed_time}s"
        }), 200

    return jsonify({
        "PlayerNickname": player.username if player else "",
        "Level": player.level if player else 0,
        "UID": uid,
        "LikesBefore": before_like,
        "LikesAfter": after_like,
        "LikesGivenByAPI": like_diff,
        "status": 1,
        "elapsed_time": f"{elapsed_time}s",
        "Tiktok": "@amdtsmodz"
    })
    
if __name__ == '__main__':
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
