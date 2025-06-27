import json
import requests
import time
from threading import Thread

# Danh sách các cặp file (input -> output)
ACCOUNT_FILES = [
    ("accgame.json", "like.json"),
    ("accinfo.json", "info.json"),
    # Thêm bao nhiêu file cũng được ở đây
]

def get_jwt_tokens(input_file, output_file):
    try:
        with open(input_file, 'r') as f:
            accounts = json.load(f)
    except Exception as e:
        print(f"Lỗi khi đọc file {input_file}: {str(e)}")
        return

    tokens = []

    for account in accounts:
        uid = account.get("uid")
        password = account.get("password")

        if not uid or not password:
            print(f"Dữ liệu sai trong {input_file}: {account}")
            continue

        try:
            url = f"https://projects-fox-x-get-jwt.vercel.app/get?uid={uid}&password={password}"
            response = requests.get(url)

            if response.status_code == 200:
                token_data = response.json()
                if 'token' in token_data:
                    tokens.append({"token": token_data['token']})
                    print(f"[{input_file}] ✅ Lấy Token UID {uid} thành công")
                else:
                    print(f"[{input_file}] ❌ Không có token cho UID {uid}")
            else:
                print(f"[{input_file}] ❌ Lỗi HTTP {response.status_code} cho UID {uid}")
        
        except Exception as e:
            print(f"[{input_file}] ❌ Lỗi xử lý UID {uid}: {str(e)}")

    try:
        with open(output_file, 'w') as f:
            json.dump(tokens, f, indent=4)
        print(f"📁 Đã lưu {len(tokens)} token vào {output_file}")
    except Exception as e:
        print(f"❌ Lỗi khi lưu file {output_file}: {str(e)}")

def run_periodically():
    while True:
        for input_file, output_file in ACCOUNT_FILES:
            get_jwt_tokens(input_file, output_file)
        # Chờ 8 tiếng
        time.sleep(8 * 60 * 60)

if __name__ == "__main__":
    print("🚀 Bắt đầu lấy token JWT từ các file...")

    # Lấy token lần đầu
    for input_file, output_file in ACCOUNT_FILES:
        get_jwt_tokens(input_file, output_file)

    # Bắt đầu luồng chạy định kỳ
    thread = Thread(target=run_periodically)
    thread.daemon = True
    thread.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("🛑 Dừng script.")