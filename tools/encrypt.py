# 動画を合言葉で暗号化して data/ に置く（AES-256-GCM / PBKDF2-SHA256）
# 使い方: python3 tools/encrypt.py <動画ファイル> <合言葉>
# 出力の並び: salt(16) + iv(12) + 暗号文（末尾16バイトは認証タグ）
# ※ 元の動画と合言葉はこのフォルダに置かない（公開リポジトリのため）
import os, sys
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ITER = 600000  # index.html の ITER と同じ値にする

def main():
    src, word = sys.argv[1], sys.argv[2]
    salt, iv = os.urandom(16), os.urandom(12)
    key = PBKDF2HMAC(hashes.SHA256(), 32, salt, ITER).derive(word.encode("utf-8"))
    body = AESGCM(key).encrypt(iv, open(src, "rb").read(), None)
    os.makedirs(os.path.join(ROOT, "data"), exist_ok=True)
    out = os.path.join(ROOT, "data", "totoro.bin")
    open(out, "wb").write(salt + iv + body)
    print(out, os.path.getsize(out))

main()
