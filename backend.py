from flask import Flask, request, jsonify, send_from_directory, make_response
from PIL import Image
import os, uuid, struct, base64, mimetypes
import numpy as np

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

from flask_cors import CORS

app = Flask(__name__)

# ── CORS ─────────────────────────────────────────────
FRONTEND = "https://hifivault.vercel.app"

CORS(
    app,
    origins=[FRONTEND],
    methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Content-Type", "Authorization"]
)

@app.after_request
def add_cors_headers(response):
    response.headers["Access-Control-Allow-Origin"] = FRONTEND
    response.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization"
    response.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
    response.headers["Access-Control-Allow-Credentials"] = "false"
    return response


# ── STORAGE ─────────────────────────────────────────
MEDIA = "media"
UPLOADS = os.path.join(MEDIA, "uploads")
OUTPUTS = os.path.join(MEDIA, "outputs")

os.makedirs(UPLOADS, exist_ok=True)
os.makedirs(OUTPUTS, exist_ok=True)


# ── CRYPTO ──────────────────────────────────────────
ITERATIONS = 200_000

def derive_key(password: str, salt: bytes):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=ITERATIONS,
    )
    return kdf.derive(password.encode())


def encrypt(data: bytes, password: str):
    salt = os.urandom(16)
    key = derive_key(password, salt)
    nonce = os.urandom(12)
    ct = AESGCM(key).encrypt(nonce, data, None)
    return salt, nonce + ct


def decrypt(blob_b64: str, password: str, salt_b64: str):
    salt = base64.b64decode(salt_b64)
    blob = base64.b64decode(blob_b64)
    key = derive_key(password, salt)
    nonce, ct = blob[:12], blob[12:]
    return AESGCM(key).decrypt(nonce, ct, None)


# ── PAYLOAD ─────────────────────────────────────────
MAGIC = "HIFIVAULT"
SEP = "|"


def create_payload(filename, filetype, salt, encrypted):
    return SEP.join([
        MAGIC,
        filename,
        filetype,
        base64.b64encode(salt).decode(),
        base64.b64encode(encrypted).decode(),
    ])


def parse_payload(raw):
    parts = raw.split(SEP, 4)
    if len(parts) != 5 or parts[0] != MAGIC:
        return None

    return {
        "filename": parts[1],
        "filetype": parts[2],
        "salt": parts[3],
        "encrypted_data": parts[4],
    }


# ── STEGANOGRAPHY (OPTIMIZED) ───────────────────────
def hide_image(image_path, payload, output_path):
    img = Image.open(image_path).convert("RGB")
    arr = np.array(img)

    flat = arr.flatten()

    data = payload.encode()
    length = len(data)

    bits = []
    for byte in struct.pack(">I", length) + data:
        for i in range(7, -1, -1):
            bits.append((byte >> i) & 1)

    if len(bits) > len(flat):
        raise ValueError("Image too small for payload")

    for i in range(len(bits)):
        flat[i] = (flat[i] & 254) | bits[i]

    out = Image.fromarray(flat.reshape(arr.shape).astype("uint8"))
    out.save(output_path, "PNG")


def extract_image(image_path):
    img = Image.open(image_path).convert("RGB")
    arr = np.array(img).flatten()

    def read_bits(offset, count):
        out = bytearray()
        for i in range(count):
            byte = 0
            for j in range(8):
                byte = (byte << 1) | (arr[(offset + i) * 8 + j] & 1)
            out.append(byte)
        return bytes(out)

    length = struct.unpack(">I", read_bits(0, 4))[0]

    if length <= 0 or length > len(arr):
        raise ValueError("No valid payload found")

    return read_bits(4, length).decode()


# ── ROUTES ──────────────────────────────────────────
@app.route("/")
def home():
    return jsonify({"status": "HifiVault API running"})


@app.route("/api/hide/", methods=["POST", "OPTIONS"])
def api_hide():
    if request.method == "OPTIONS":
        return "", 204

    image = request.files.get("image")
    secret = request.files.get("file")
    password = request.form.get("password", "").strip()

    if not image or not secret or not password:
        return jsonify({"error": "Missing fields"}), 400

    img_path = os.path.join(UPLOADS, f"{uuid.uuid4()}.png")
    image.save(img_path)

    file_bytes = secret.read()

    salt, encrypted = encrypt(file_bytes, password)

    mime = secret.content_type or mimetypes.guess_type(secret.filename)[0] or "application/octet-stream"

    payload = create_payload(secret.filename, mime, salt, encrypted)

    out_name = f"stego_{uuid.uuid4()}.png"
    out_path = os.path.join(OUTPUTS, out_name)

    try:
        hide_image(img_path, payload, out_path)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

    base = request.host_url.rstrip("/")

    return jsonify({
        "status": "success",
        "download": f"{base}/download/{out_name}"
    })


@app.route("/api/extract/", methods=["POST", "OPTIONS"])
def api_extract():
    if request.method == "OPTIONS":
        return "", 204

    image = request.files.get("image")
    password = request.form.get("password", "").strip()

    if not image or not password:
        return jsonify({"error": "Missing fields"}), 400

    img_path = os.path.join(UPLOADS, f"{uuid.uuid4()}.png")
    image.save(img_path)

    try:
        raw = extract_image(img_path)
    except Exception as e:
        return jsonify({"error": str(e)}), 400

    payload = parse_payload(raw)

    if not payload:
        return jsonify({"error": "Invalid payload"}), 400

    try:
        decrypted = decrypt(
            payload["encrypted_data"],
            password,
            payload["salt"]
        )
    except Exception:
        return jsonify({"error": "Wrong password"}), 400

    out_name = f"{uuid.uuid4()}_{payload['filename']}"
    out_path = os.path.join(OUTPUTS, out_name)

    with open(out_path, "wb") as f:
        f.write(decrypted)

    base = request.host_url.rstrip("/")

    return jsonify({
        "status": "success",
        "filename": payload["filename"],
        "filetype": payload["filetype"],
        "saved_to": f"{base}/download/{out_name}"
    })


@app.route("/download/<path:filename>")
def download(filename):
    return send_from_directory(OUTPUTS, filename, as_attachment=True)


# ── RUN ─────────────────────────────────────────────
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8000))
    app.run(host="0.0.0.0", port=port, debug=False)
