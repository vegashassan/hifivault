from flask import Flask, request, jsonify, send_from_directory, make_response
from PIL import Image
import os, uuid, struct, base64, mimetypes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

from flask_cors import CORS

app = Flask(__name__)

CORS(
    app,
    origins=["https://hifivault.vercel.app"],
    methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["Content-Type", "Authorization"]
)

# ── Storage ───────────────────────────────────────────────────────────────────
MEDIA   = "media"
UPLOADS = os.path.join(MEDIA, "uploads")
OUTPUTS = os.path.join(MEDIA, "outputs")
os.makedirs(UPLOADS, exist_ok=True)
os.makedirs(OUTPUTS, exist_ok=True)

@app.route("/api/hide/", methods=["POST", "OPTIONS"])
def hide():
    if request.method == "OPTIONS":
        return '', 204


@app.route("/api/extract/", methods=["POST", "OPTIONS"])
def extract():
    if request.method == "OPTIONS":
        return '', 204
# ════════════════════════════════════════════════════════════════════════════
#  CORS — manual, no flask-cors, applied to EVERY response including errors
# ════════════════════════════════════════════════════════════════════════════
def cors_response(data, status=200):
    resp = make_response(jsonify(data), status)
    resp.headers["Access-Control-Allow-Origin"] = "https://hifivault.vercel.app"
    resp.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization, X-Requested-With"
    resp.headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, DELETE, OPTIONS"
    resp.headers["Access-Control-Allow-Credentials"] = "false"
    resp.headers["Access-Control-Max-Age"] = "86400"
    return resp

@app.after_request
def inject_cors(response):
    response.headers["Access-Control-Allow-Origin"] = "https://hifivault.vercel.app"
    response.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization, X-Requested-With"
    response.headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, DELETE, OPTIONS"
    response.headers["Access-Control-Allow-Credentials"] = "false"
    response.headers["Access-Control-Max-Age"] = "86400"
    return response
# Handle ALL OPTIONS preflight requests globally
@app.route("/", defaults={"path": ""}, methods=["OPTIONS"])
@app.route("/<path:path>", methods=["OPTIONS"])
def preflight(path):
    return cors_response({})


# ════════════════════════════════════════════════════════════════════════════
#  CRYPTO — AES-256-GCM + PBKDF2
# ════════════════════════════════════════════════════════════════════════════
ITERATIONS = 200_000

def _derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=ITERATIONS,
    )
    return kdf.derive(password.encode())

def encrypt(data: bytes, password: str):
    salt  = os.urandom(16)
    key   = _derive_key(password, salt)
    nonce = os.urandom(12)
    ct    = AESGCM(key).encrypt(nonce, data, None)
    return salt, nonce + ct

def decrypt(blob_b64: str, password: str, salt_b64: str) -> bytes:
    salt  = base64.b64decode(salt_b64)
    blob  = base64.b64decode(blob_b64)
    key   = _derive_key(password, salt)
    nonce, ct = blob[:12], blob[12:]
    return AESGCM(key).decrypt(nonce, ct, None)


# ════════════════════════════════════════════════════════════════════════════
#  PAYLOAD — HIFIVAULT|filename|mimetype|salt_b64|data_b64
# ════════════════════════════════════════════════════════════════════════════
MAGIC = "HIFIVAULT"
SEP   = "|"

def create_payload(filename, filetype, salt, encrypted_data):
    return SEP.join([
        MAGIC,
        filename,
        filetype,
        base64.b64encode(salt).decode(),
        base64.b64encode(encrypted_data).decode(),
    ])

def parse_payload(raw):
    parts = raw.split(SEP, 4)
    if len(parts) != 5 or parts[0] != MAGIC:
        return None
    return {
        "filename":       parts[1],
        "filetype":       parts[2],
        "salt":           parts[3],
        "encrypted_data": parts[4],
    }


# ════════════════════════════════════════════════════════════════════════════
#  STEGANOGRAPHY — LSB
# ════════════════════════════════════════════════════════════════════════════
def _to_png(src_path):
    if src_path.lower().endswith(".png"):
        return src_path
    dst = src_path.rsplit(".", 1)[0] + "_converted.png"
    img = Image.open(src_path)
    img.convert("RGB").save(dst, "PNG")
    return dst

def get_capacity(image_path):
    img = Image.open(image_path).convert("RGB")
    w, h = img.size
    return (w * h * 3) // 8 - 4

def hide(image_path, payload, output_path):
    data   = payload.encode("utf-8")
    length = len(data)
    img    = Image.open(image_path).convert("RGB")
    w, h   = img.size
    pixels = list(img.getdata())

    max_bytes = (w * h * 3) // 8 - 4
    if length > max_bytes:
        raise ValueError(f"Payload too large ({length} bytes). Image only holds {max_bytes} bytes.")

    # Build bit array: 4-byte length header + payload
    bits = []
    for byte in struct.pack(">I", length) + data:
        for i in range(7, -1, -1):
            bits.append((byte >> i) & 1)

    flat = [ch for px in pixels for ch in px]
    for i, bit in enumerate(bits):
        flat[i] = (flat[i] & 0xFE) | bit

    out = Image.new("RGB", (w, h))
    out.putdata([tuple(flat[i*3:i*3+3]) for i in range(w * h)])
    out.save(output_path, "PNG")

def extract(image_path):
    img    = Image.open(image_path).convert("RGB")
    w, h   = img.size
    pixels = list(img.getdata())
    flat   = [ch for px in pixels for ch in px]

    def read_bytes(count, bit_offset):
        result = bytearray()
        for i in range(count):
            byte = 0
            for j in range(8):
                idx = (bit_offset + i) * 8 + j
                byte = (byte << 1) | (flat[idx] & 1)
            result.append(byte)
        return bytes(result)

    length = struct.unpack(">I", read_bytes(4, 0))[0]

    if length == 0 or length > (w * h * 3) // 8:
        raise ValueError("No valid HifiVault payload found.")

    return read_bytes(length, 4).decode("utf-8")


# ════════════════════════════════════════════════════════════════════════════
#  ROUTES
# ════════════════════════════════════════════════════════════════════════════
@app.route("/")
def health():
    return cors_response({"status": "HifiVault API running"})


@app.route("/api/hide/", methods=["POST"])
def api_hide():
    image_file  = request.files.get("image")
    secret_file = request.files.get("file")
    password    = request.form.get("password", "").strip()

    if not image_file:
        return cors_response({"error": "No cover image provided"}, 400)
    if not secret_file:
        return cors_response({"error": "No secret file provided"}, 400)
    if not password:
        return cors_response({"error": "No password provided"}, 400)

    # Save cover image
    ext      = os.path.splitext(image_file.filename)[-1].lower() or ".png"
    img_path = os.path.join(UPLOADS, f"{uuid.uuid4()}{ext}")
    image_file.save(img_path)

    try:
        png_path = _to_png(img_path)
    except Exception as e:
        return cors_response({"error": f"Could not read image: {e}"}, 400)

    # Read secret
    file_bytes = secret_file.read()
    if not file_bytes:
        return cors_response({"error": "Secret file is empty"}, 400)

    # Encrypt
    salt, encrypted = encrypt(file_bytes, password)

    # Build payload
    mime    = secret_file.content_type or \
              mimetypes.guess_type(secret_file.filename)[0] or \
              "application/octet-stream"
    payload = create_payload(secret_file.filename, mime, salt, encrypted)

    # Capacity check
    try:
        cap = get_capacity(png_path)
    except Exception as e:
        return cors_response({"error": f"Image error: {e}"}, 400)

    needed = len(payload.encode("utf-8"))
    if needed > cap:
        return cors_response({
            "error": f"Image too small. Need {needed // 1024 + 1} KB capacity but image only holds {cap // 1024} KB. Use a larger image."
        }, 400)

    # Embed
    out_name = f"stego_{uuid.uuid4()}.png"
    out_path = os.path.join(OUTPUTS, out_name)
    try:
        hide(png_path, payload, out_path)
    except Exception as e:
        return cors_response({"error": f"Embedding failed: {e}"}, 500)

    base_url = request.host_url.rstrip("/")
    return cors_response({
        "status":   "success",
        "download": f"{base_url}/download/{out_name}",
    })


@app.route("/api/extract/", methods=["POST"])
def api_extract():
    image_file = request.files.get("image")
    password   = request.form.get("password", "").strip()

    if not image_file:
        return cors_response({"error": "No image provided"}, 400)
    if not password:
        return cors_response({"error": "No password provided"}, 400)

    ext      = os.path.splitext(image_file.filename)[-1].lower() or ".png"
    img_path = os.path.join(UPLOADS, f"{uuid.uuid4()}{ext}")
    image_file.save(img_path)

    # Extract
    try:
        raw = extract(img_path)
    except Exception as e:
        return cors_response({"error": f"No hidden data found. ({e})"}, 400)

    # Parse
    payload = parse_payload(raw)
    if not payload:
        return cors_response({"error": "Corrupted payload or not a HifiVault image."}, 400)

    # Decrypt
    try:
        decrypted = decrypt(
            blob_b64=payload["encrypted_data"],
            password=password,
            salt_b64=payload["salt"],
        )
    except Exception:
        return cors_response({"error": "Wrong password or corrupted data."}, 400)

    # Save extracted file
    safe_name = os.path.basename(payload["filename"])
    out_name  = f"{uuid.uuid4()}_{safe_name}"
    out_path  = os.path.join(OUTPUTS, out_name)
    with open(out_path, "wb") as f:
        f.write(decrypted)

    base_url = request.host_url.rstrip("/")
    return cors_response({
        "status":   "success",
        "filename": safe_name,
        "filetype": payload["filetype"],
        "saved_to": f"{base_url}/download/{out_name}",
    })


@app.route("/download/<path:filename>")
def download(filename):
    safe = os.path.basename(filename)
    return send_from_directory(OUTPUTS, safe, as_attachment=True)


# ════════════════════════════════════════════════════════════════════════════
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8000))
    app.run(host="0.0.0.0", port=port, debug=False)
