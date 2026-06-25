from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
from PIL import Image
import os, uuid, struct, hashlib, base64, mimetypes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

app = Flask(__name__)

# ── CORS: allow every origin including null (local file://) ──────────────────
CORS(app, resources={r"/*": {"origins": "*"}}, supports_credentials=False)

@app.after_request
def add_cors(response):
    response.headers["Access-Control-Allow-Origin"]  = "*"
    response.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization"
    response.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
    return response

@app.route("/", defaults={"path": ""}, methods=["OPTIONS"])
@app.route("/<path:path>", methods=["OPTIONS"])
def options_handler(path):
    return jsonify({}), 200

# ── Storage ──────────────────────────────────────────────────────────────────
MEDIA   = "media"
UPLOADS = os.path.join(MEDIA, "uploads")
OUTPUTS = os.path.join(MEDIA, "outputs")
os.makedirs(UPLOADS, exist_ok=True)
os.makedirs(OUTPUTS, exist_ok=True)


# ════════════════════════════════════════════════════════════════════════════
#  CRYPTO  —  AES-256-GCM  +  PBKDF2
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
    # pack: nonce(12) + ciphertext+tag
    blob  = nonce + ct
    return salt, blob

def decrypt(blob_b64: str, password: str, salt_b64: str) -> bytes:
    salt = base64.b64decode(salt_b64)
    blob = base64.b64decode(blob_b64)
    key  = _derive_key(password, salt)
    nonce, ct = blob[:12], blob[12:]
    return AESGCM(key).decrypt(nonce, ct, None)


# ════════════════════════════════════════════════════════════════════════════
#  PAYLOAD  —  simple |-delimited header  +  base64 body
#  Format:  HIFIVAULT|<filename>|<mimetype>|<salt_b64>|<data_b64>
# ════════════════════════════════════════════════════════════════════════════
MAGIC = "HIFIVAULT"
SEP   = "|"

def create_payload(filename: str, filetype: str, salt: bytes, encrypted_data: bytes) -> str:
    salt_b64 = base64.b64encode(salt).decode()
    data_b64 = base64.b64encode(encrypted_data).decode()
    return SEP.join([MAGIC, filename, filetype, salt_b64, data_b64])

def parse_payload(raw: str) -> dict | None:
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
#  STEGANOGRAPHY  —  LSB  (least-significant bit)
# ════════════════════════════════════════════════════════════════════════════

def _to_png(src_path: str) -> str:
    """Convert any image format to PNG and return new path."""
    if src_path.lower().endswith(".png"):
        return src_path
    dst = src_path.rsplit(".", 1)[0] + ".png"
    Image.open(src_path).convert("RGBA").save(dst, "PNG")
    return dst

def get_capacity(image_path: str) -> int:
    """Max bytes we can hide = (pixels * 3 channels * 1 bit) / 8  minus 4 bytes for length header."""
    img = Image.open(image_path).convert("RGB")
    w, h = img.size
    return (w * h * 3) // 8 - 4

def hide(image_path: str, payload: str, output_path: str):
    data   = payload.encode("utf-8")
    length = len(data)

    img    = Image.open(image_path).convert("RGB")
    pixels = list(img.getdata())
    w, h   = img.size

    max_bytes = (w * h * 3) // 8 - 4
    if length > max_bytes:
        raise ValueError(f"Payload too large: {length} bytes, image holds {max_bytes}")

    # Encode length as 4-byte big-endian then payload bytes
    bits = []
    for byte in struct.pack(">I", length) + data:
        for i in range(7, -1, -1):
            bits.append((byte >> i) & 1)

    flat   = [ch for px in pixels for ch in px]
    for i, bit in enumerate(bits):
        flat[i] = (flat[i] & 0xFE) | bit

    # Rebuild pixels
    new_pixels = [tuple(flat[i*3:(i*3)+3]) for i in range(w * h)]
    out = Image.new("RGB", (w, h))
    out.putdata(new_pixels)
    out.save(output_path, "PNG")

def extract(image_path: str) -> str:
    img    = Image.open(image_path).convert("RGB")
    pixels = list(img.getdata())
    flat   = [ch for px in pixels for ch in px]

    def read_bytes(n, offset=0):
        result = bytearray()
        for i in range(n):
            byte = 0
            for j in range(8):
                byte = (byte << 1) | (flat[offset * 8 + i * 8 + j] & 1)
            result.append(byte)
        return bytes(result)

    # Read 4-byte length header
    length = struct.unpack(">I", read_bytes(4, 0))[0]

    if length == 0 or length > len(flat) // 8:
        raise ValueError("No valid payload found in this image")

    payload_bytes = read_bytes(length, 4)
    return payload_bytes.decode("utf-8")


# ════════════════════════════════════════════════════════════════════════════
#  ROUTES
# ════════════════════════════════════════════════════════════════════════════

@app.route("/")
def health():
    return jsonify({"status": "HifiVault API running ✓"})


@app.route("/api/hide/", methods=["POST"])
def api_hide():
    image_file  = request.files.get("image")
    secret_file = request.files.get("file")
    password    = request.form.get("password", "").strip()

    if not image_file:
        return jsonify({"error": "No cover image provided"}), 400
    if not secret_file:
        return jsonify({"error": "No secret file provided"}), 400
    if not password:
        return jsonify({"error": "No password provided"}), 400

    # Save uploaded image
    ext      = os.path.splitext(image_file.filename)[1] or ".png"
    img_path = os.path.join(UPLOADS, f"{uuid.uuid4()}{ext}")
    image_file.save(img_path)

    try:
        png_path = _to_png(img_path)
    except Exception as e:
        return jsonify({"error": f"Could not open image: {e}"}), 400

    # Read secret file
    file_bytes = secret_file.read()
    if not file_bytes:
        return jsonify({"error": "Secret file is empty"}), 400

    # Encrypt
    salt, encrypted = encrypt(file_bytes, password)

    # Build payload
    mime     = secret_file.content_type or mimetypes.guess_type(secret_file.filename)[0] or "application/octet-stream"
    payload  = create_payload(
        filename=secret_file.filename,
        filetype=mime,
        salt=salt,
        encrypted_data=encrypted,
    )

    # Capacity check
    try:
        cap = get_capacity(png_path)
    except Exception as e:
        return jsonify({"error": f"Image error: {e}"}), 400

    if len(payload.encode("utf-8")) > cap:
        return jsonify({"error": f"Image too small. Need ~{len(payload.encode())//1024+1} KB capacity, image holds {cap//1024} KB. Use a larger image."}), 400

    # Embed
    out_name = f"stego_{uuid.uuid4()}.png"
    out_path = os.path.join(OUTPUTS, out_name)
    try:
        hide(png_path, payload, out_path)
    except Exception as e:
        return jsonify({"error": f"Embedding failed: {e}"}), 500

    return jsonify({
        "status":   "success",
        "download": f"/download/{out_name}",
    })


@app.route("/api/extract/", methods=["POST"])
def api_extract():
    image_file = request.files.get("image")
    password   = request.form.get("password", "").strip()

    if not image_file:
        return jsonify({"error": "No image provided"}), 400
    if not password:
        return jsonify({"error": "No password provided"}), 400

    ext      = os.path.splitext(image_file.filename)[1] or ".png"
    img_path = os.path.join(UPLOADS, f"{uuid.uuid4()}{ext}")
    image_file.save(img_path)

    # Extract raw payload
    try:
        raw = extract(img_path)
    except Exception as e:
        return jsonify({"error": f"No hidden data found in this image. ({e})"}), 400

    # Parse
    payload = parse_payload(raw)
    if not payload:
        return jsonify({"error": "Payload is corrupted or not a HifiVault image"}), 400

    # Decrypt
    try:
        decrypted = decrypt(
            blob_b64=payload["encrypted_data"],
            password=password,
            salt_b64=payload["salt"],
        )
    except Exception:
        return jsonify({"error": "Wrong password or corrupted data"}), 400

    # Save extracted file
    safe_name  = os.path.basename(payload["filename"])  # prevent path traversal
    out_path   = os.path.join(OUTPUTS, f"{uuid.uuid4()}_{safe_name}")
    with open(out_path, "wb") as f:
        f.write(decrypted)

    return jsonify({
        "status":   "success",
        "filename": safe_name,
        "filetype": payload["filetype"],
        "saved_to": f"/download/{os.path.basename(out_path)}",
    })


@app.route("/download/<path:filename>")
def download(filename):
    # Security: only serve files from OUTPUTS directory
    safe = os.path.basename(filename)
    return send_from_directory(OUTPUTS, safe, as_attachment=True)


# ════════════════════════════════════════════════════════════════════════════
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8000))
    app.run(host="0.0.0.0", port=port, debug=False)