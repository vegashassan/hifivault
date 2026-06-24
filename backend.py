from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
import os
import uuid

from vault.crypto import encrypt, decrypt
from vault.payload import create_payload, parse_payload, validate_payload
from vault.stego import hide_data, extract_data, convert_to_png, get_image_capacity

app = Flask(__name__)
CORS(app)

# -----------------------
# STORAGE
# -----------------------
MEDIA = "media"
UPLOADS = os.path.join(MEDIA, "uploads")
OUTPUTS = os.path.join(MEDIA, "outputs")

os.makedirs(UPLOADS, exist_ok=True)
os.makedirs(OUTPUTS, exist_ok=True)


# -----------------------
# HEALTH CHECK
# -----------------------
@app.route("/")
def home():
    return jsonify({"status": "HifiVault API running"})


# -----------------------
# HIDE FILE
# -----------------------

@app.route("/api/hide/", methods=["POST"])
def hide():

    image = request.files.get("image")
    secret_file = request.files.get("file")
    password = request.form.get("password")

    if not image or not secret_file or not password:
        return jsonify({"error": "Missing image, file, or password"}), 400

    # Save image
    img_id = f"{uuid.uuid4()}_{image.filename}"
    image_path = os.path.join(UPLOADS, img_id)
    image.save(image_path)

    # Convert to PNG
    png_path = convert_to_png(image_path)

    # Read file bytes
    file_bytes = secret_file.read()

    # ENCRYPT (IMPORTANT FIX)
    result = encrypt(file_bytes, password)

    salt = result[0]
    encrypted = result[1]

    # Create payload
    payload = create_payload(
        filename=secret_file.filename,
        filetype=secret_file.content_type,
        salt=salt,
        encrypted_data=encrypted
    )

    # Capacity check
    capacity = get_image_capacity(png_path)

    if len(payload.encode("utf-8")) > capacity:
        return jsonify({"error": "Image too small for this file"}), 400

    # Output file
    output_name = f"stego_{uuid.uuid4()}.png"
    output_path = os.path.join(OUTPUTS, output_name)

    hide_data(png_path, payload, output_path)

    return jsonify({
        "status": "success",
        "download": f"/download/{output_name}"
    })


# -----------------------
# EXTRACT FILE
# -----------------------

@app.route("/api/extract/", methods=["POST"])
def extract():

    image = request.files.get("image")
    password = request.form.get("password")

    if not image or not password:
        return jsonify({"error": "Missing image or password"}), 400

    img_id = f"{uuid.uuid4()}_{image.filename}"
    image_path = os.path.join(UPLOADS, img_id)
    image.save(image_path)

    # Extract payload safely
    try:
        payload_str = extract_data(image_path)

        if not payload_str:
            return jsonify({"error": "No hidden data found"}), 400

        payload = parse_payload(payload_str)

        if not validate_payload(payload):
            return jsonify({"error": "Invalid payload"}), 400

    except Exception as e:
        return jsonify({
            "error": "Failed to read payload",
            "details": str(e)
        }), 400

    # Decrypt safely
    try:
        decrypted = decrypt(
            payload["encrypted_data"],
            password,
            payload["salt"]
        )
    except Exception:
        return jsonify({"error": "Wrong password or corrupted data"}), 400

    # FIX TYPE SAFETY
    if isinstance(decrypted, tuple):
        decrypted = decrypted[0]

    # Save file
    output_file = os.path.join(OUTPUTS, payload["filename"])

    with open(output_file, "wb") as f:
        f.write(decrypted)

    return jsonify({
        "status": "success",
        "filename": payload["filename"],
        "download": f"/download/{payload['filename']}"
    })

# -----------------------
# DOWNLOAD
# -----------------------
@app.route("/download/<path:filename>")
def download(filename):
    return send_from_directory(OUTPUTS, filename, as_attachment=True)


# -----------------------
# RUN
# -----------------------
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000, debug=True)