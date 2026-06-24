from stegano import lsb
from PIL import Image
import os


def convert_to_png(input_path):
    from PIL import Image
    import os

    img = Image.open(input_path)

    output_path = os.path.splitext(input_path)[0] + ".png"

    img = img.convert("RGB")
    img.save(output_path, "PNG")

    # REMOVE ORIGINAL FILE (prevents duplicates)
    if os.path.exists(input_path):
        os.remove(input_path)

    return output_path


def hide_data(image_path, payload, output_path):

    secret = lsb.hide(image_path, payload)
    secret.save(output_path)


def extract_data(image_path):

    data = lsb.reveal(image_path)

    if not data:
        raise Exception("No hidden payload found")

    return data


def get_image_capacity(image_path):

    img = Image.open(image_path)

    width, height = img.size

    # realistic LSB safe capacity (slightly reduced safety margin)
    return (width * height * 3) // 10