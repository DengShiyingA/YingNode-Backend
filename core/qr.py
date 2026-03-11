from pathlib import Path
import uuid
import qrcode


def make_qr(content: str, output_dir: str = 'static/qrcodes') -> str:
    Path(output_dir).mkdir(parents=True, exist_ok=True)
    filename = f"{uuid.uuid4().hex}.png"
    file_path = Path(output_dir) / filename

    img = qrcode.make(content)
    img.save(file_path)
    return str(file_path)
