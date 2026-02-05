from PIL import Image
import pytesseract
import re

def extract_text(image_path):
    image = Image.open(image_path)
    text = pytesseract.image_to_string(image)
    return text

def extract_dob(text):
    """
    Tries to extract DOB from Aadhaar OCR text.
    Supports:
    - DOB: DD/MM/YYYY
    - DOB- DD-MM-YYYY
    - Year of Birth: YYYY
    """

    patterns = [
        r"D[O0]B\s*[:\-]?\s*(\d{2}\s*[/-]\s*\d{2}\s*[/-]\s*\d{4})",
        r"\b\d{2}\s*[/-]\s*\d{2}\s*[/-]\s*\d{4}\b",
        r"Year\s*of\s*Birth\s*[:\-]?\s*(\d{4})"
    ]

    for pattern in patterns:
        match = re.search(pattern, text, re.IGNORECASE)
        if match:
            return match.group(1) if match.lastindex else match.group()

    return None
