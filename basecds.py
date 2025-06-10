import json
from magika import Magika
import bleach
import re
import os
from datetime import datetime

'''You have two different domains in the same script here: Blue and Red. Seperate and expand as you see fit.'''

allowed_types_blue = [".pdf", ".docx", ".json"] #you can add or remove filetypes as you see fit, these are just examples.
blocked_types_blue = ["exe", "javascript", "shellscript"] #you can add or remove filetypes as you see fit, these are just examples.

allowed_types_red = [".pdf", ".docx", ".json"] #you can add or remove filetypes as you see fit, these are just examples.
blocked_types_red = ["exe", "javascript", "shellscript"] #you can add or remove filetypes as you see fit, these are just examples.

#Set you max file size here.
MAX_FILE_SIZE_MB = 25  # 25MB max size

#Feel free to add, delete, amend, play with suspicious patterns.
SUSPICIOUS_PATTERNS = [
    # Script injection
    r"<script.*?>.*?</script>",
    r"<iframe.*?>.*?</iframe>",
    r"<object.*?>.*?</object>",
    r"<embed.*?>.*?</embed>",
    r"<svg.*?>.*?</svg>",
    r"on\w+\s*=\s*['\"].*?['\"]",   # onload=, onclick= etc.
    r"javascript\s*:",
    r"data\s*:[^;]+;base64,",       # data URI payloads
    # SQL Injection
    r"(\\bSELECT\\b|\\bDROP\\b|\\bINSERT\\b|\\bDELETE\\b|\\bUPDATE\\b).*?(FROM|INTO|SET|WHERE)",
    r"(['\"]).*?--",               # comment injection
    r"(['\"]).*?(OR|AND)\\s+\\1.*?=\\1",  # tautologies
    # Shell command injection
    r"(\\||&&|;).*?(rm\\s+-rf|shutdown|reboot|mkfs|wget|curl|chmod|chown|scp|nc\\s)",
    r"eval\\s*\\(",
    r"exec\\s*\\(",
    r"base64\\s+-d",
    r"python\\s+-c\\s*['\"]",
    r"echo\\s+.*?\\|\\s+sh",       # pipe to shell
    # File manipulation
    r"file:\\/\\/",
    r"\\\\\\\\?\\\\",
    r"\\.\\.\\/\\.\\.",            # path traversal
    r"\\/etc\\/passwd",
    r"[A-Z]:\\\\",                 # Windows paths
    # Office macro indicators
    r"Auto(Open|Close)",
    r"CreateObject\\(",
    r"Shell\\.Run\\(",
    r"WScript\\.",
    r"ADODB\\.Stream",
    r"Win32_Process",
    r"Function\\s+Document_Open\\(",
    # Suspicious encoding or obfuscation
    r"[A-Za-z0-9+/]{200,}={0,2}",   # large base64 block
    r"\\x[a-fA-F0-9]{2}",          # hex encoding
    r"\\u00[a-fA-F0-9]{2}",        # unicode escapes
    r"document\\.write\\(",
    r"setTimeout\\(.*?eval",
]

'''We are using Magika, the AI file tool released by Google as it's very good! You can read up about it here: https://github.com/google/magika'''

# Initialise Magika once
magika = Magika()

#Handle bytes
def magika_bytes(b):
    return magika.identify_bytes(b)
  
#Handle file paths
def magika_path(p):
    return magika.identify_path(p)
  
#Handle files in stream (e.g. uploads)
def magika_stream(p):
    with open(p, 'rb') as f:
        return magika.identify_stream(f)

#Check the file size isn't over your max set above.
def check_size(path=None, data=None):
    if path:
        size_mb = os.path.getsize(path) / (1024 * 1024)
    elif data:
        size_mb = len(data) / (1024 * 1024)
    else:
        raise ValueError("No input for size check")
    if size_mb > MAX_FILE_SIZE_MB:
        raise ValueError(f"File size {size_mb:.2f}MB exceeds max allowed of {MAX_FILE_SIZE_MB}MB")
    return True

#Scan for suspicious patterns.
def scan_content(data):
    text = data.decode(errors='ignore')
    for pattern in SUSPICIOUS_PATTERNS:
        if re.search(pattern, text, re.IGNORECASE):
            raise ValueError(f"Suspicious pattern detected: {pattern}")
    return text

# The main function for file evaluation which uses all the helpers.
def evaluate_file(source_bytes=None, path=None, stream=False, blocked_types=None, confidence_threshold=0.75, blue_to_red=False):
    if source_bytes is None and path is None:
        raise ValueError("No file assessment possible: both bytes and path are None.")

    if source_bytes is None and not stream:
        check_size(path=path)
        result = magika_path(path)
        with open(path, 'rb') as f:
            file_data = f.read()
    elif path is None and not stream:
        check_size(data=source_bytes)
        result = magika_bytes(source_bytes)
        file_data = source_bytes
    elif path is not None and stream:
        check_size(path=path)
        result = magika_stream(path)
        with open(path, 'rb') as f:
            file_data = f.read()
    else:
        raise ValueError("Ambiguous input. Provide only one of bytes or path, with stream flag correctly set.")

    label = result.output.label
    score = result.score

    if score < confidence_threshold:
        raise ValueError(f"Low confidence ({score:.2f}) in type detection for: {label}")

    if label in blocked_types:
        raise ValueError(f"Disallowed file type: {label}")

    # Content scanning for red-to-blue
    if blue_to_red:
        cleaned = bleach.clean(scan_content(file_data))
        return label, score, cleaned
    else:
        scan_content(file_data)
        return label, score

# Use it one a blue client (low side).
def blue_call_on_magika(source_bytes=None, path=None, stream=False):
    return evaluate_file(source_bytes, path, stream, blocked_types=blocked_types_blue, confidence_threshold=0.75)

# Use it on a red client (high side).
def red_call_on_magika(source_bytes=None, path=None, stream=False):
    return evaluate_file(source_bytes, path, stream, blocked_types=blocked_types_red, confidence_threshold=0.7, red_to_blue=True)

# Sample test
def test():
    test_path = "./yourtestfile.js"
    try:
        label, score, *_ = red_call_on_magika(path=test_path, stream=False)
        print(f"PASS: {test_path} identified as {label} with score {score:.2f}")
    except ValueError as e:
        print(f"BLOCKED: {e}")

test()
