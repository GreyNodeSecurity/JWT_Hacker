import base64
import hashlib
import hmac
import zlib
import gzip
import codecs
import binascii
import asyncio
from cryptography.hazmat.primitives.asymmetric import rsa, padding, ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.hmac import HMAC
from cryptography.hazmat.primitives.padding import PKCS7
from cryptography.hazmat.backends import default_backend

# Async decoding functions
async def decode_base64(data):
    try:
        return base64.urlsafe_b64decode(data + '===').decode('utf-8')
    except Exception:
        return None

async def decode_base58(data):
    try:
        alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
        base_count = len(alphabet)
        decoded = 0
        for char in data:
            decoded = decoded * base_count + alphabet.index(char)

        byte_array = []
        while decoded > 0:
            byte_array.append(decoded % 256)
            decoded //= 256
        byte_array.reverse()

        return bytes(byte_array).decode("utf-8").capitalize()
    except Exception:
        return None

async def decode_rot13(data):
    try:
        return codecs.decode(data, 'rot_13')
    except Exception:
        return None

async def decompress_gzip(data):
    try:
        return gzip.decompress(base64.b64decode(data)).decode('utf-8')
    except Exception:
        return None

async def decompress_zlib(data):
    try:
        return zlib.decompress(base64.b64decode(data)).decode('utf-8')
    except Exception:
        return None

async def hash_md5(data):
    try:
        return hashlib.md5(data.encode()).hexdigest()
    except Exception:
        return None

async def hash_sha256(data):
    try:
        return hashlib.sha256(data.encode()).hexdigest()
    except Exception:
        return None

async def hash_sha1(data):
    try:
        return hashlib.sha1(data.encode()).hexdigest()
    except Exception:
        return None

async def decode_hex(data):
    try:
        return bytes.fromhex(data).decode('utf-8')
    except Exception:
        return None

async def decode_binary(data):
    try:
        return ''.join(chr(int(data[i:i+8], 2)) for i in range(0, len(data), 8))
    except Exception:
        return None

async def decode_url(data):
    try:
        from urllib.parse import unquote
        return unquote(data)
    except Exception:
        return None

async def decode_ascii85(data):
    try:
        if data.startswith("<~") and data.endswith("~>"):
            data = data[2:-2]
        decoded = base64.a85decode(data).decode("utf-8")
        return decoded
    except Exception:
        return None

async def decode_base32(data):
    try:
        return base64.b32decode(data).decode('utf-8')
    except Exception:
        return None

async def decode_base16(data):
    try:
        return base64.b16decode(data).decode('utf-8')
    except Exception:
        return None

async def decode_unicode_escape(data):
    try:
        return data.encode().decode('unicode_escape')
    except Exception:
        return None

async def decode_base91(data):
    try:
        import base91
        return base91.decode(data).decode('utf-8')
    except Exception:
        return None

async def decode_morse(data):
    try:
        morse_dict = {".-": "A", "-...": "B", "-.-.": "C", "-..": "D", ".": "E", "..-.": "F",
                      "--.": "G", "....": "H", "..": "I", ".---": "J", "-.-": "K", ".-..": "L",
                      "--": "M", "-.": "N", "---": "O", ".--.": "P", "--.-": "Q", ".-.": "R",
                      "...": "S", "-": "T", "..-": "U", "...-": "V", ".--": "W", "-..-": "X",
                      "-.--": "Y", "--..": "Z", "-----": "0", ".----": "1", "..---": "2", "...--": "3",
                      "....-": "4", ".....": "5", "-....": "6", "--...": "7", "---..": "8", "----.": "9"}
        return ''.join(morse_dict[char] for char in data.split(' '))
    except Exception:
        return None

async def decode_punycode(data):
    try:
        return data.encode('ascii').decode('punycode')
    except Exception:
        return None

async def verify_hs256(jwt, secret):
    try:
        header, payload, signature = jwt.split('.')
        signature_check = hmac.new(
            key=secret.encode(),
            msg=f"{header}.{payload}".encode(),
            digestmod=hashlib.sha256
        ).digest()
        expected_signature = base64.urlsafe_b64encode(signature_check).rstrip(b'=').decode()
        return signature == expected_signature
    except Exception:
        return False

async def verify_rs256(jwt, public_key):
    try:
        header, payload, signature = jwt.split('.')
        signature = base64.urlsafe_b64decode(signature + '===')
        rsa_key = rsa.RSAPublicKey.load_pem(public_key.encode())
        rsa_key.verify(
            signature,
            f"{header}.{payload}".encode(),
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False

async def hash_sha3_256(data):
    try:
        return hashlib.sha3_256(data.encode()).hexdigest()
    except Exception:
        return None

async def encrypt_aes(data, key, iv):
    try:
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        padder = PKCS7(algorithms.AES.block_size).padder()
        padded_data = padder.update(data) + padder.finalize()
        return encryptor.update(padded_data) + encryptor.finalize()
    except Exception:
        return None

async def decrypt_aes(encrypted, key, iv):
    try:
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        unpadder = PKCS7(algorithms.AES.block_size).unpadder()
        decrypted_padded = decryptor.update(encrypted) + decryptor.finalize()
        return unpadder.update(decrypted_padded) + unpadder.finalize()
    except Exception:
        return None

# Decoding operation mapping
operations = {
    "Base64": decode_base64,
    "Base58": decode_base58,
    "ROT13": decode_rot13,
    "Gzip": decompress_gzip,
    "Zlib": decompress_zlib,
    "MD5 Hash": hash_md5,
    "SHA-256 Hash": hash_sha256,
    "SHA-1 Hash": hash_sha1,
    "Hexadecimal": decode_hex,
    "Binary": decode_binary,
    "URL Encoding": decode_url,
    "Ascii85": decode_ascii85,
    "Base32": decode_base32,
    "Base16": decode_base16,
    "Unicode Escape": decode_unicode_escape,
    "Base91": decode_base91,
    "Morse": decode_morse,
    "Punycode": decode_punycode,
    "HS256 Verify": verify_hs256,
    "RS256 Verify": verify_rs256,
    "SHA3-256 Hash": hash_sha3_256
}
