import unittest
import base64
import gzip
import hashlib
import hmac
import asyncio
from jwt_hacker.decoder import *
from cryptography.hazmat.primitives.asymmetric import rsa, padding, ec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.hmac import HMAC
from cryptography.hazmat.primitives.padding import PKCS7
from cryptography.hazmat.backends import default_backend

class AsyncTestDecoder(unittest.IsolatedAsyncioTestCase):

    async def async_test(self, func, *args):
        return await asyncio.to_thread(func, *args)

    async def test_decode_base64(self):
        result = await self.async_test(decode_base64, "SGVsbG8=")
        self.assertEqual(result, "Hello")
        result_invalid = await self.async_test(decode_base64, "InvalidBase64")
        self.assertIsNone(result_invalid)

    async def test_hash_sha256(self):
        result = await self.async_test(hash_sha256, "test")
        self.assertEqual(result, hashlib.sha256(b"test").hexdigest())

    async def test_hash_sha3(self):
        result = await self.async_test(hash_sha3_256, "test")
        self.assertEqual(result, hashlib.sha3_256(b"test").hexdigest())

    async def test_verify_hs256(self):
        header = base64.urlsafe_b64encode(b'{"alg":"HS256","typ":"JWT"}').decode().rstrip("=")
        payload = base64.urlsafe_b64encode(b'{"sub":"1234567890","name":"John Doe","iat":1516239022}').decode().rstrip("=")
        secret = "secret"
        signature = hmac.new(secret.encode(), f"{header}.{payload}".encode(), hashlib.sha256).digest()
        jwt = f"{header}.{payload}.{base64.urlsafe_b64encode(signature).decode().rstrip('=')}"
        result = await self.async_test(verify_hs256, jwt, secret)
        self.assertTrue(result)
        result_invalid = await self.async_test(verify_hs256, jwt, "wrongsecret")
        self.assertFalse(result_invalid)

    async def test_verify_rs256(self):
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        public_key = private_key.public_key()

        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode()

        header = base64.urlsafe_b64encode(b'{"alg":"RS256","typ":"JWT"}').decode().rstrip("=")
        payload = base64.urlsafe_b64encode(b'{"sub":"1234567890","name":"John Doe","iat":1516239022}').decode().rstrip("=")

        message = f"{header}.{payload}".encode()
        signature = private_key.sign(
            message,
            padding.PKCS1v15(),
            hashes.SHA256(),
        )
        jwt = f"{header}.{payload}.{base64.urlsafe_b64encode(signature).decode().rstrip('=')}"

        result = await self.async_test(verify_rs256, jwt, public_pem)
        self.assertTrue(result)

        wrong_private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        wrong_public_pem = wrong_private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode()
        result_invalid = await self.async_test(verify_rs256, jwt, wrong_public_pem)
        self.assertFalse(result_invalid)

    async def test_aes_encryption(self):
        key = b"\x00" * 32
        iv = b"\x01" * 16
        data = b"Hello, AES!"
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())

        encryptor = cipher.encryptor()
        padder = PKCS7(algorithms.AES.block_size).padder()
        padded_data = padder.update(data) + padder.finalize()
        encrypted = encryptor.update(padded_data) + encryptor.finalize()

        decryptor = cipher.decryptor()
        unpadder = PKCS7(algorithms.AES.block_size).unpadder()
        decrypted_padded = decryptor.update(encrypted) + decryptor.finalize()
        decrypted = unpadder.update(decrypted_padded) + unpadder.finalize()

        self.assertEqual(decrypted, data)

    async def test_ecdsa_signature(self):
        private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
        public_key = private_key.public_key()

        data = b"ECDSA test message"
        signature = private_key.sign(
            data,
            ec.ECDSA(hashes.SHA256())
        )

        try:
            public_key.verify(
                signature,
                data,
                ec.ECDSA(hashes.SHA256())
            )
            verified = True
        except Exception:
            verified = False

        self.assertTrue(verified)

if __name__ == "__main__":
    asyncio.run(unittest.main())
