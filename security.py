from Crypto import Random
from Crypto.Cipher import AES
from typing import Dict
import hashlib


_SALT = b'8_TuDUK9IpJKaM7NWkpSQcMlVh0ZoEmYdeIOjvItOSk='


def pad(data: bytes, block_size: int) -> bytes:
    if isinstance(data, bytes) is False \
            or isinstance(block_size, int) is False:
        raise TypeError("Incompatible value type in security.pad()")
    padding_len = block_size - len(data) % block_size
    padding = bytes([padding_len]) * padding_len
    return data + padding


def unpad(padded_data: bytes, block_size: int) -> bytes:
    if isinstance(padded_data, bytes) is False \
            or isinstance(block_size, int) is False:
        raise TypeError("Incompatible value type in security.unpad()")
    pdata_len = len(padded_data)
    if pdata_len % block_size:
        raise ValueError("Input data is not padded")
    padding_len = padded_data[-1]
    if padding_len < 1 or padding_len > min(block_size, pdata_len):
        raise ValueError("Padding is incorrect.")
    if padded_data[-padding_len:] != bytes([padding_len]) * padding_len:
        raise ValueError("Padding is incorrect.")
    return padded_data[:-padding_len]


def hash(data: bytes) -> str:
    if isinstance(data, bytes) is False:
        raise TypeError("Incompatible value type in security.hash()")
    return hashlib.sha256(_SALT + data).hexdigest()


def gen_master_key(passwrd: bytes) -> bytes:
    if isinstance(passwrd, bytes) is False:
        raise TypeError("Incompatible value type in security.gen_master_key()")
    enc_passwrd = hashlib.pbkdf2_hmac('sha256', passwrd, _SALT, 100000)
    return enc_passwrd


def gen_key() -> bytes:
    return Random.new().read(32)


def encrypt(text: bytes, key: bytes) -> Dict[bytes, bytes]:
    if isinstance(text, bytes) is False \
            or isinstance(key, bytes) is False:
        raise TypeError("Incompatible value type in security.encrypt()")

    cipher = AES.new(key, AES.MODE_CBC)
    ct = bytes(cipher.encrypt(pad(text, AES.block_size)))
    iv = bytes(cipher.iv)
    result = {'ciphertext': ct, "iv": iv}
    if isinstance(ct, bytes) and isinstance(iv, bytes):
        return result
    else:
        raise TypeError("Incompatible return value type in security.encrypt()")


def decrypt(encrypted_data: Dict[str, bytes], key: bytes) -> bytes:
    ct = encrypted_data["ciphertext"]
    iv = encrypted_data["iv"]
    if isinstance(ct, bytes) is False \
            or isinstance(key, bytes) is False:
        raise TypeError("Incompatible value type in security.decrypt()")

    cipher = AES.new(key, AES.MODE_CBC, iv)
    text = unpad(cipher.decrypt(ct), AES.block_size)
    return text


if __name__ == "__main__":
    pass
