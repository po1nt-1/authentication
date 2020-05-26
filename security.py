from Crypto import Random
from Crypto.Cipher import AES
from typing import Dict, Union
import hashlib


_SALT = b'8_TuDUK9IpJKaM7NWkpSQcMlVh0ZoEmYdeIOjvItOSk='


def hash(data: bytes) -> Union[bytes, int]:
    if isinstance(data, bytes) is False:
        print("Error in security.hash(): Incompatible value type")
        return -1
    return hashlib.sha256(_SALT + data).digest()


def gen_master_key(passwrd: bytes) -> Union[bytes, int]:
    if isinstance(passwrd, bytes) is False:
        print("Error in security.gen_master_key(): Incompatible value type")
        return -1
    enc_passwrd = hashlib.pbkdf2_hmac('sha256', passwrd, _SALT, 100000)
    return enc_passwrd


def gen_key() -> bytes:
    return Random.new().read(32)


def pad(data: bytes, block_size: int) -> Union[bytes, int]:
    if isinstance(data, bytes) is False \
            or isinstance(block_size, int) is False:
        print("Error in security.pad(): Incompatible value type")
        return -1
    padding_len = block_size - len(data) % block_size
    padding = bytes([padding_len]) * padding_len
    return data + padding


def unpad(padded_data: bytes, block_size: int) -> Union[bytes, int]:
    if isinstance(padded_data, bytes) is False \
            or isinstance(block_size, int) is False:
        print("Error in security.unpad(): Incompatible value type")
        return -1
    pdata_len = len(padded_data)
    if pdata_len % block_size:
        print("Error in security.unpad(): Input data is not padded")
        return -1
    padding_len = padded_data[-1]
    if padding_len < 1 or padding_len > min(block_size, pdata_len):
        print("Error in security.unpad(): Padding is incorrect.")
        return -1
    if padded_data[-padding_len:] != bytes([padding_len]) * padding_len:
        print("Error in security.unpad(): Padding is incorrect.")
        return -1
    return padded_data[:-padding_len]


def encrypt(text: bytes, key: bytes) -> Union[Dict[bytes, bytes], int]:
    if isinstance(text, bytes) is False \
            or isinstance(key, bytes) is False:
        print("Error in security.encrypt(): Incompatible value type")
        return -1

    cipher = AES.new(key, AES.MODE_CBC)
    ct = bytes(cipher.encrypt(pad(text, AES.block_size)))
    iv = bytes(cipher.iv)
    result = {'ciphertext': ct, "iv": iv}
    if isinstance(ct, bytes) and isinstance(iv, bytes):
        return result
    else:
        print("Error in security.encrypt(): Incompatible return value type")
        return -1


def decrypt(encrypted_data: Dict[str, bytes], key: bytes) -> Union[bytes, int]:
    ct = encrypted_data["ciphertext"]
    iv = encrypted_data["iv"]
    if isinstance(ct, bytes) is False \
            or isinstance(key, bytes) is False:
        print("Error in security.decrypt(): Incompatible value type")
        return -1

    cipher = AES.new(key, AES.MODE_CBC, iv)
    text = unpad(cipher.decrypt(ct), AES.block_size)
    return text


if __name__ == "__main__":
    p = 'PJKJnja'.encode(encoding="utf-8")
    print(hash(p))
