from Crypto import Random
from Crypto.Cipher import AES
from typing import Dict, Union
import hashlib


_SALT: bytes = b'8_TuDUK9IpJKaM7NWkpSQcMlVh0ZoEmYdeIOjvItOSk='


def hash(data: bytes) -> Union[bytes, int]:
    if isinstance(data, bytes) is False:
        print("Error in security.hash(): Incompatible value type")
        return -1
    return hashlib.sha256(_SALT + data).digest()


def gen_master_key(passwrd: bytes) -> Union[bytes, int]:
    if isinstance(passwrd, bytes) is False:
        print("Error in security.gen_master_key(): Incompatible value type")
        return -1
    enc_passwrd: bytes = hashlib.pbkdf2_hmac("sha256", passwrd, _SALT, 100000)
    return enc_passwrd


def gen_key() -> bytes:
    return Random.new().read(32)


def pad(data: bytes, block_size: int) -> Union[bytes, int]:
    if isinstance(data, bytes) is False \
            or isinstance(block_size, int) is False:
        print("Error in security.pad(): Incompatible value type")
        return -1
    padding_len: int = block_size - len(data) % block_size
    padding: bytes = bytes(bytes([padding_len]) * padding_len)
    return data + padding


def unpad(padded_data: bytes, block_size: int) -> Union[bytes, int]:
    if isinstance(padded_data, bytes) is False \
            or isinstance(block_size, int) is False:
        print("Error in security.unpad(): Incompatible value type")
        return -1
    pdata_len: int = len(padded_data)
    if pdata_len % block_size:
        print("Error in security.unpad(): Input data is not padded")
        return -1
    # padding_len: int = int.from_bytes(bytes(padded_data[-1]), byteorder='little')
    padding_len: int = padded_data[-1]
    if padding_len < 1 or padding_len > min(block_size, pdata_len):
        print("Error in security.unpad(): Padding is incorrect.")
        return -1
    if padded_data[-padding_len:] != bytes([padding_len]) * padding_len:
        print("Error in security.unpad(): Padding is incorrect.")
        return -1
    return padded_data[:-padding_len]


def encrypt(text: bytes, key: bytes) -> Union[Dict[str, bytes], int]:
    if isinstance(text, bytes) is False \
            or isinstance(key, bytes) is False:
        print("Error in security.encrypt(): Incompatible value type")
        return -1
    cipher: Crypto.Cipher._mode_cbc.CbcMode = AES.new(key, AES.MODE_CBC)

    checker1: Union[bytes, int] = pad(text, AES.block_size)
    if checker1 == -1:
        return -1
    ct: bytes = cipher.encrypt(checker1)
    iv: bytes = cipher.iv
    if isinstance(ct, bytes) and isinstance(iv, bytes):
        return {'ciphertext': ct, "iv": iv}
    else:
        print("Error in security.encrypt(): Incompatible return value type")
        return -1


def decrypt(encrypted_data: Dict[str, bytes], key: bytes) -> Union[bytes, int]:
    ct: bytes = encrypted_data["ciphertext"]
    iv: bytes = encrypted_data["iv"]
    if not isinstance(ct, bytes) or not isinstance(iv, bytes) \
            or not isinstance(key, bytes):
        print("Error in security.decrypt(): Incompatible value type")
        return -1

    cipher: Crypto.Cipher._mode_cbc.CbcMode = AES.new(key, AES.MODE_CBC, iv)
    checker1: Union[bytes, int] = unpad(cipher.decrypt(ct), AES.block_size)
    if checker1 == -1:
        return -1
    return bytes(checker1)


if __name__ == "__main__":
    pass
