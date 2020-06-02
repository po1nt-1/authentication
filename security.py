from Crypto import Random
from Crypto.Cipher import AES
from Crypto.Util import Padding
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


def encrypt(text: bytes, key: bytes, iv: bytes) \
        -> Union[Dict[str, bytes], int]:
    if not isinstance(text, bytes) \
            or not isinstance(key, bytes) or not isinstance(iv, bytes):
        print("Error in security.encrypt(): Incompatible value type")
        return -1
    cipher: Crypto.Cipher._mode_cbc.CbcMode = AES.new(key, AES.MODE_CBC, iv=iv)

    checker1 = Padding.pad(text, AES.block_size)

    ct: bytes = cipher.encrypt(checker1)
    if isinstance(ct, bytes) and isinstance(iv, bytes):
        return {'ciphertext': ct, "iv": iv}
    else:
        print("Error in security.encrypt(): Incompatible return value type")
        return -1


def encrypt_new(text: bytes, key: bytes) -> Union[Dict[str, bytes], int]:
    if isinstance(text, bytes) is False \
            or isinstance(key, bytes) is False:
        print("Error in security.encrypt(): Incompatible value type")
        return -1
    cipher: Crypto.Cipher._mode_cbc.CbcMode = AES.new(key, AES.MODE_CBC)

    checker1 = Padding.pad(text, AES.block_size)

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
    checker1 = Padding.unpad(
        cipher.decrypt(ct), AES.block_size)

    return bytes(checker1)


if __name__ == "__main__":
    pass
