import Crypto
from Crypto import Random
from Crypto.Cipher import AES
from Crypto.Util import Padding
from typing import Dict
import hashlib


class security_Error(Exception):
    pass


_SALT: bytes = b'8_TuDUK9IpJKaM7NWkpSQcMlVh0ZoEmYdeIOjvItOSk='


def hash(data: bytes) -> bytes:
    if not isinstance(data, bytes):
        raise security_Error("Error in security.hash(): Invalid input type")
    return hashlib.sha256(_SALT + data).digest()


def gen_master_key(passwrd: bytes) -> bytes:
    if not isinstance(passwrd, bytes):
<<<<<<< HEAD
        raise security_Error(
            "Error in security.gen_master_key(): Invalid input type")
=======
        raise security_Error("Error in security.gen_master_key(): Invalid input type")
>>>>>>> 4c54057f4a3c5e764a96cae717e7ce3db61e0136
    enc_passwrd: bytes = hashlib.pbkdf2_hmac("sha256", passwrd, _SALT, 100000)
    return enc_passwrd


def gen_key() -> bytes:
    return Random.new().read(32)


def encrypt(text: bytes, key: bytes, iv: bytes) \
        -> Dict[str, bytes]:
    if not isinstance(text, bytes) \
            or not isinstance(key, bytes) or not isinstance(iv, bytes):
        raise security_Error("Error in security.encrypt(): Invalid input type")
<<<<<<< HEAD
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    if not isinstance(cipher, Crypto.Cipher._mode_cbc.CbcMode):
        raise security_Error(
            "Error in security.encrypt(): Invalid return type")
=======
    cipher: Crypto.Cipher._mode_cbc.CbcMode = AES.new(key, AES.MODE_CBC, iv=iv)
>>>>>>> 4c54057f4a3c5e764a96cae717e7ce3db61e0136

    checker1 = Padding.pad(text, AES.block_size)

    ct: bytes = cipher.encrypt(checker1)
    if isinstance(ct, bytes) and isinstance(iv, bytes):
        return {'ciphertext': ct, "iv": iv}
    raise security_Error("Error in security.encrypt(): Invalid output type")


def encrypt_new(text: bytes, key: bytes) -> Dict[str, bytes]:
    if not isinstance(text, bytes) or not isinstance(key, bytes):
        raise security_Error("Error in security.encrypt(): Invalid input type")
<<<<<<< HEAD
    cipher = AES.new(key, AES.MODE_CBC)
    if not isinstance(cipher, Crypto.Cipher._mode_cbc.CbcMode):
        raise security_Error(
            "Error in security.encrypt_new(): Invalid return type")
=======
    cipher: Crypto.Cipher._mode_cbc.CbcMode = AES.new(key, AES.MODE_CBC)
>>>>>>> 4c54057f4a3c5e764a96cae717e7ce3db61e0136

    checker1 = Padding.pad(text, AES.block_size)

    ct: bytes = cipher.encrypt(checker1)
    iv: bytes = cipher.iv
    if isinstance(ct, bytes) and isinstance(iv, bytes):
        return {'ciphertext': ct, "iv": iv}
    raise security_Error("Error in security.encrypt(): Invalid output type")


def decrypt(encrypted_data: Dict[str, bytes], key: bytes) -> bytes:
    ct: bytes = encrypted_data["ciphertext"]
    iv: bytes = encrypted_data["iv"]
    if not isinstance(ct, bytes) or not isinstance(iv, bytes) \
            or not isinstance(key, bytes):
        raise security_Error("Error in security.decrypt(): Invalid input type")

    cipher = AES.new(key, AES.MODE_CBC, iv)
    if not isinstance(cipher, Crypto.Cipher._mode_cbc.CbcMode):
        raise security_Error(
            "Error in security.encrypt_new(): Invalid return type")
    checker1 = Padding.unpad(
        cipher.decrypt(ct), AES.block_size)
    if not isinstance(checker1, bytes):
<<<<<<< HEAD
        raise security_Error(
            "Error in security.decrypt(): Invalid output type")
=======
        raise security_Error("Error in security.decrypt(): Invalid output type")
>>>>>>> 4c54057f4a3c5e764a96cae717e7ce3db61e0136
    return checker1
