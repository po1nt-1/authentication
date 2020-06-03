import security
import db
import os
import pickle
import subprocess
from typing import Dict, Tuple


class Error(Exception):
    pass


def encrypt_text(login: str, master_key: bytes,
                 text: str) -> bytes:
    if not isinstance(login, str) or not isinstance(master_key, bytes) \
            or not isinstance(text, str):
        raise Error("Error in notes.encrypt_text(): Invalid input type")

    text_bytes = text.encode(encoding="utf-8")
    if not isinstance(text_bytes, bytes):
        raise Error("Error in notes.encrypt_text(): Incorrect text encoding")

    try:
        checker1 = db.info(login)
        if checker1 is None:
            raise Error(f"Error in notes.encrypt_text(): \
                        User with login {login} not found")
    except Error as e:
        raise Error(str(e))
    info: Tuple[object, ...] = tuple(checker1)

    encrypted_data: Dict[str, bytes] = {"ciphertext": info[3], "iv": info[4]}

    try:
        checker2 = security.decrypt(encrypted_data, master_key)
    except Error as e:
        raise Error(str(e))
    key: bytes = checker2

    try:
        checker3 = security.encrypt(text_bytes, key, info[4])
    except Error as e:
        raise Error(str(e))
    ct: bytes = checker3["ciphertext"]
    if not isinstance(ct, bytes):
        raise Error("Error in notes.encrypt_text(): Invalid output type")
    return ct


def decrypt_text(login: str, master_key: bytes, ct: bytes) -> str:
    if not isinstance(login, str) or not isinstance(master_key, bytes) \
            or not isinstance(ct, bytes):
        raise Error("Error in notes.decrypt_text(): Invalid input type")

    try:
        checker1 = db.info(login)
        if checker1 is None:
            raise Error(f"Error in notes.encrypt_text(): \
                        User with login {login} not found")
    except Error as e:
        raise Error(str(e))
    info: Tuple[object, ...] = tuple(checker1)

    encrypted_data: Dict[str, bytes] = {"ciphertext": info[3], "iv": info[4]}

    try:
        checker2 = security.decrypt(encrypted_data, master_key)
    except Error as e:
        raise Error(str(e))
    key: bytes = checker2

    encrypted_text = {"ciphertext": ct, "iv": info[4]}

    try:
        checker3 = security.decrypt(encrypted_text, key)
    except Error as e:
        raise Error(str(e))
    text: bytes = checker3

    result = text.decode(encoding="utf-8")

    if not isinstance(result, str):
        raise Error("Error in notes.decrypt_text(): Invalid output type")
    return result


def visual(path: str) -> None:
    if not isinstance(path, str):
        raise Error("Error in notes.visual(): Invalid input type")
    path_ = path + '_temp'
    if os.name == 'posix':
        soft = ['kate', 'vim', 'geany', 'gedit', 'nano']
        for elem in soft:
            try:
                m = subprocess.run([elem, path_])
                return None
            except FileNotFoundError:
                continue
    elif os.name == 'nt':
        m = subprocess.run(['notepad', path_])
        return None
    raise Error("Error in notes.visual(): Operating system not supported")


def write(login: str, master_key: bytes, name: str) -> None:
    if not isinstance(login, str) or not isinstance(name, str) \
            or not isinstance(master_key, bytes):
        raise Error("Error in notes.write(): Invalid input type")

    path_ = os.path.join("authentication/notes", login, name)
    if os.path.exists(path_):
        os.remove(path_)

    try:
        visual(path_)
    except Error as e:
        raise Error(str(e))
    with open(path_ + '_temp', "r", encoding="utf-8") as t:
        text: str = t.read()
    os.remove(path_ + '_temp')

    try:
        checker2 = encrypt_text(login, master_key, text)
    except Error as e:
        raise Error(str(e))
    enc_text: bytes = checker2

    with open(path_, "wb") as f:
        pickle.dump(enc_text, f)
    return None


def read(login: str, master_key: bytes, name: str) -> None:
    if not isinstance(login, str) or not isinstance(name, str) \
            or not isinstance(master_key, bytes):
        raise Error("Error in notes.read(): Invalid input type")

    path_ = os.path.join("authentication/notes", login, name)
    if not os.path.exists(path_):
        raise Error("Error in notes.read(): Note does not exist")

    enc_text = bytes()
    with open(path_, "rb") as f:
        try:
            while True:
                data: bytes = pickle.load(f)
                enc_text += data
        except EOFError:
            pass

    try:
        checker1 = decrypt_text(login, master_key, enc_text)
    except Error as e:
        raise Error(str(e))
    text: str = str(checker1)

    with open(path_ + '_temp', "w", encoding="utf-8") as t:
        t.write(text)

    try:
        visual(path_)
    except Error as e:
        raise Error(str(e))

    with open(path_ + '_temp', "r", encoding="utf-8") as t:
        new_text: str = t.read()

    os.remove(path_ + '_temp')

    try:
        checker3 = encrypt_text(login, master_key, new_text)
    except Error as e:
        raise Error(str(e))
    new_enc_text: bytes = checker3

    with open(path_, "wb") as f:
        pickle.dump(new_enc_text, f)
    return None


def delete(login: str, name: str) -> None:
    if not isinstance(login, str) or not isinstance(name, str):
        raise Error("Error in notes.delete(): Invalid input type")

    path_ = os.path.join("authentication/notes", login, name)
    if os.path.exists(path_):
        os.remove(path_)
        return None
    else:
        raise Error("Error in notes.delete(): Note does not exist")
