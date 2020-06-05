import security
import db
import os
import pickle
import subprocess
from typing import Dict, Tuple, Union, List


class notes_Error(Exception):
    pass


def _encrypt_text(login: str, master_key: bytes,
                  text: str) -> bytes:
    if not isinstance(login, str) or not isinstance(master_key, bytes) \
            or not isinstance(text, str):
        raise notes_Error("Error in notes._encrypt_text(): Invalid input type")

    text_bytes = text.encode(encoding="utf-8")
    if not isinstance(text_bytes, bytes):
        raise notes_Error(
            "Error in notes._encrypt_text(): Invalid text encoding")

    try:
        checker1: Union[Tuple[str, bytes, str,
                              bytes, bytes], None] = db.info(login)
        if checker1 is None:
            raise notes_Error(f"Error in notes._encrypt_text(): \
                        User with login {login} not found")
    except db.db_Error as e:
        raise notes_Error(str(e))
    info: Tuple[str, bytes, str, bytes, bytes] = checker1

    encrypted_data: Dict[str, bytes] = {
        "ciphertext": info[3], "iv": info[4]}

    try:
        checker2 = security.decrypt(encrypted_data, master_key)
    except security.security_Error as e:
        raise notes_Error(str(e))
    key: bytes = checker2

    try:
        checker3 = security.encrypt(text_bytes, key, info[4])
    except security.security_Error as e:
        raise notes_Error(str(e))
    ct: bytes = checker3["ciphertext"]
    if not isinstance(ct, bytes):
        raise notes_Error(
            "Error in notes._encrypt_text(): Invalid output type")
    return ct


def _decrypt_text(login: str, master_key: bytes, ct: bytes) -> str:
    if not isinstance(login, str) or not isinstance(master_key, bytes) \
            or not isinstance(ct, bytes):
        raise notes_Error("Error in notes._decrypt_text(): Invalid input type")

    try:
        checker1: Union[Tuple[str, bytes, str,
                              bytes, bytes], None] = db.info(login)
        if checker1 is None:
            raise notes_Error(f"Error in notes._encrypt_text(): \
                        User with login {login} not found")
    except db.db_Error as e:
        raise notes_Error(str(e))
    info: Tuple[str, bytes, str, bytes, bytes] = checker1

    encrypted_data: Dict[str, bytes] = {"ciphertext": info[3], "iv": info[4]}

    try:
        checker2 = security.decrypt(encrypted_data, master_key)
    except security.security_Error as e:
        raise notes_Error(str(e))
    key: bytes = checker2

    encrypted_text = {"ciphertext": ct, "iv": info[4]}

    try:
        checker3 = security.decrypt(encrypted_text, key)
    except security.security_Error as e:
        raise notes_Error(str(e))
    text: bytes = checker3

    result = text.decode(encoding="utf-8")

    if not isinstance(result, str):
        raise notes_Error(
            "Error in notes._decrypt_text(): Invalid output type")
    return result


def _visual(path: str) -> None:
    if not isinstance(path, str):
        raise notes_Error("Error in notes._visual(): Invalid input type")
    path_ = path + '_temp'
    if os.name == 'posix':
        soft = ['kate', 'vim', 'geany', 'gedit', 'nano']
        for elem in soft:
            try:
                m = subprocess.run([elem, path_])   # type: ignore
                return None
            except FileNotFoundError:
                continue
    elif os.name == 'nt':
        k = subprocess.run(['notepad', path_])  # type: ignore
        return None
    raise notes_Error(
        "Error in notes._visual(): Operating system not supported")


def write(login: str, master_key: bytes, name: str) -> None:
    if not isinstance(login, str) or not isinstance(name, str) \
            or not isinstance(master_key, bytes):
        raise notes_Error("Error in notes.write(): Invalid input type")

    path_ = os.path.join('authentication', 'notes', login, name)
    if os.path.exists(path_):
        os.remove(path_)

    try:
        _visual(path_)
    except notes_Error as e:
        raise notes_Error(str(e))
    if not os.path.exists(path_ + "_temp"):
        raise notes_Error(
            "Error in notes.write(): Invalid work of the text editor")

    with open(path_ + "_temp", 'r', encoding="utf-8") as t:
        text: str = t.read()
    os.remove(path_ + "_temp")

    try:
        checker2 = _encrypt_text(login, master_key, text)
    except notes_Error as e:
        raise notes_Error(str(e))
    enc_text: bytes = checker2

    with open(path_, "wb") as f:
        pickle.dump(enc_text, f)
    return None


def edit(login: str, master_key: bytes, name: str) -> None:
    if not isinstance(login, str) or not isinstance(name, str) \
            or not isinstance(master_key, bytes):
        raise notes_Error("Error in notes.edit(): Invalid input type")

    path_ = os.path.join('authentication', 'notes', login, name)
    if not os.path.exists(path_):
        raise notes_Error("Error in notes.edit(): Note does not exist")

    enc_text = bytes()
    with open(path_, "rb") as f:
        try:
            while True:
                data: bytes = pickle.load(f)
                enc_text += data
        except EOFError:
            pass

    try:
        checker1 = _decrypt_text(login, master_key, enc_text)
    except notes_Error as e:
        raise notes_Error(str(e))
    text: str = str(checker1)

    with open(path_ + '_temp', "w", encoding="utf-8") as t:
        t.write(text)

    try:
        _visual(path_)
    except notes_Error as e:
        raise notes_Error(str(e))

    with open(path_ + '_temp', "r", encoding="utf-8") as t:
        new_text: str = t.read()

    os.remove(path_ + '_temp')

    try:
        checker3 = _encrypt_text(login, master_key, new_text)
    except notes_Error as e:
        raise notes_Error(str(e))
    new_enc_text: bytes = checker3

    with open(path_, "wb") as f:
        pickle.dump(new_enc_text, f)
    return None


def note_list(login: str) -> Tuple[str, ...]:
    if not isinstance(login, str):
        raise notes_Error("Error in notes.note_list(): Invalid input type")

    path_ = os.path.join('authentication', 'notes', login)
    notes = tuple(os.listdir(path_))
    return notes


def delete(login: str, name: str) -> None:
    if not isinstance(login, str) or not isinstance(name, str):
        raise notes_Error("Error in notes.delete(): Invalid input type")

    path_ = os.path.join('authentication', 'notes', login, name)
    if os.path.exists(path_):
        os.remove(path_)
        return None
    else:
        raise notes_Error("Error in notes.delete(): Note does not exist")


def delete_all(login: str) -> None:
    if not isinstance(login, str):
        raise notes_Error("Error in notes.delete_all(): Invalid input type")

    path_ = os.path.join('authentication', 'notes', login)
    notes = tuple(os.listdir(path_))

    for note in notes:
        path_ = os.path.join('authentication', 'notes', login, note)
        if os.path.exists(path_):
            os.remove(path_)
        else:
            raise notes_Error(
                "Error in notes.delete_all(): Note does not exist")
    return None
