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


def _visual(path: str, flag: str = "") -> None:
    if not isinstance(path, str) or not isinstance(flag, str):
        raise notes_Error("Error in notes._visual(): Invalid input type")

    if os.name == "posix":
        path_temp = path + '_temp'
    elif os.name == "nt":
        path_temp = path[:-4] + '_temp' + ".txt"
    else:
        raise notes_Error(
            "Error in notes._visual(): Operating system not supported")

    soft = ['gedit', 'kate', 'mousepad', 'geany',  'vim', 'nano']
    for elem in soft:
        try:
            m = subprocess.run([elem, path_temp])   # type: ignore
            return None
        except FileNotFoundError:
            continue
    if flag == "write":
        with open(path_temp, 'w', encoding="utf-8") as bug_fix:
            pass

    k = subprocess.run(['notepad', path_temp])  # type: ignore
    return None


def write(login: str, master_key: bytes, name: str) -> None:
    if not isinstance(login, str) or not isinstance(name, str) \
            or not isinstance(master_key, bytes):
        raise notes_Error("Error in notes.write(): Invalid input type")

    if os.name == "posix":
        path_ = os.path.join('authentication', 'notes', login, name)
        path_temp = path_ + "_temp"
    elif os.name == "nt":
        path_ = os.path.join('authentication', 'notes', login, name + ".txt")
        path_temp = path_[:-4]
        path_temp += '_temp' + ".txt"
    else:
        raise notes_Error(
            "Error in notes.write(): Operating system not supported")

    if os.path.exists(path_):
        os.remove(path_)

    try:
        _visual(path_, "write")
    except notes_Error as e:
        raise notes_Error(str(e))

    if not os.path.exists(path_temp):
        raise notes_Error(
            "Error in notes.write(): Invalid work of the text editor")

    with open(path_temp, 'r', encoding="utf-8") as t:
        text: str = t.read()
    os.remove(path_temp)

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

    if os.name == "posix":
        path_ = os.path.join('authentication', 'notes', login, name)
        path_temp = path_ + "_temp"
    elif os.name == "nt":
        path_ = os.path.join('authentication', 'notes', login, name + ".txt")
        path_temp = path_[:-4]
        path_temp += '_temp' + ".txt"
    else:
        raise notes_Error(
            "Error in notes.edit(): Operating system not supported")

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

    with open(path_temp, "w", encoding="utf-8") as t:
        t.write(text)

    try:
        _visual(path_)
    except notes_Error as e:
        raise notes_Error(str(e))

    with open(path_temp, "r", encoding="utf-8") as t:
        new_text: str = t.read()

    os.remove(path_temp)

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

    if os.name == "posix" or os.name == "nt":
        path_ = os.path.join('authentication', 'notes', login)
    else:
        raise notes_Error(
            "Error in notes.note_list(): Operating system not supported")

    if os.name == "posix":
        notes: Tuple[str, ...] = tuple(os.listdir(path_))
    elif os.name == "nt":
        iter_notes = os.listdir(path_)
        notes_nt: List[str] = list()
        for note in iter_notes:
            notes_nt.append(note[:-4])
        notes = tuple(notes_nt)
    else:
        raise notes_Error(
            "Error in notes.note_list(): Operating system not supported")

    return notes


def delete(login: str, name: str) -> None:
    if not isinstance(login, str) or not isinstance(name, str):
        raise notes_Error("Error in notes.delete(): Invalid input type")

    if os.name == "posix":
        path_ = os.path.join('authentication', 'notes', login, name)
    elif os.name == "nt":
        path_ = os.path.join('authentication', 'notes', login, name + ".txt")
    else:
        raise notes_Error(
            "Error in notes.delete(): Operating system not supported")

    if os.path.exists(path_):
        os.remove(path_)
        return None
    else:
        raise notes_Error("Error in notes.delete(): Note does not exist")


def delete_all(login: str) -> None:
    if not isinstance(login, str):
        raise notes_Error("Error in notes.delete_all(): Invalid input type")

    if os.name == "posix" or os.name == "nt":
        path_ = os.path.join('authentication', 'notes', login)
    else:
        raise notes_Error(
            "Error in notes.delete_all(): Operating system not supported")

    notes = tuple(os.listdir(path_))

    for note in notes:
        if os.name == "posix" or os.name == "nt":
            path_ = os.path.join('authentication', 'notes', login, note)
        else:
            raise notes_Error(
                "Error in notes.delete_all(): Operating system not supported")

        if os.path.exists(path_):
            os.remove(path_)
        else:
            raise notes_Error(
                "Error in notes.delete_all(): Note does not exist")
    return None
