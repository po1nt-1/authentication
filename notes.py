import security
import db
import os
import pickle
import subprocess
from typing import Union


def encrypt_text(login: str, master_key: bytes,
                 text: str) -> Union[bytes, int]:
    if not isinstance(login, str) or not isinstance(master_key, bytes) \
            or not isinstance(text, str):
        print("Error: Incorrect value type")
        return -1

    text_bytes = text.encode(encoding="utf-8")
    if not isinstance(text_bytes, bytes):
        print("Error: Incorrect text encoding")
        return -1

    checker1 = db.info(login)
    if checker1 == -1:
        print("Error: Incorrect value type")
        return -1
    info: Tuple[str, bytes, str, bytes, bytes] = tuple(checker1)

    if not isinstance(info[3], bytes) or not isinstance(info[4], bytes):
        print("Error: Incorrect value type")
        return -1
    encrypted_data: Dict[str, bytes] = {"ciphertext": info[3], "iv": info[4]}

    checker2 = security.decrypt(
        encrypted_data, master_key)
    if checker2 == -1:
        return -1
    key: bytes = bytes(checker2)

    checker3 = security.encrypt(text_bytes, key, info[4])
    if checker3 == -1:
        return -1
    ct: bytes = bytes(checker3["ciphertext"])
    if not isinstance(ct, bytes):
        print("Error: Incompatible return value type")
        return -1

    return ct


def decrypt_text(login: str, master_key: bytes, ct: bytes) -> Union[str, int]:
    if not isinstance(login, str) or not isinstance(master_key, bytes) \
            or not isinstance(ct, bytes):
        print("Error: Incorrect value type")
        return -1

    checker1 = db.info(login)
    if checker1 == -1:
        print("Error: Incorrect value type")
        return -1
    info: Tuple[str, bytes, str, bytes, bytes] = tuple(checker1)

    if not isinstance(info[3], bytes) or not isinstance(info[4], bytes):
        print("Error: Incorrect value type")
        return -1
    encrypted_data: Dict[str, bytes] = {"ciphertext": info[3], "iv": info[4]}

    checker2 = security.decrypt(encrypted_data, master_key)
    if checker2 == -1:
        return -1
    key: bytes = bytes(checker2)

    encrypted_text = {"ciphertext": ct, "iv": info[4]}

    checker3 = security.decrypt(encrypted_text, key)
    if checker3 == -1:
        return -1
    text: bytes = bytes(checker3)
    if not isinstance(text, bytes):
        print("Error: Incompatible return value type")
        return -1

    result = text.decode(encoding="utf-8")

    if not isinstance(result, str):
        print("Error: Incompatible return value type")
        return -1

    return result


def visual(path: str) -> int:
    path_ = path + '_temp'
    if os.name == 'posix':
        soft = ['kate', 'vim', 'geany', 'gedit', 'nano']
        for elem in soft:
            try:
                m = subprocess.run([elem, path_])
                return 0
            except FileNotFoundError:
                continue
    elif os.name == 'nt':
        m = subprocess.run(['notepad', path_])
        return 0

    return -1


def write(login: str, master_key: bytes, name: str) -> int:
    if not isinstance(login, str) or not isinstance(name, str) \
            or not isinstance(master_key, bytes):
        print("Error in notes.write(): Incompatible value type")
        return -1

    path_ = os.path.join("authentication/notes", login, name)
    if os.path.exists(path_):
        os.remove(path_)

    checker1 = visual(path_)
    if checker1 == -1:
        return -1
    with open(path_ + '_temp', "r", encoding="utf-8") as t:
        text: str = t.read()
    os.remove(path_ + '_temp')

    checker2 = encrypt_text(login, master_key, text)
    if checker2 == -1:
        return -1
    enc_text: bytes = bytes(checker2)

    with open(path_, "wb") as f:
        pickle.dump(enc_text, f)
    return 0


def read(login: str, master_key: bytes, name: str) -> int:
    if not isinstance(login, str) or not isinstance(name, str) \
            or not isinstance(master_key, bytes):
        print("Error in notes.write(): Incompatible value type")
        return -1

    path_ = os.path.join("authentication/notes", login, name)
    if not os.path.exists(path_):
        print("Error in notes.write(): Note does not exist")
        return -1

    enc_text = bytes()
    with open(path_, "rb") as f:
        try:
            while True:
                data: bytes = pickle.load(f)
                enc_text += data
        except EOFError:
            pass

    if not isinstance(enc_text, bytes):
        print("Error in notes.read(): Incompatible return value type")
        return -1

    checker1 = decrypt_text(login, master_key, enc_text)
    if checker1 == -1:
        return -1
    text: str = str(checker1)

    with open(path_ + '_temp', "w", encoding="utf-8") as t:
        t.write(text)

    checker2 = visual(path_)
    if checker2 == -1:
        return -1

    with open(path_ + '_temp', "r", encoding="utf-8") as t:
        new_text: str = t.read()

    os.remove(path_ + '_temp')

    checker3 = encrypt_text(login, master_key, new_text)
    if checker3 == -1:
        return -1
    new_enc_text: bytes = bytes(checker3)

    with open(path_, "wb") as f:
        pickle.dump(new_enc_text, f)
    return 0


def delete(login: str, name: str) -> int:
    if not isinstance(login, str) or not isinstance(name, str):
        print("Error in notes.write(): Incompatible value type")
        return -1

    path_ = os.path.join("authentication/notes", login, name)
    if os.path.exists(path_):
        os.remove(path_)
        return 0
    else:
        print("Error in delete.write(): Note does not exist")
        return -1


if __name__ == "__main__":
    pass
    print(write('admin', 'secret1', 'привет'.encode(
        encoding="utf-8"), mode="overwrite"))
    print(read('admin', 'secret1'))
    # print(delete('admin', 'secret1'))
