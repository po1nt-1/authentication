import db
import notes
import security
import os
import shutil
from typing import Dict, Tuple, List


class Error(Exception):
    pass


_ALLOWED_CHARACTERS: str = "ZFyt2NebDRMlJUGm[№Q1AVHspK-PXI8douwB" + \
    "T~4O5_zSWi7rLxa]90k(3vgq!6f})Ej{nCcYh"


def create_account() -> int:
    print("REGISTRATION")
    login: str = input("Enter your login: ")
    if len(login) < 1 or not isinstance(login, str):
        raise Error("Error in main.create_account(): Incorrect login")
    if len(login) > 100:
        raise Error(
            f"Error in main.create_account(): Login too long " +
            "(len: {len(login)}).\nMax length 100")
    error_list: List[str] = list()
    for elem in login:
        if elem not in _ALLOWED_CHARACTERS:
            error_list.append(elem)
    if len(error_list) != 0:
        raise Error(
            f"Error in main.create_account(): '{''.join(error_list)}' " +
            "is not allowed")

    try:
        checker1 = db.info(login)
        if checker1 is not None:
            raise Error(
                "Error in main.create_account(): A user with this login " +
                "is already registered")
    except Error as e:
        raise Error(str(e))

    password: str = input("Enter your password: ")
    if len(password) < 1 or not isinstance(login, str):
        raise Error("Error in main.create_account(): Incorrect password")
    for elem in password:
        if elem not in _ALLOWED_CHARACTERS:
            error_list.append(elem)
    if len(error_list) != 0:
        raise Error(
            f"Error in main.create_account(): '{''.join(error_list)}' " +
            "is not allowed")

    password_bytes: bytes = password.encode(encoding="utf-8")

    try:
        checker2 = security.gen_master_key(password_bytes)
    except Error as e:
        raise Error(str(e))
    master_key: bytes = checker2

    try:
        checker3 = security.hash(password_bytes)
    except Error as e:
        raise Error(str(e))
    password_bytes_hash: bytes = checker3

    dirr: str = os.path.join("authentication", "notes", login)

    if os.path.exists(dirr):
        shutil.rmtree(dirr)
    os.mkdir(dirr)

    key: bytes = security.gen_key()
    try:
        checker4 = security.encrypt_new(key, master_key)
    except Error as e:
        raise Error(str(e))
    enc_key_with_iv: Dict[str, bytes] = dict(checker4)
    enc_key: bytes = enc_key_with_iv["ciphertext"]
    iv: bytes = enc_key_with_iv["iv"]

    db.insert(login, password_bytes_hash, dirr, enc_key, iv)
    print("Account creation completed successfully")


def auth() -> Tuple[str, bytes]:
    print("AUTHENTICATION")
    login: str = input("Enter your login: ")
    if len(login) < 1 or not isinstance(login, str):
        raise Error("Error in main.auth(): Incorrect login")
    error_list: List[str] = list()
    for elem in login:
        if elem not in _ALLOWED_CHARACTERS:
            error_list.append(elem)
    if len(error_list) != 0:
        raise Error(
            f"Error in main.auth(): '{''.join(error_list)}' is not allowed")

    try:
        checker1 = db.info(login)
        if checker1 is None:
            raise Error(
                "Error in main.auth(): A user with this login " +
                " is not registered")
    except Error as e:
        raise Error(str(e))

    password: str = input("Enter your password: ")
    if len(password) < 1 or not isinstance(login, str):
        raise Error("Error in main.auth(): Incorrect password")
    for elem in password:
        if elem not in _ALLOWED_CHARACTERS:
            error_list.append(elem)
    if len(error_list) != 0:
        raise Error(
            f"Error in main.auth(): '{''.join(error_list)}' is not allowed")

    dirr: str = os.path.join("authentication", "notes", login)
    if not os.path.exists(dirr):
        os.mkdir(dirr)

    password_bytes: bytes = password.encode(encoding="utf-8")

    try:
        checker2 = security.gen_master_key(password_bytes)
    except Error as e:
        raise Error(str(e))
    master_key: bytes = checker2

    try:
        checker3 = security.hash(password_bytes)
    except Error as e:
        raise Error(str(e))
    password_bytes_hash: bytes = checker3

    info: Tuple[object, ...] = tuple(checker1)
    password_bytes_hash_orig = info[1]

    if password_bytes_hash != password_bytes_hash_orig:
        raise Error("Error in main.auth(): Wrong password")
    print("Authorization completed successfully")

    if not isinstance(login, str) or not isinstance(master_key, bytes):
        raise Error("Error in main.auth(): Invalid output type")
    return (login, master_key)


def delete_account(login: str) -> None:
    try:
        checker1 = db.info(login)
        if checker1 is None:
            raise Error(
                "Error in main.delete_account(): A user with this login " +
                "is not registered")
    except Error as e:
        raise Error(str(e))
    info: Tuple[object, ...] = tuple(checker1)

    dirr = info[2]

    if os.path.exists(dirr):
        shutil.rmtree(dirr)

    try:
        checker2 = db.cut(login)
    except Error as e:
        raise Error(str(e))

    print("Account deletion completed successfully")
    return None


def change_key(login: str, master_key: bytes) -> None:
    try:
        checker1 = db.info(login)
        if checker1 is None:
            raise Error(
                "Error in main.change_key(): A user with this login " +
                "is not registered")
    except Error as e:
        raise Error(str(e))
    info: Tuple[object, ...] = tuple(checker1)

    encrypted_data: Dict[str, bytes] = {"ciphertext": info[3], "iv": info[4]}

    try:
        checker2: bytes = security.decrypt(encrypted_data, master_key)
    except Error as e:
        raise Error(str(e))
    old_key: object = checker2

    key: bytes = security.gen_key()

    try:
        checker4 = security.encrypt_new(key, master_key)
    except Error as e:
        raise Error(str(e))
    enc_key: bytes = checker4["ciphertext"]
    iv: bytes = checker4["iv"]

    try:
        checker6 = db.update(login=login, enc_key=enc_key, iv=iv)
    except Error as e:
        raise Error(str(e))

    print("The key change was successful")
    return None


def change_pass(login: str, old_master_key: bytes) -> None:
    try:
        checker1 = db.info(login)
        if checker1 is None:
            raise Error(
                "Error in main.change_pass(): A user with this login " +
                "is not registered")
    except Error as e:
        raise Error(str(e))
    info: Tuple[object, ...] = tuple(checker1)

    password: str = input("Enter your new password: ")
    if len(password) < 1 or not isinstance(login, str):
        raise Error("Error in main.change_pass(): Incorrect password")
    error_list: List[str] = list()
    for elem in password:
        if elem not in _ALLOWED_CHARACTERS:
            error_list.append(elem)
    if len(error_list) != 0:
        raise Error(
            f"Error in main.change_pass(): '{''.join(error_list)}' " +
            "is not allowed")
    password_bytes: bytes = password.encode(encoding="utf-8")

    encrypted_data: Dict[str, bytes] = {"ciphertext": info[3], "iv": info[4]}

    try:
        checker2: bytes = security.decrypt(encrypted_data, old_master_key)
    except Error as e:
        raise Error(str(e))
    key: bytes = checker2

    try:
        checker3 = security.gen_master_key(password_bytes)
    except Error as e:
        raise Error(str(e))
    master_key_new: bytes = checker3

    try:
        checker4 = security.encrypt(key, master_key_new, info[4])
    except Error as e:
        raise Error(str(e))
    enc_key = checker4["ciphertext"]

    try:
        checker5 = security.hash(password_bytes)
    except Error as e:
        raise Error(str(e))
    password_bytes_hash: bytes = checker5

    try:
        checker6 = db.update(
            login=login, hash=password_bytes_hash, enc_key=enc_key)
    except Error as e:
        raise Error(str(e))

    print("Password change was successful")
    return None


def user_interface() -> None:
    pass


if __name__ == "__main__":
    while True:
        #       создать директорию с заметками
        path = os.path.join("authentication", "notes")
        if not os.path.exists(path):
            os.mkdir(path)

        try:
            print(db.open_db())
        except Error as e:
            print(str(e))
            break  # continue

        try:
            print(db.create_table())
        except Error as e:
            print(str(e))
            break  # continue

        #       создать акк
        # try:
        #     print(create_account())
        # except Error as e:
        #     print(str(e))
        #     break  # continue

        #       авторизация и сохранение выхлопа
        try:
            cache: Tuple[str, bytes] = auth()
        except Error as e:
            print(str(e))
            break  # continue
        login: str = cache[0]
        master_key: bytes = cache[1]

        # #       шифрование и запись заметки
        # note_name = input("Enter a note name: ")
        # error_list: List[str] = list()
        # for elem in note_name:
        #     if elem not in _ALLOWED_CHARACTERS:
        #         error_list.append(elem)
        # if len(error_list) != 0:
        #     print(f"Error: '{''.join(error_list)}' is not allowed")
        #     break  # continue

        # try:
        #     checker1 = notes.write(login, master_key, note_name)
        # except Error as e:
        #     print(str(e))
        #     break  # continue

        # #       расшифрование и чтение заметки
        # note_name = input("Enter a note name: ")
        # error_list: List[str] = list()
        # for elem in note_name:
        #     if elem not in _ALLOWED_CHARACTERS:
        #         error_list.append(elem)
        # if len(error_list) != 0:
        #     print(f"Error: '{''.join(error_list)}' is not allowed")
        #     break  # continue
        # try:
        #     checker0 = notes.read(login, master_key, note_name)
        # except Error as e:
        #     print(str(e))
        #     break  # continue

        # #       смена пароля(только при авторизации)
        # try:
        #     change_pass(login, master_key)
        # except Error as e:
        #     print(str(e))
        #     break  # continue

        # #       смена ключа(только при авторизации)
        # try:
        #     print(change_key(login, master_key))
        # except Error as e:
        #     print(str(e))
        #     break  # continue

        # #       удаление пользователя и его папки
        # try:
        #     print(delete_account(login))
        # except Error as e:
        #     print(str(e))
        #     break  # continue

        try:
            print(db.close_db())
        except Error as e:
            print(str(e))
            break  # continue

        break
