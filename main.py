import db
import notes
import security
from typing import Union, Dict, Tuple, List
import json

allowed_characters: str = "ZFyt2NebDRMlJUGm[№Q1AVHspK-PXI8douwB" + \
    "T~4O5_zSWi7rLxa]90k(3vgq!6f})Ej{nCcYh"


def create_account() -> int:
    print("REGISTRATION")
    login: str = input("Enter your login: ")
    if len(login) < 1 or not isinstance(login, str):
        print("Incorrect login")
        return -1
    if len(login) > 100:
        print(f"Error: Login too long (len: {len(login)}).\nMax length 100")
        return -1
    error_list: List[str] = list()
    for elem in login:
        if elem not in allowed_characters:
            error_list.append(elem)
    if len(error_list) != 0:
        print(f"Error: '{''.join(error_list)}' is not allowed")
        return -1

    checker1: Union[Tuple[str, bytes, str, bytes, bytes], int] = db.info(login)
    if checker1 != -1:
        print("Error: A user with this username is already registered")
        return -1

    password: str = input("Enter your password: ")
    if len(password) < 1 or not isinstance(login, str):
        print("Error: Incorrect password")
        return -1
    for elem in password:
        if elem not in allowed_characters:
            error_list.append(elem)
    if len(error_list) != 0:
        print(f"Error: '{''.join(error_list)}' is not allowed")
        return -1

    password_bytes: bytes = password.encode(encoding="utf-8")

    checker2: Union[bytes, int] = security.gen_master_key(password_bytes)
    if checker2 == -1:
        return -1
    master_key: bytes = bytes(checker2)

    checker3: Union[bytes, int] = security.hash(password_bytes)
    if checker3 == -1:
        return -1
    password_bytes_hash: bytes = bytes(checker3)

    dirr: str = login + "_folder"

    key: bytearray = security.gen_key()
    checker4: Union[Dict[str, bytes], int] = security.encrypt(key, master_key)
    if checker4 == -1:
        return -1
    enc_key_with_iv: Dict[str, bytes] = dict(checker4)
    enc_key: bytes = enc_key_with_iv["ciphertext"]
    iv: bytes = enc_key_with_iv["iv"]
    if not isinstance(enc_key, bytes) or not isinstance(iv, bytes):
        print("Error: Incorrect value type")
        return -1

    db.insert(login, password_bytes_hash, dirr, enc_key, iv)
    print("Successful")
    return 0


def auth() -> Union[Tuple[str, bytes], int]:
    print("AUTHENTICATION")
    login: str = input("Enter your login: ")
    if len(login) < 1 or not isinstance(login, str):
        print("Error: Incorrect login")
        return -1
    error_list: List[str] = list()
    for elem in login:
        if elem not in allowed_characters:
            error_list.append(elem)
    if len(error_list) != 0:
        print(f"Error: '{''.join(error_list)}' is not allowed")
        return -1

    checker1: Union[Tuple[str, bytes, str, bytes, bytes], int] = db.info(login)
    if checker1 == -1:
        print("Error: A user with this login is not registered")
        return -1

    password: str = input("Enter your password: ")
    if len(password) < 1 or not isinstance(login, str):
        print("Error: Incorrect password")
        return -1
    for elem in password:
        if elem not in allowed_characters:
            error_list.append(elem)
    if len(error_list) != 0:
        print(f"Error: '{''.join(error_list)}' is not allowed")
        return -1

    password_bytes: bytes = password.encode(encoding="utf-8")

    checker2: Union[bytes, int] = security.gen_master_key(password_bytes)
    if checker2 == -1:
        return -1
    master_key: bytes = bytes(checker2)

    checker3: Union[bytes, int] = security.hash(password_bytes)
    if checker3 == -1:
        return -1
    password_bytes_hash: bytes = bytes(checker3)

    checker4: Union[Tuple[str, bytes, str, bytes, bytes], int] = db.info(login)
    if checker4 == -1:
        return -1
    info: Tuple[str, bytes, str, bytes, bytes] = tuple(checker4)
    password_bytes_hash_orig: bytes = info[1]

    if password_bytes_hash != password_bytes_hash_orig:
        print("Error: Wrong password")
        return -1
    print("Successful")
    return (login, master_key)


def delete_account(login):
    pass


def change_key(login: str, master_key: bytes):
    pass


def change_pass(login: str, old_master_key: bytes) -> int:
    checker1: Union[Tuple[str, bytes, str, bytes, bytes], int] = db.info(login)
    if checker1 == -1:
        return -1
    info: Tuple[str, bytes, str, bytes, bytes] = tuple(checker1)

    password: str = input("Enter your new password: ")
    if len(password) < 1 or not isinstance(login, str):
        print("Error: Incorrect password")
        return -1
    error_list: List[str] = list()
    for elem in password:
        if elem not in allowed_characters:
            error_list.append(elem)
    if len(error_list) != 0:
        print(f"Error: '{''.join(error_list)}' is not allowed")
        return -1
    password_bytes: bytes = password.encode(encoding="utf-8")

    if not isinstance(info[3], bytes) or not isinstance(info[4], bytes):
        print("Error: Incorrect value type")
        return -1
    encrypted_data: Dict[str, bytes] = {"ciphertext": info[3], "iv": info[4]}

    checker2: Union[bytes, int] = security.decrypt(
        encrypted_data, old_master_key)
    if checker2 == -1:
        return -1
    key: bytes = bytes(checker2)

    checker3: Union[bytes, int] = security.gen_master_key(password_bytes)
    if checker3 == -1:
        return -1
    master_key_new: bytes = bytes(checker3)

    checker4 = security.encrypt(key, master_key_new)
    if checker4 == -1:
        return -1
    enc_key: bytes = bytes(checker4["ciphertext"])
    iv: bytes = bytes(checker4["iv"])

    checker5: Union[bytes, int] = security.hash(password_bytes)
    if checker5 == -1:
        return -1
    password_bytes_hash: bytes = bytes(checker5)

    checker6 = db.update(login=login, hash=password_bytes_hash,
                         enc_key=enc_key, iv=iv)
    if checker6 == -1:
        return -1

    print("Successful")
    return 0


if __name__ == "__main__":
    while True:
        print(db.open_db())

        print(db.create_table())
        print(create_account())
        # cache: Union[Tuple[str, bytes], int] = auth()
        # if cache == -1:
        #     break
        # login: str = str(cache[0])
        # master_key: bytes = bytes(cache[1])
        # change_pass(login, master_key)

        print(db.close_db())

        break
