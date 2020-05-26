import db
import notes
import security
from typing import Union, Dict, Tuple
import os


def create_account() -> Union[Dict[str, bytes], int]:
    allowed_characters = 'ZFyt:2N"e=b.%DRMlJU<Gm[№Q1AVHsp>K-PXI'\
        + '8d+ouw,BT~4O5_zSWi7"rLxa]/90k(3vgq!;6f})Ej{nCc?*\\Yh'

    login: str = input("Enter your login: ")
    if len(login) < 1 or isinstance(login, str) is False:
        print("Incorrect login")
        return -1
    for elem in login:
        if elem not in allowed_characters:
            print(f"The symbol '{elem}' is not allowed")
            return -1

    password = input("Enter your password: ")
    if len(password) < 1 or isinstance(login, str) is False:
        print("Incorrect login")
        return -1
    for elem in password:
        if elem not in allowed_characters:
            print(f"The symbol '{elem}' is not allowed")
            return -1
    password = password.encode(encoding="utf-8")

    checker1 = security.gen_master_key(password)
    if checker1 == -1:
        return -1
    master_key = bytes(checker1)

    checker2 = security.hash(password)
    if checker2 == -1:
        return -1
    password = bytes(checker2)

    dirr = 'folder' + login

    key = security.gen_key()

    checker3 = security.encrypt(key, master_key)
    if checker3 == -1:
        return -1
    enc_key_with_iv = dict(checker3)
    # enc_key_with_iv эту штуку нужно хранить в формате shelvew
    db.insert(login, password, dirr, enc_key_with_iv)
    return 0


if __name__ == "__main__":
    print(db.open_db())
    print(db.create_table())
    print(create_account())
