import db
import notes
import security
import os
import shutil
from typing import Dict, Tuple, List, Union


class Error(Exception):
    pass


_ALLOWED_CHARACTERS: str = "ZFyt2NebDRMlJUGmQ1AVHspK-PXI8douwB" + \
    "T4O5_zSWi7rLxa]90k3vgq!6fEjnCcYh"


def create_account() -> None:
    print("REGISTRATION")
    login: str = input("Enter your login: ")
    if len(login) < 1 or not isinstance(login, str):
        raise Error("Error in main.create_account(): Invalid login")
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
    except db.db_Error as e:
        raise Error(str(e))

    password: str = input("Enter your password: ")
    if len(password) < 1 or not isinstance(login, str):
        raise Error("Error in main.create_account(): Invalid password")
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
    except security.security_Error as e:
        raise Error(str(e))
    master_key: bytes = checker2

    try:
        checker3 = security.hash(password_bytes)
    except security.security_Error as e:
        raise Error(str(e))
    password_bytes_hash: bytes = checker3

    dirr: str = os.path.join("notes", login)

    if os.path.exists(dirr):
        shutil.rmtree(dirr)
    os.mkdir(dirr)

    key: bytes = security.gen_key()
    try:
        checker4 = security.encrypt_new(key, master_key)
    except security.security_Error as e:
        raise Error(str(e))
    enc_key_with_iv: Dict[str, bytes] = dict(checker4)
    enc_key: bytes = enc_key_with_iv["ciphertext"]
    iv: bytes = enc_key_with_iv["iv"]

    db.insert(login, password_bytes_hash, dirr, enc_key, iv)
    print("Account creation completed successfully")
    return None


def auth() -> Tuple[str, bytes]:
    print("AUTHENTICATION")
    login: str = input("Enter your login: ")
    if len(login) < 1 or not isinstance(login, str):
        raise Error("Error in main.auth(): Invalid login")
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
    except db.db_Error as e:
        raise Error(str(e))

    password: str = input("Enter your password: ")
    if len(password) < 1 or not isinstance(login, str):
        raise Error("Error in main.auth(): Invalid password")
    for elem in password:
        if elem not in _ALLOWED_CHARACTERS:
            error_list.append(elem)
    if len(error_list) != 0:
        raise Error(
            f"Error in main.auth(): '{''.join(error_list)}' is not allowed")

    dirr: str = os.path.join("notes", login)
    if not os.path.exists(dirr):
        os.mkdir(dirr)

    password_bytes: bytes = password.encode(encoding="utf-8")

    try:
        checker2 = security.gen_master_key(password_bytes)
    except security.security_Error as e:
        raise Error(str(e))
    master_key: bytes = checker2

    try:
        checker3 = security.hash(password_bytes)
    except security.security_Error as e:
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
    except db.db_Error as e:
        raise Error(str(e))
    info: Tuple[object, ...] = tuple(checker1)

    dirr = info[2]

    if os.path.exists(dirr):    # type: ignore
        shutil.rmtree(dirr)     # type: ignore

    try:
        checker2 = db.cut(login)
    except db.db_Error as e:
        raise Error(str(e))

    print("Account deletion completed successfully")
    return None


def change_key(login: str, master_key: bytes) -> None:
    try:
        checker1: Union[Tuple[str, bytes, str,
                              bytes, bytes], None] = db.info(login)
        if checker1 is None:
            raise Error(
                "Error in main.change_key(): A user with this login " +
                "is not registered")
    except db.db_Error as e:
        raise Error(str(e))
    info: Tuple[str, bytes, str, bytes, bytes] = checker1

    encrypted_data: Dict[str, bytes] = {"ciphertext": info[3], "iv": info[4]}

    try:
        checker2: bytes = security.decrypt(encrypted_data, master_key)
    except security.security_Error as e:
        raise Error(str(e))
    old_key: object = checker2

    key: bytes = security.gen_key()

    try:
        checker4 = security.encrypt_new(key, master_key)
    except security.security_Error as e:
        raise Error(str(e))
    enc_key: bytes = checker4["ciphertext"]
    iv: bytes = checker4["iv"]

    try:
        checker6 = db.update(login=login, enc_key=enc_key, iv=iv)
    except db.db_Error as e:
        raise Error(str(e))

    print("The key change was successful")
    return None


def change_pass(login: str, old_master_key: bytes) -> None:
    try:
        checker1: Union[Tuple[str, bytes, str,
                              bytes, bytes], None] = db.info(login)
        if checker1 is None:
            raise Error(
                "Error in main.change_pass(): A user with this login " +
                "is not registered")
    except db.db_Error as e:
        raise Error(str(e))
    info: Tuple[str, bytes, str, bytes, bytes] = checker1

    password: str = input("Enter your new password: ")
    if len(password) < 1 or not isinstance(login, str):
        raise Error("Error in main.change_pass(): Invalid password")
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
    except security.security_Error as e:
        raise Error(str(e))
    key: bytes = checker2

    try:
        checker3 = security.gen_master_key(password_bytes)
    except security.security_Error as e:
        raise Error(str(e))
    master_key_new: bytes = checker3

    try:
        checker4 = security.encrypt(key, master_key_new, info[4])
    except security.security_Error as e:
        raise Error(str(e))
    enc_key = checker4["ciphertext"]

    try:
        checker5 = security.hash(password_bytes)
    except security.security_Error as e:
        raise Error(str(e))
    password_bytes_hash: bytes = checker5

    try:
        checker6 = db.update(
            login=login, hash=password_bytes_hash, enc_key=enc_key)
    except db.db_Error as e:
        raise Error(str(e))

    print("Password change was successful")
    return None


def start() -> int:
    path = os.path.join("notes")
    if not os.path.exists(path):
        os.mkdir(path)
    try:
        db.open_db()
    except db.db_Error as e:
        print(str(e))
        return -1
    try:
        db.create_table()
    except db.db_Error as e:
        print(str(e))
        return -1
    return 0


def stop() -> int:
    try:
        db.close_db()
    except db.db_Error as e:
        print(str(e))
        return -1
    return 0


def registration() -> int:
    try:
        create_account()
    except Error as e:
        print(str(e))
    return 0


def _confirm(act: str) -> bool:
    attempt = 0
    while attempt != 3:
        print(f"Confirm {act}? (Y/n)")
        choice = input("Your choice: ")
        try:
            if choice == 'Y' or choice == 'y':
                return True
            elif choice == 'N' or choice == 'n':
                return False
            else:
                attempt += 1
                print(f"Error: Invalid answer! {attempt} / 3")
                continue
        except ValueError:
            attempt += 1
            print(f"Error: Invalid answer! {attempt} / 3")
            continue
    if attempt == 3:
        print("Error: Attempts are over")
    return False


def account(login: str, master_key: bytes) -> int:
    while True:
        print("Account management:")
        print("\t1) Change password")
        print("\t2) Change Encryption Key")
        print("\t3) Delete account and all notes")
        print("\n\t9) Back")
        choice = input("Your choice: ")
        try:
            if int(choice) == 1:
                if _confirm("password change"):
                    try:
                        change_pass(login, master_key)
                    except Error as e:
                        print(str(e))
                    return -1
                continue
            elif int(choice) == 2:
                if _confirm("encryption key change"):
                    try:
                        change_key(login, master_key)
                    except Error as e:
                        print(str(e))
                    return -1
                continue
            elif int(choice) == 3:
                if _confirm("deletion"):
                    try:
                        delete_account(login)
                    except Error as e:
                        print(str(e))
                    return -1
                continue
            elif int(choice) == 9:
                break
            else:
                print("Error: Invalid input")
                continue
        except ValueError:
            print("Error: Invalid input")
            continue
    return 0


def _note_name() -> Union[str, int]:
    note_name = input("Enter a note name: ")
    if len(note_name) < 1:
        print("Error in _note_name(): Invalid note name")
        return -1
    error_list: List[str] = list()
    for elem in note_name:
        if elem not in _ALLOWED_CHARACTERS:
            error_list.append(elem)
    if len(error_list) != 0:
        print(f"Error: '{''.join(error_list)}' is not allowed")
        return -1
    return note_name


def actions_with_notes(login: str, master_key: bytes) -> int:
    while True:
        print("Actions with notes:")
        print("\t1) List of notes")
        print("\t2) Create a note")
        print("\t3) Edit a note")
        print("\t4) Delete a note")
        print("\t5) Delete all notes")
        print("\n\t9) Back")
        choice = input("Your choice: ")
        try:
            if int(choice) == 1:
                ns = notes.note_list(login)
                for n in ns:
                    print(n)
                if len(ns) == 0:
                    print("The list of notes is empty")
                continue
            elif int(choice) == 2:
                checker2: Union[str, int] = _note_name()
                if checker2 == -1:
                    continue
                note_name1 = str(checker2)
                try:
                    notes.write(login, master_key, note_name1)
                    print("Note created")
                except notes.notes_Error as e:
                    print(str(e))
                continue
            elif int(choice) == 3:
                checker3: Union[str, int] = _note_name()
                if checker3 == -1:
                    continue
                note_name2 = str(checker3)
                try:
                    notes.edit(login, master_key, note_name2)
                    print("Note saved")
                except notes.notes_Error as e:
                    print(str(e))
                continue
            elif int(choice) == 4:
                checker4: Union[str, int] = _note_name()
                if checker4 == -1:
                    continue
                note_name3 = str(checker4)
                if _confirm("deletion"):
                    try:
                        notes.delete(login, note_name3)
                        print("Note deleted")
                    except notes.notes_Error as e:
                        print(str(e))
                continue
            elif int(choice) == 5:
                if _confirm("deletion"):
                    try:
                        notes.delete_all(login)
                        print("All notes deleted")
                    except notes.notes_Error as e:
                        print(str(e))
                continue
            elif int(choice) == 9:
                break
            else:
                print("Error: Invalid input")
                continue
        except ValueError:
            print("Error: Invalid input")
            continue
    return 0


def authorization() -> int:
    try:
        cache: Tuple[str, bytes] = auth()
    except Error as e:
        print(str(e))
        return -1
    login: str = cache[0]
    master_key: bytes = cache[1]

    while True:
        print("Account Menu:")
        print("\t1) Account management")
        print("\t2) Actions with notes")
        print("\n\t9) Back")
        choice = input("Your choice: ")
        try:
            if int(choice) == 1:
                if account(login, master_key) == -1:
                    break
                continue
            elif int(choice) == 2:
                actions_with_notes(login, master_key)
                continue
            elif int(choice) == 9:
                break
            else:
                print("Error: Invalid input")
                continue
        except ValueError:
            print("Error: Invalid input")
            continue
    return 0


def user_interface() -> None:
    while True:
        if start() == -1:
            break

        print("Main menu:")
        print("\t1) Sign up")
        print("\t2) Sign in")
        print("\n\t9) Exit")
        choice = input("Your choice: ")
        try:
            if int(choice) == 1:
                registration()
                if stop() == -1:
                    break
                continue
            elif int(choice) == 2:
                authorization()
                if stop() == -1:
                    break
                continue
            elif int(choice) == 9:
                stop()
                break
            else:
                print("Error: Invalid input")
                continue
        except ValueError:
            print("Error: Invalid input")
            continue


def main() -> int:
    ch = os.path.abspath(os.curdir)
    if "authentication" not in ch:
        print("Error: main.py needs to be run " +
              "from the directory /authentication")
        return -1
    user_interface()
    return 0


if __name__ == "__main__":
    main()
