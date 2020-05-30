import sqlite3
import os
from typing import Union, Tuple
# import shelve

conn: sqlite3.Connection
c: sqlite3.Cursor


def open_db() -> int:
    """
        Открытие БД.
        Если БД не существует, будет создана новая БД.
    """
    global conn
    global c

    try:
        if os.path.exists('authentication/service'):
            conn = sqlite3.connect('authentication/service/database.db')
            c = conn.cursor()
        else:
            os.mkdir('authentication/service')
            conn = sqlite3.connect('authentication/service/database.db')
            c = conn.cursor()
        return 0
    except sqlite3.Error as e:
        print("Error in open_db(): " + str(e))
        return -1


def close_db() -> int:
    global conn
    try:
        conn.close()
        return 0
    except sqlite3.Error as e:
        print("Error in close_db(): " + str(e))
        return -1


def create_table() -> int:
    """
        Создание таблицы, если она не существует.
    """
    global conn
    global c

    try:
        with conn:
            c.execute("""
                CREATE TABLE IF NOT EXISTS users (
                login       TEXT        PRIMARY KEY NOT NULL UNIQUE, \
                hash        BLOB        NOT NULL, \
                dir         TEXT        NOT NULL UNIQUE, \
                enc_key     BLOB        NOT NULL, \
                iv          BLOB        NOT NULL
                )
            """)
        return 0
    except sqlite3.Error as e:
        print("Error in create_table(): " + str(e))
        return -1


def insert(login: str, hash: bytes, dir: str,
           enc_key: bytes, iv: bytes) -> int:
    global conn
    global c
    if not isinstance(login, str):
        print("Error in insert(): Incorrect login type")
        return -1
    else:
        if len(login) < 1:
            print("Error in insert(): Incorrect login length")
            return -1
        elif login == 'None':
            print(f"Error in insert(): You can not use {login} as a login")
            return -1
    if not isinstance(dir, str):
        print("Error in insert(): Incorrect dir type")
        return -1
    try:
        with conn:
            c.execute("""
                INSERT INTO users (login, hash, dir, enc_key, iv) \
                VALUES (?, ?, ?, ?, ?)""",
                      (login, hash, dir, enc_key, iv))
        return 0
    except sqlite3.IntegrityError as e:
        print("Error in insert(): " + str(e))
        return -1


def cut(login: str) -> int:
    global conn
    global c
    if not isinstance(login, str):
        print("Error in cut(): Incorrect login type")
        return -1
    else:
        if len(login) < 1:
            print("Error in cut(): Incorrect login length")
            return -1

    with conn:
        c.execute("""SELECT * FROM users WHERE login=?""", (login, ))
        info: Tuple[str, bytes, str, bytes] = c.fetchone()
        if info is None:
            print("Error in cut(): Incorrect login")
            return -1

    try:
        with conn:
            c.execute("""DELETE FROM users WHERE login=?""", (login, ))
        return 0
    except sqlite3.IntegrityError as e:
        print("Error in cut(): " + str(e))
        return -1


def update(login: str = 'None', hash: bytes = b'None',
           dir: str = 'None', enc_key: bytes = b'None',
           iv: bytes = b'None') -> int:
    global conn
    global c

    if login == 'None':
        print("Error in update(): Login not specified")
        return -1

    try:
        with conn:
            c.execute("""SELECT * FROM users WHERE login=?""", (login, ))
            if c.fetchone() is None:
                print(f"Error in update(): User with login {login} not found")
                return -1
    except sqlite3.IntegrityError as e:
        print("Error in update(): " + str(e))
        return -1

    temp_values: list = [login, hash, dir, enc_key, iv]
    temp_types: list = [str, bytes, str, bytes, bytes]

    for i in range(len(temp_values)):
        if not isinstance(temp_values[i], temp_types[i]):
            print("Error in update(): Incorrect data type")
            return -1
        else:
            if len(temp_values[i]) < 1:
                print("Error in update(): Incorrect data length")
                return -1

    try:
        with conn:
            if hash != b'None':
                c.execute("""
                UPDATE users SET hash=? WHERE login=?""", (hash, login))
            if dir != 'None':
                c.execute("""
                UPDATE users SET dir=? WHERE login=?""", (dir, login))
            if enc_key != b'None':
                c.execute("""
                UPDATE users SET enc_key=? WHERE login=?""", (enc_key, login))
            if iv != b'None':
                c.execute("""
                UPDATE users SET iv=? WHERE login=?""", (iv, login))
        return 0
    except sqlite3.IntegrityError as e:
        print("Error in update(): " + str(e))
        return -1


def info(login: str) -> Union[Tuple[str, bytes, str, bytes, bytes], int]:
    global conn
    global c
    try:
        with conn:
            c.execute("""SELECT * FROM users WHERE login=?""", (login, ))
            info: Tuple[str, bytes, str, bytes, bytes] = c.fetchone()
            if info is None:
                return -1
        return info
    except sqlite3.IntegrityError as e:
        print("Error in info(): " + str(e))
        return -1


if __name__ == "__main__":
    print("open_db:", open_db())
    # print("create_table:", create_table())
    # print("insert:", insert('user1', b'hashpass', 'folder', b'enc_key', b'iv1234'))
    # print("update:", update('user1', iv=b'newiv312', enc_key=b'test12', dir='test23'))
    # print("info:", info('admin'))
    # print("cut:", cut('user1'))
    print("close_db:", close_db())
