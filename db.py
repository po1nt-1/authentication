import sqlite3
import os
from typing import Union, Tuple

conn: sqlite3.Connection
c: sqlite3.Cursor


def open_db() -> int:
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
        print("Error in open_db: " + str(e))
        return -1


def close_db() -> int:
    global conn
    try:
        conn.close()
        return 0
    except sqlite3.Error as e:
        print("Error in close_db: " + str(e))
        return -1


def create_table() -> int:
    global conn
    global c
    try:
        with conn:
            c.execute("""DROP TABLE IF EXISTS users""")
            conn.commit()
            c.execute("""
                CREATE TABLE users (
                user        TEXT        PRIMARY KEY NOT NULL UNIQUE, \
                hash        BLOB NOT    NULL, \
                dir         TEXT NOT    NULL UNIQUE, \
                enc_key     BLOB NOT    NULL
                )
            """)
        return 0
    except sqlite3.Error as e:
        print("Error in create_table: " + str(e))
        return -1


def insert(user: str, hash: bytes, dir: str, enc_key: bytes) -> int:
    global conn
    global c
    if not isinstance(user, str):
        print("Error in insert: Incorrect user type")
        return -1
    else:
        if len(user) < 1:
            print("Error in insert: Incorrect name length")
            return -1
    if not isinstance(dir, str):
        print("Error in insert: Incorrect dir type")
        return -1
    try:
        with conn:
            c.execute("""
                INSERT INTO users (user, hash, dir, enc_key) \
                VALUES (?, ?, ?, ?)""",
                      (user, hash, dir, enc_key))
        return 0
    except sqlite3.IntegrityError as e:
        print("Error in insert: " + str(e))
        return -1


def cut(user: str) -> int:
    global conn
    global c
    if not isinstance(user, str):
        print("Error in insert: Incorrect user type")
        return -1
    else:
        if len(user) < 1:
            print("Error in insert: Incorrect name length")
            return -1

    with conn:
        c.execute("""SELECT * FROM users WHERE user=?""", (user, ))
        info: Tuple[str, bytes, str, bytes] = c.fetchone()
        if info is None:
            return -1

    try:
        with conn:
            c.execute("""DELETE FROM users WHERE user=?""", (user, ))
        return 0
    except sqlite3.IntegrityError as e:
        print("Error in cut: " + str(e))
        return -1


def update(user: str, hash: bytes = b'None',
           dir: str = 'None', enc_key: bytes = b'None') -> int:
    global conn
    global c
    if not isinstance(user, str):
        print("Error in insert: Incorrect user type")
        return -1
    else:
        if len(user) < 1:
            print("Error in insert: Incorrect name length")
            return -1

    temp_values = [user, hash, dir, enc_key]
    temp_types = [str, bytes, str, bytes]
    for i in range(len(temp_values)):
        if not isinstance(temp_values[i], temp_types[i]):
            print("Error in update: Incorrect user type")
            return -1
        else:
            if len(temp_values[i]) < 1:
                print("Error in update: Incorrect name length")
                return -1

    try:
        with conn:
            upd = ""
            if hash != b'None':
                upd += "hash = '" + str(hash) + "'"
            if dir != 'None':
                if len(upd) > 0:
                    upd += ", "
                upd += "dir ='" + str(dir) + "'"
            if enc_key != b'None':
                if len(upd) > 0:
                    upd += ", "
                upd += "enc_key = '" + str(enc_key) + "'"
            c.execute("""
                UPDATE users SET {0} WHERE user = '{1}'""".format(upd, user))
        return 0
    except sqlite3.IntegrityError as e:
        print("Error in update: " + str(e))
        return -1


def info(user: str) -> Union[Tuple[str, bytes, str, bytes], int]:
    global conn
    global c
    try:
        with conn:
            c.execute("""SELECT * FROM users WHERE user=?""", (user, ))
            info: Tuple[str, bytes, str, bytes] = c.fetchone()
            if info is None:
                return -1
        return info
    except sqlite3.IntegrityError as e:
        print("Error in info: " + str(e))
        return -1


if __name__ == "__main__":
    print("open_db:", open_db())
    # print("create_table:", create_table())
    # print("insert:", insert('test', b'hsh', 'folder', b'enc'))
    # print("update:", update('admin', dir='folderforadmin'))
    # print("info:", info('lols'))
    # print("cut:", cut('lols'))
    print("close_db:", close_db())
