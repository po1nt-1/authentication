import os
import pickle
from typing import Union


def write(login: str, name: str, text: bytes, mode: str = "overwrite") -> int:
    if not isinstance(login, str) or not isinstance(name, str) \
            or not isinstance(text, bytes):
        print("Error in notes.write(): Incompatible value type")
        return -1

    path_ = os.path.join("authentication/notes", login, name)
    try:
        if mode == "overwrite":
            if os.path.exists(path_):
                os.remove(path_)

            f = open(path_, "wb")
        elif mode == "add":
            f = open(path_, "ab")
        else:
            print("Error in notes.write(): Incorrect mode")
            return -1
    except FileNotFoundError:
        print("Error in notes.write(): User directory does not exist")
        f.close()
        return -1
    pickle.dump(text, f)
    f.close()
    return 0


def read(login: str, name: str) -> Union[bytes, int]:
    if not isinstance(login, str) or not isinstance(name, str):
        print("Error in notes.write(): Incompatible value type")
        return -1

    path_ = os.path.join("authentication/notes", login, name)
    if not os.path.exists(path_):
        print("Error in notes.write(): Note does not exist")
        return -1

    result = bytes()
    with open(path_, "rb") as f:
        try:
            while True:
                data: bytes = pickle.load(f)
                result += data
        except EOFError:
            pass

    if not isinstance(result, bytes):
        print("Error in notes.read(): Incompatible return value type")
        return -1
    return result


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
