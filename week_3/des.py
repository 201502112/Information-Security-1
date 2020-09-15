from Crypto.Cipher import DES


def encrypt_des(message: str, key: str, mode: int, iv=None) -> (bytes, bytes):
    """

    :param message:
    :param key:
    :param mode:
    :param iv:
    :return:
    """
    cipher = DES.new(bytes(key, 'utf-8'), mode, iv=iv)
    return cipher.iv, cipher.encrypt(bytes(message, 'utf-8'))


def decrypt_des(encrypted: bytes, key: str, mode: int, iv: bytes) -> str:
    """

    :param encrypted:
    :param key:
    :param mode:
    :param iv:
    :return:
    """
    cipher = DES.new(bytes(key, 'utf-8'), mode, iv=iv)
    return cipher.decrypt(encrypted).decode('utf-8')
