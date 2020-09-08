import string
from enum import Enum

lower_alphabet_list = list(string.ascii_lowercase)
upper_alphabet_list = list(string.ascii_uppercase)
number_list = list(string.digits)


class EncryptionMode(Enum):
    ENC = 'ENCRYPT'
    DEC = 'DECRYPT'


def vigenere_encrypt_decrypt(text: str, key: str, mode: EncryptionMode) -> str:
    """
    비제네르 암호를 이용하여 암호화 혹은 복호화를 수행하는 암호 알고리즘
    :param text: 암호화할 문자열
    :param key: 암호화에 사용할 key의 배열
    :param mode: 암호화할 지 복호화할 지 구분하기 위한 값
    :return: 비제네르 암호를 이용한 암호문 혹은 복호화된 문자열
    """
    pass
