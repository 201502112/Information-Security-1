import string
from enum import Enum

lower_alphabet_list = list(string.ascii_lowercase)
upper_alphabet_list = list(string.ascii_uppercase)
number_list = list(string.digits)


class EncryptionMode(Enum):
    ENC = 'ENCRYPT'
    DEC = 'DECRYPT'


def vigenere_encrypt_decrypt(text: str, key: str, mode: EncryptionMode) -> str:
    enc = []
    for i, c in enumerate(text):
        k = lower_alphabet_list.index(key[i%len(key)])
        digit_key = k % 10
        k %= 26
        if mode == EncryptionMode.DEC:
            digit_key = len(number_list) - digit_key
            k = len(lower_alphabet_list) - k
        if c.isupper():
            index = (upper_alphabet_list.index(c)+k + 26) % 26
            enc.append(upper_alphabet_list[index])
        elif c.islower():
            index = (lower_alphabet_list.index(c)+k + 26) % 26
            enc.append(lower_alphabet_list[index])
        elif c.isdigit():
            enc.append(str((int(c)+digit_key) % 10))
        else:
            enc.append(c)

    return ''.join(enc)
