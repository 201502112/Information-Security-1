from typing import List
from bitarray import bitarray


def string_to_bits(string: str) -> List[bool]:
    bits = bitarray()
    bits.frombytes(string.encode('utf-8'))
    return bits.tolist()


def bits_to_string(bits: List[bool]) -> str:
    return bitarray(bits).tobytes().decode('utf-8')


def xor_encrypt_decrypt(message: str, key: str) -> str:
    """

    :param message:
    :param key:
    :return:
    """
    message_bits = string_to_bits(message)
    key_bits = string_to_bits(key)
    pass
