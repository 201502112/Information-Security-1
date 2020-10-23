import string

lower_alphabet_list = list(string.ascii_lowercase)
upper_alphabet_list = list(string.ascii_uppercase)
number_list = list(string.digits)


def caesar_encrypt_decrypt(text: str, key: int) -> str:
    digit_key = key % 10
    key %= 26
    enc = []
    for c in text:
        if c.isupper():
            index = (upper_alphabet_list.index(c)+key + 26) % 26
            enc.append(upper_alphabet_list[index])
        elif c.islower():
            index = (lower_alphabet_list.index(c)+key + 26) % 26
            enc.append(lower_alphabet_list[index])
        elif c.isdigit():
            enc.append(str((int(c)+digit_key) % 10))
        else:
            enc.append(c)

    return ''.join(enc)
