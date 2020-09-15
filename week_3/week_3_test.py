from Crypto.Cipher import DES
from bitarray import bitarray

from week_3.des import encrypt_des, decrypt_des
from week_3.xor import xor_encrypt_decrypt


def test_xor_encryption():
    message = 'Hello Security abcdefghijklmnopqrstuvwxyz ABCDEFGHIJKLMNOPQRSTUVWXYZ 1234567890'
    assert xor_encrypt_decrypt(xor_encrypt_decrypt(message, 'Key'), 'Key') == message


def test_xor_encryption_with_different_key():
    message = 'Hello Security abcdefghijklmnopqrstuvwxyz ABCDEFGHIJKLMNOPQRSTUVWXYZ 1234567890'
    assert xor_encrypt_decrypt(message, 'Key') != xor_encrypt_decrypt(message, 'key')
    assert xor_encrypt_decrypt(xor_encrypt_decrypt(message, 'Key'), 'key') != message


def test_xor_encryption_message():
    message = 'Hello Security abcdefghijklmnopqrstuvwxyz ABCDEFGHIJKLMNOPQRSTUVWXYZ 1234567890'
    enc = bitarray('001010010000011100001111000011010000110101000011001100100000011100000000000101000001000000001010000'
                   '101010001101101000011000000000000000000000000000001010000011100000101000001100000101000001010000010'
                   '110000100100001111000011000000110000001100000100010001001100010001000100100001011000010110000101110'
                   '001010100011011000110000001100001000011001000000010000000100000001001010010011100100101001001100010'
                   '101000101010001010110010100100101111001011000010110000101100001100010011001100110001001100100011011'
                   '000110110001101110011010100111011001110000011100001000011010100000101000001010000010101010101011101'
                   '01010101010110010110100101101001010001').tobytes().decode('utf-8')
    assert xor_encrypt_decrypt(message, 'abc') == enc


def test_des_encryption():
    message = 'Hello Security abcdefghijklmnopqrstuvwxyz ABCDEFGHIJKLMNOPQRSTUVWXYZ 1234567890'
    key = '12345678'
    iv, enc = encrypt_des(message, key, DES.MODE_OFB)
    assert decrypt_des(enc, key, DES.MODE_OFB, iv) == message


def test_des_encryption_with_different_key():
    message = 'Hello Security abcdefghijklmnopqrstuvwxyz ABCDEFGHIJKLMNOPQRSTUVWXYZ 1234567890'
    key1 = '12345678'
    key2 = '12345677'
    iv, enc1 = encrypt_des(message, key1, DES.MODE_OFB)
    _, enc2 = encrypt_des(message, key2, DES.MODE_OFB, iv)
    assert enc1 != enc2


def test_des_encryption_message():
    message = 'Hello Security abcdefghijklmnopqrstuvwxyz ABCDEFGHIJKLMNOPQRSTUVWXYZ 1234567890'
    key = '12345678'
    iv = b'\xc1\x8eb*\xaf.;\xee'
    enc = b"Ad7\x921\xfbF:\xc1\x04\xd2\x19/\x1d\x0eB\xf4\xab\xddG7\xa2'\xa6\xdc\xc7\x8a\xd0\x82\xc9-\xb9\xf6YFp\x0f\x0b:i\x1e\xae\x08\nw\xa0\x11X\xe7ked\x19\xe0\x14\xf1\nkk?4\x9a\x807\x7f\xb9/\x9e\x1b\xdc\xfc\x88\xbe\x04\x04\xc3\x0bEz"
    assert decrypt_des(enc, key, DES.MODE_OFB, iv) == message
