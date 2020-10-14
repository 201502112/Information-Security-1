from Crypto.Cipher import PKCS1_OAEP
from Crypto.Random import get_random_bytes

from week_7.key_exchange import Client, Proxy


def test_encryption_client():
    client1 = Client('123.456.0.2')
    client2 = Client('123.556.0.4')
    proxy1 = Proxy()
    proxy1.link(client1)
    proxy1.link(client2)

    msg = 'abcdefghijklmnopqrstuvwxyz'
    client1.request(proxy1, '123.556.0.4', msg)
    assert len(client1.msg_list) == 0
    assert len(client2.msg_list) == 1
    assert client2.msg_list[0] == msg


def test_encryption_proxy():
    client1 = Client('123.456.0.1')
    client2 = Client('123.556.0.5')
    proxy1 = Proxy()
    proxy1.link(client1)
    proxy1.link(client2)

    msg = 'abcdefghijklmnopqrstuvwxyz'
    client1.request(proxy1, '123.556.0.5', msg)
    assert len(proxy1.msg_list) == 0


def test_handshake_client():
    client1 = Client('123.456.0.1')
    client2 = Client('123.556.0.5')
    proxy1 = Proxy()
    proxy1.link(client1)
    proxy1.link(client2)

    msg = 'abcdefghijklmnopqrstuvwxyz'
    client1.request(proxy1, '123.556.0.5', msg)

    assert client1.session_key['123.556.0.5'] == client2.session_key['123.456.0.1']


def test_handshake_key():
    client1 = Client('123.456.0.1')
    client2 = Client('123.556.0.5')
    proxy1 = Proxy()
    proxy1.link(client1)
    proxy1.link(client2)

    session_key = b'\xfa\xb2P\x14\r\x88\xd8\xcc\x91Hu\xcdNA:V'
    target_pub = PKCS1_OAEP.new(proxy1.public_key('123.456.0.1'))
    enc = target_pub.encrypt(session_key)
    client1.handshake(proxy1, '123.556.0.5', enc)

    assert client1.session_key['123.556.0.5'] == session_key

