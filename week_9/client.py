from socket import *
import threading
import time
from Crypto.Cipher import AES
import random


def pad(s: str):
    return s + (16 - len(s) % 16) * chr(16 - len(s) % 16)


def unpad(s: bytes):
    return s[0:-s[-1]]


def encrypt(data: str, key: bytes) -> bytes:
    data = pad(data).encode('utf-8')
    aes = AES.new(key, AES.MODE_CBC)
    iv = aes.iv
    enc = aes.encrypt(data)
    return iv + enc


def decrypt(data: bytes, key: bytes) -> str:
    iv = data[:16]
    enc = data[16:]
    aes = AES.new(key, AES.MODE_CBC, iv=iv)
    dec = aes.decrypt(enc)
    return unpad(dec).decode('utf-8')


def send(sock, key):
    while True:
        send_data = input('>>>')
        sock.send(encrypt(send_data, key))


def receive(sock, key):
    while True:
        recv_data = sock.recv(1024)
        print('상대방 :', decrypt(recv_data, key))


def login():
    """
    TODO: 아이디와 패스워드 값을 전송하는 함수
    :return:
    """
    user_id = input()
    password = input()
    # socket 통신으로 id와 password를 전송
    pass


def generate_key(key: int or None = None) -> int:
    """
    테스트를 위해 임의 key를 입력할 경우에 해당 key를 반환하도록 구현
    기본적으로 랜덤한 secret 키를 생성
    :param key:
    :return:
    """
    if key is not None:
        return key
    return random.randint(10000000000000000, 100000000000000000000000000000000000000000000000)


def diffie_hellman(my_secret_key: int, target_public_key: int) -> bytes:
    """
    TODO: [함수 설명]
    :param my_secret_key:
    :param target_public_key:
    :return:
    """
    p = 9723448991222331098330293371197519246446906995517093957384966642329511534161627658859950763542683697458467770974347360725590854862427735703874399411721649
    g = 2348329574892572380947382043

    pass


def public_key(secret_key: int) -> int:
    """
    TODO: diffie hellman에서의 public key를 계산하여 반환하는 함수
    :param secret_key:
    :return:
    """
    p = 9723448991222331098330293371197519246446906995517093957384966642329511534161627658859950763542683697458467770974347360725590854862427735703874399411721649
    g = 2348329574892572380947382043


def connect_socket():
    port = 8081

    client_socket = socket(AF_INET, SOCK_STREAM)
    client_socket.connect(('127.0.0.1', port))
    print('접속 완료')

    login()
    print('로그인 완료')

    my_secret_key = generate_key()
    # TODO: 자신의 public key를 전송해야 함

    target_public_key = int.from_bytes(client_socket.recv(1024), byteorder='little')  # little endian 으로 보내야 함
    key = diffie_hellman(my_secret_key, target_public_key)
    print('키 교환 완료')

    sender = threading.Thread(target=send, args=(client_socket, key))
    receiver = threading.Thread(target=receive, args=(client_socket, key))

    sender.start()
    receiver.start()

    while True:
        time.sleep(1)
        pass


if __name__ == '__main__':
    connect_socket()
    # p = 9723448991222331098330293371197519246446906995517093957384966642329511534161627658859950763542683697458467770974347360725590854862427735703874399411721649
    # print(p.to_bytes(64, byteorder='little'))
    # print(int.from_bytes(p.to_bytes(64, byteorder='little'), byteorder='little'))
