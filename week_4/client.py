from socket import *
import threading
import time
from Crypto.Cipher import AES


def pad(s: str or bytes):
    """

    :param s:
    :return:
    """
    return (16 - len(s) % 16) * chr(16 - len(s) % 16)


def unpad(s: bytes):
    """

    :param s:
    :return:
    """
    return s[0:-s[-1]]


def encrypt(data: str, key: bytes) -> bytes:
    """

    :param data:
    :param key:
    :return:
    """
    #  TODO: 구현할 부분 (data.encode('utf-8') 도 변경해도 됨)

    return data.encode('utf-8')


def decrypt(data: bytes, key: bytes) -> str:
    """

    :param data:
    :param key:
    :return:
    """
    #  TODO: 구현할 부분 (data.decode('utf-8') 도 변경해도 됨)

    return data.decode('utf-8')


def send(sock, key):
    """
    함수설명:

    :param sock:
    :param key:
    :return:
    """
    while True:
        send_data = input('>>>')
        sock.send(encrypt(send_data, key))


def receive(sock, key):
    """
    함수설명:

    :param sock:
    :param key:
    :return:
    """
    while True:
        recv_data = sock.recv(1024)
        print('상대방 :', decrypt(recv_data, key))


port = 8081

clientSock = socket(AF_INET, SOCK_STREAM)
clientSock.connect(('127.0.0.1', port))

print('접속 완료')

key = input('key를 입력해주세요: ')
sender = threading.Thread(target=send, args=(clientSock, key.encode('utf-8')))
receiver = threading.Thread(target=receive, args=(clientSock, key.encode('utf-8')))

sender.start()
receiver.start()

while True:
    time.sleep(1)
    pass
