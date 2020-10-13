from enum import Enum
from typing import Dict, List

from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes


def pad(s: str):
    return s + (16 - len(s) % 16) * chr(16 - len(s) % 16)


def unpad(s: bytes):
    return s[0:-s[-1]]


def encrypt(data: str, key: bytes or None) -> bytes:
    if key is None:
        return data.encode('utf-8')
    data = pad(data).encode('utf-8')
    aes = AES.new(key, AES.MODE_CBC)
    iv = aes.iv
    enc = aes.encrypt(data)
    return iv + enc


def decrypt(data: bytes, key: bytes) -> str:
    if key is None:
        return data.decode('utf-8')
    iv = data[:16]
    enc = data[16:]
    aes = AES.new(key, AES.MODE_CBC, iv=iv)
    dec = aes.decrypt(enc)
    return unpad(dec).decode('utf-8')


class Proxy:
    def __init__(self):
        self._linked_ip: Dict[str, "Client"] = {}
        self.msg_list: List[str] = []

    def link(self, server: "Client"):
        self._linked_ip[server.ip] = server

    def public_key(self, target_ip: str):
        """
        Public key는 올바르게 전송해줌을 가정합니다.
        :param target_ip:
        :return:
        """
        return self._linked_ip[target_ip].key.publickey()

    def request(self, source_ip: str, target_ip: str, msg: bytes):
        self.msg_list.append(msg.decode('utf-8'))
        self._linked_ip[target_ip].receive(msg, source_ip)


class Mode(Enum):
    SEND = "SEND"
    RECEIVE = "RECEIVE"


class Client:
    def __init__(self, ip: str, rsa_key=None):
        self.ip = ip
        self.session_key: Dict[str, bytes] = {}   # { ip : session key }
        if rsa_key is None:
            self.key = RSA.generate(2048)             # RSA Key
        else:
            self.key = rsa_key
        self.msg_list: List[str] = []

    def request(self, proxy: Proxy, target_ip: str, msg: str):
        """
        TODO 함수 설명:
        :param proxy:
        :param target_ip:
        :param msg:
        :return:
        """
        if not self.session_key.get(target_ip):
            self.handshake(proxy, target_ip, Mode.SEND)

        enc = encrypt(msg, self.session_key[target_ip])
        proxy.request(self.ip, target_ip, enc)

    def receive(self, msg: bytes, source_ip: str):
        """
        TODO 함수설명:
        이전에 handshake 과정을 거쳐서 session key를 공유한 상황이어야 함
        :param msg:
        :param source_ip:
        :return:
        """
        dec = decrypt(msg, self.session_key[source_ip])
        self.msg_list.append(dec)

    def handshake(self, proxy: Proxy, target_ip: str, mode: Mode):
        """
        상대 ip에 대한 session key가 없을 경우 사용하는 함수
        target ip 주소의 client의 public key를 받아와 public key 로 암호화한 session key를 전송

        공유한 session key는 self.session_key 에 ip와 매핑하여 저장
        :param mode:
        :param proxy:
        :param target_ip:
        :return:
        """
        session_key = get_random_bytes(16)
        # TODO: mode에 따라 각각 구현
        # handshake를 하는 상대도 session key를 저장해야 함


"""
RSA 라이브러리 활용을 위한 예제 코드
구현 이후에는 아래 코드는 지워주시길 바랍니다.
"""
if __name__ == '__main__':
    key = RSA.generate(2048)  # RSA Key
    pub = key.publickey()

    rsa_pub = PKCS1_OAEP.new(pub)
    rsa_priv = PKCS1_OAEP.new(key)
    print(rsa_pub.encrypt(b'abc'))
    print(rsa_priv.decrypt(rsa_pub.encrypt(b'abc')))
