import copy
from dataclasses import dataclass
from typing import List

from Crypto.Hash import SHA256
from Crypto.PublicKey import ECC
from Crypto.Signature import DSS


@dataclass
class Cert:
    issuer: bytes
    public: bytes
    sign: bytes


class Issuer:
    def __init__(self, key: bytes, cert_chain=None):
        if cert_chain is None:
            cert_chain = []
        self.__secret = ECC.import_key(key)
        self.public = self.__secret.public_key()
        self.cert_chain: List[Cert] = cert_chain

    def change_secret(self, key: bytes):
        self.__secret = ECC.import_key(key)
        self.public = self.__secret.public_key()
        self.cert_chain = []

    def public_key(self) -> bytes:
        return bytes(self.public.export_key(format='DER'))

    def issue(self, pub_key: bytes):
        """
        TODO:
        자신의 certificate chain 과
        issuer의 public key, holder의 public key와 public key의 Hash에 대한 서명을 가진 dictionary 반환

        :param pub_key:
        :return: cert_chain:
         [ { issuer: pub_key0, public_key: pub_key1, sign: Signature0(Hash(pub_key1)) }, ... ]
        """


class Holder:
    def __init__(self, key: bytes):
        self.__secret = ECC.import_key(key)
        self.public = self.__secret.public_key()
        self.cert: List[Cert] = []

    def set_cert(self, cert: List[Cert]):
        self.cert = cert

    def public_key(self) -> bytes:
        return bytes(self.public.export_key(format='DER'))

    def present(self, nonce: bytes) -> (List[Cert], bytes):
        """
        TODO:

        자신이 발급받아온 cert chain을 통해
        :param nonce: 랜덤 값
        :return: cert_chain, sign(nonce)
        """


class Verifier:
    def __init__(self, root_pub: bytes):
        self.root = root_pub

    def verify(self, cert_chain: List[Cert], pub_key: bytes, nonce: bytes, sign: bytes):
        """
        TODO:

        cert_chain을 검증하고 pub_key의 서명을 확인함

        root issuer는 저장된 root ca에 대한 정보를 이용하여 확인

        cert chain 검증 결과 root ca로부터 연결된 신뢰 관계를 갖고 있을 경우 True 반환

        :param cert_chain:
        :param pub_key:
        :param nonce:
        :param sign:
        :return:
        """
