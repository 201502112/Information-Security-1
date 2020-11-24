from dataclasses import dataclass
from time import time
from typing import List, Dict

from Crypto.Hash import SHA256
from Crypto.Hash.SHA256 import SHA256Hash
from Crypto.PublicKey import ECC
from Crypto.Signature import DSS


class Address:
    def __init__(self, pk: bytes):
        k = SHA256.new(pk)
        self.__address = k.hexdigest()

    def __bytes__(self):
        return bytes.fromhex(self.__address)

    def __str__(self):
        return f'0x{self.__address}'


@dataclass
class Transaction:
    sender: Address  # sender's address
    receiver: Address  # receiver's address
    value: int  # amount the sender send to receiver
    nonce: bytes  # random value for checking double spending
    signature: bytes or None  # Signature

    def hash(self) -> SHA256Hash:
        k = SHA256.new()
        k.update(bytes(self.sender))
        k.update(bytes(self.receiver))
        k.update(bytes(self.value))
        k.update(bytes(self.nonce))
        return k

    def sign(self, sk: ECC):
        signer = DSS.new(sk, 'fips-186-3')
        hash_val = self.hash()
        self.signature = signer.sign(hash_val)


@dataclass
class MerkleNode:
    hash: bytes
    left: 'MerkleNode' or None
    right: 'MerkleNode' or None

    def __init__(self, left: 'MerkleNode' or None = None, right: 'MerkleNode' or None = None, hash_val: bytes = None):
        if hash_val:
            self.hash = hash_val
            self.left = None
            self.right = None
        else:
            k = SHA256.new()
            if left:
                k.update(left.hash)
                self.left = left
            if right:
                k.update(right.hash)
                self.right = right
            self.hash = bytes.fromhex(k.hexdigest())


class MerkleTree:
    def __init__(self, transaction_list: List[Transaction]):
        merkle_nodes = list(map(
            lambda transaction: MerkleNode(hash_val=bytes(transaction.hash().digest())),
            transaction_list,
        ))
        self.root = self.make_merkle_tree(merkle_nodes)

    @classmethod
    def make_merkle_tree(cls, merkle_nodes: List[MerkleNode]) -> MerkleNode:
        if len(merkle_nodes) == 0:
            return MerkleNode()
        if len(merkle_nodes) == 1:
            return merkle_nodes[0]

        nodes = [MerkleNode(merkle_nodes[i], merkle_nodes[i + 1]) for i in range(0, len(merkle_nodes) - 1, 2)]
        if len(merkle_nodes) % 2 == 1:
            nodes.append(merkle_nodes[-1])
        return cls.make_merkle_tree(nodes)

    def merkle_root(self) -> bytes:
        return self.root.hash


@dataclass
class BlockHeader:
    block_number: int  # number of block
    parent_hash: bytes  # parent block's hash
    merkle_root: bytes  # root of merkle tree
    state_root: bytes  # root of state tree
    difficulty: int  # block difficulty
    nonce: int  # random value


@dataclass
class State:
    address: Address  # address
    value: int  # amount of address


@dataclass
class Block:
    block_header: BlockHeader
    merkle_tree: MerkleTree
    state_tree: Dict[Address, int]


class BlockChain:
    def __init__(self, genesis_block: Block):
        self.block_chain = [genesis_block]

    def make_merkle_tree(self, transaction_list: List[Transaction]) -> bytes:
        """
        다음 주 과제
        :param transaction_list:
        :return: merkle root 값
        """
        return b''

    def update_state_root(self, transaction_list: List[Transaction]) -> bytes:
        """
        다음 주 과제
        :param transaction_list:
        :return: state root 값
        """
        return b''

    def mining(self, transaction_list: List[Transaction]):
        """
        TODO:
        :return:
        """
        # block_number: int  # number of block
        # parent_hash: bytes  # parent block's hash
        # merkle_root: bytes  # root of merkle tree
        # state_root: bytes  # root of state tree
        # difficulty: int  # block difficulty
        # nonce: int  # random value
        merkle_root = self.make_merkle_tree(transaction_list)
        state_root = self.update_state_root(transaction_list)
        parent_header = self.block_chain[-1].block_header

        prev_hash_input = bytes(parent_header.block_number) + \
                          parent_header.parent_hash + \
                          parent_header.merkle_root + \
                          parent_header.state_root + \
                          bytes(parent_header.nonce)
        prev_hash = SHA256.new(prev_hash_input).digest()

        hash_input = bytes(parent_header.block_number + 1) + \
                     prev_hash + \
                     merkle_root + \
                     state_root

        limit = 2 ** 256 // parent_header.difficulty
        nonce = 0
        while True:
            sha = SHA256.new(hash_input + bytes(nonce))
            hash_value = sha.digest()
            if int.from_bytes(hash_value, byteorder='big') < limit:
                break
            nonce += 1

        header = BlockHeader(parent_header.block_number + 1, prev_hash, merkle_root, state_root,
                             parent_header.difficulty, nonce)

        self.block_chain.append(Block(header, MerkleTree([]), {}))

    def verify(self) -> bool:
        """
        생성한 블록을 검증하는 함수
        :return:
        """
        for i in range(1, len(self.block_chain)):
            if not self.verify_block(i):
                return False
        return True

    def verify_block(self, index) -> bool:
        """
        TODO:
        :param index:
        :return:
        """
        # Check merkle root (다음 주차에 추가 예정)

        # Check state root (다음 주차에 추가 예정)

        # Check prev block
        if index != 0:
            prev_hash_input = bytes(self.block_chain[index - 1].block_header.block_number) + \
                              self.block_chain[index - 1].block_header.parent_hash + \
                              self.block_chain[index - 1].block_header.merkle_root + \
                              self.block_chain[index - 1].block_header.state_root + \
                              bytes(self.block_chain[index - 1].block_header.nonce)
            prev_hash = SHA256.new(prev_hash_input).digest()
            if self.block_chain[index].block_header.parent_hash != prev_hash:
                return False

        # difficulty check
        hash_input = bytes(self.block_chain[index].block_header.block_number) + \
                     self.block_chain[index].block_header.parent_hash + \
                     self.block_chain[index].block_header.merkle_root + \
                     self.block_chain[index].block_header.state_root + \
                     bytes(self.block_chain[index].block_header.nonce)
        sha = SHA256.new(hash_input).digest()
        limit = 2 ** 256 // self.block_chain[index].block_header.difficulty

        if int.from_bytes(sha, byteorder='big') >= limit:
            return False

        return True


if __name__ == '__main__':
    block_header = BlockHeader(0,
                               SHA256.new(b'0').digest(),
                               SHA256.new(b'').digest(),
                               SHA256.new(b'').digest(),
                               2**13,
                               0)
    chain = BlockChain(Block(block_header, MerkleTree([]), {}))
    a = time()
    for i in range(10):
        chain.mining([])
    b = time()
    print(chain.verify())
    c = time()

    print('블록 생성 시간 : ', b - a)
    print('블록 검증 시간 : ', c - b)
