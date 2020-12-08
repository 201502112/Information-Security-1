from copy import deepcopy
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

    def __eq__(self, other: 'Address'):
        """
        Dictionary의 key로 사용하기 위함
        :param other:
        :return:
        """
        return self.__address == other.__address

    def __hash__(self):
        """
        Dictionary의 Hash값을 위함
        :return:
        """
        return int.from_bytes(bytes(self), byteorder='big')

    def __repr__(self):
        """
        디버깅 시 프린트 찍을 때 주소 값을 확인하기 쉽도록 함
        :return:
        """
        return f'0x{self.__address[:12]}...'


@dataclass
class Transaction:
    sender: Address  # sender's address
    receiver: Address  # receiver's address
    value: int  # 송금액
    nonce: int  # double spending을 막기 위한 counting값
    signature: bytes or None  # Signature

    def hash(self) -> SHA256Hash:
        k = SHA256.new()
        k.update(bytes(self.sender))
        k.update(bytes(self.receiver))
        k.update(bytes(self.value))
        k.update(self.nonce.to_bytes(256, signed=True, byteorder='big'))
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
        # 트랜잭션 리스트를 저장하도록 기능 추가 (14주차)
        self.transaction_list = transaction_list

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
    nonce_dict: Dict[Address, int]


class BlockChain:
    def __init__(self, genesis_block: Block):
        self.block_chain = [genesis_block]

    def check_nonce(self, transaction_list: List[Transaction]) -> (List[Transaction], Dict[Address, int]):
        """
        Transaction 의 nonce 값을 확인

        기존 nonce_dict를 deepcopy 한 후 nonce에 대해 정렬

        nonce 값을 nonce_dict 에 있는 정보와 비교해서 double spending이 없는지 확인
        nonce값이 적절하지 않을 경우 해당 트랜잭션을 제외시킨 후 반환

        nonce_dict에 해당 address의 정보가 없을 경우 default값과 함께 추가

        :param transaction_list:
        :return: nonce 값을 확인 후 올바른 nonce를 가진
        """
        # TODO:

    def update_state_tree(self, transaction_list: List[Transaction]) -> Dict[Address, int]:
        """
        14 주 과제
        state dictionary를 트랜잭션 리스트에 맞게 업데이트 함

        트랜잭션의 송금액에 맞게 보유 금액을 조정 (차감)

        :param transaction_list:
        :return: state root 값
        """
        # TODO

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
        txs, nonce_dict = self.check_nonce(transaction_list)
        merkle_tree = MerkleTree(txs)
        merkle_root = merkle_tree.root.hash
        state_tree = self.update_state_tree(txs)
        state_hash = SHA256.new()
        for address in state_tree.keys():
            state_hash.update(bytes(address))
            state_hash.update(state_tree[address].to_bytes(256, byteorder='big'))
        state_root = state_hash.digest()
        # TODO: 이후 블록 생성 구현

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
        생성된 블록을 검증하는 함수

        :param index:
        :return:
        """
        # Check merkle root (Merkle Tree를 직접 생성해 확인)
        merkle_tree = self.block_chain[index].merkle_tree
        merkle_nodes = list(map(
            lambda transaction: MerkleNode(hash_val=bytes(transaction.hash().digest())),
            merkle_tree.transaction_list,
        ))
        root = MerkleTree.make_merkle_tree(merkle_nodes)
        if merkle_tree.root.hash != root.hash:
            return False

        # Check state tree (트랜잭션에 따라 직접 state tree를 계산해 확인)
        state_tree = self.block_chain[index].state_tree

        state = deepcopy(self.block_chain[index-1].state_tree)
        for transaction in merkle_tree.transaction_list:
            if state[transaction.sender] < transaction.value:
                continue
            if transaction.receiver not in state.keys():
                state[transaction.receiver] = 0
            state[transaction.receiver] += transaction.value
            state[transaction.sender] -= transaction.value

        if not len(state.keys()) == len(state_tree.keys()):
            return False

        for address in state.keys():
            if state[address] != state_tree[address]:
                return False

        # Check state root (state root를 직접 계산해 확인)
        state_hash = SHA256.new()
        for address in state_tree.keys():
            state_hash.update(bytes(address))
            state_hash.update(state_tree[address].to_bytes(256, byteorder='big'))
        state_root = state_hash.digest()
        if self.block_chain[index].block_header.state_root != state_root:
            return False

        # Check prev block
        if index != 0:
            prev_hash_input = bytes(self.block_chain[index - 1].block_header.block_number) + \
                              self.block_chain[index - 1].block_header.parent_hash + \
                              self.block_chain[index - 1].block_header.merkle_root + \
                              self.block_chain[index - 1].block_header.state_root + \
                              self.block_chain[index - 1].block_header.nonce.to_bytes(256, byteorder='big')
            prev_hash = SHA256.new(prev_hash_input).digest()
            if self.block_chain[index].block_header.parent_hash != prev_hash:
                return False

        # difficulty check
        hash_input = bytes(self.block_chain[index].block_header.block_number) + \
                     self.block_chain[index].block_header.parent_hash + \
                     self.block_chain[index].block_header.merkle_root + \
                     self.block_chain[index].block_header.state_root + \
                     self.block_chain[index].block_header.nonce.to_bytes(256, byteorder='big')
        sha = SHA256.new(hash_input).digest()
        limit = 2 ** 256 // self.block_chain[index].block_header.difficulty

        if int.from_bytes(sha, byteorder='big') >= limit:
            return False

        return True


def new_transaction_list(blockchain: BlockChain, _admin, _admin_sk):
    """
    새로운 임의 transaction 생성
    :param blockchain:
    :param _admin:
    :param _admin_sk:
    :return:
    """
    addresses = []
    txs = []
    last_block = blockchain.block_chain[-1]
    admin_nonce = last_block.nonce_dict[_admin]
    for i in range(1, 11):
        _key = ECC.generate(curve='P-256')
        _address = Address(bytes(_key.export_key(format='DER')))
        addresses.append(_address)
        tx = Transaction(_admin, _address, 10000, admin_nonce+i, None)
        tx.sign(_admin_sk)
        txs.append(tx)
    return txs


if __name__ == '__main__':
    key = ECC.generate(curve='P-256')
    admin = Address(bytes(key.export_key(format='DER')))
    block_header = BlockHeader(0,
                               SHA256.new(b'0').digest(),
                               SHA256.new(b'').digest(),
                               SHA256.new(b'').digest(),
                               2 ** 13,
                               0)
    chain = BlockChain(Block(block_header, MerkleTree([]), {admin: 10000000}, {admin:-1}))
    a = time()
    for i in range(2):
        chain.mining(new_transaction_list(chain, admin, key))
    b = time()
    print(chain.verify())
    c = time()

    print('블록 생성 시간 : ', b - a)
    print('블록 검증 시간 : ', c - b)
