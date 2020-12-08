from Crypto.Hash import SHA256
from Crypto.PublicKey import ECC

from week_13.blockchain import Address, BlockHeader, BlockChain, Block, MerkleTree, new_transaction_list, Transaction


def test_mining():
    key = ECC.generate(curve='P-256')
    admin = Address(bytes(key.export_key(format='DER')))
    block_header = BlockHeader(0,
                               SHA256.new(b'0').digest(),
                               SHA256.new(b'').digest(),
                               SHA256.new(b'').digest(),
                               2 ** 13,
                               0)
    chain = BlockChain(Block(block_header, MerkleTree([]), {admin: 10000000}, {admin: -1}))
    chain.mining(new_transaction_list(chain, admin, key))
    assert chain.block_chain[-1].merkle_tree.root.hash == chain.block_chain[-1].block_header.merkle_root
    assert chain.block_chain[-1].nonce_dict[admin] == 9


def test_verify():
    key = ECC.generate(curve='P-256')
    admin = Address(bytes(key.export_key(format='DER')))
    block_header = BlockHeader(0,
                               SHA256.new(b'0').digest(),
                               SHA256.new(b'').digest(),
                               SHA256.new(b'').digest(),
                               1,
                               0)
    chain = BlockChain(Block(block_header, MerkleTree([]), {admin: 10000000}, {admin: -1}))
    chain.mining(new_transaction_list(chain, admin, key))
    assert chain.verify()


def test_mining_wrong_transactions():
    key = ECC.generate(curve='P-256')
    admin = Address(bytes(key.export_key(format='DER')))
    block_header = BlockHeader(0,
                               SHA256.new(b'0').digest(),
                               SHA256.new(b'').digest(),
                               SHA256.new(b'').digest(),
                               1,
                               0)
    chain = BlockChain(Block(block_header, MerkleTree([]), {admin: 10000000}, {admin: -1}))

    addresses = []
    txs = []
    for i in range(1, 11):
        _key = ECC.generate(curve='P-256')
        _address = Address(bytes(_key.export_key(format='DER')))
        addresses.append(_address)
        tx = Transaction(admin, _address, 10000, i-6, None)
        tx.sign(key)
        txs.append(tx)

    chain.mining(txs)
    assert chain.verify()
    assert chain.block_chain[-1].nonce_dict[admin] == 4
    assert chain.block_chain[-1].state_tree[admin] == 10000000 - 5 * 10000


def test_mining_double_spending():
    key = ECC.generate(curve='P-256')
    admin = Address(bytes(key.export_key(format='DER')))
    block_header = BlockHeader(0,
                               SHA256.new(b'0').digest(),
                               SHA256.new(b'').digest(),
                               SHA256.new(b'').digest(),
                               1,
                               0)
    chain = BlockChain(Block(block_header, MerkleTree([]), {admin: 10000000}, {admin: -1}))

    addresses = []
    txs = []
    for i in range(1, 11):
        _key = ECC.generate(curve='P-256')
        _address = Address(bytes(_key.export_key(format='DER')))
        addresses.append(_address)
        tx = Transaction(admin, _address, 10000, 0, None)
        tx.sign(key)
        txs.append(tx)

    chain.mining(txs)
    assert chain.verify()
    assert chain.block_chain[-1].nonce_dict[admin] == 0
    assert chain.block_chain[-1].state_tree[admin] == 10000000 - 10000
