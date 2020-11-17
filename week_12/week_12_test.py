from Crypto.Hash import SHA256
from Crypto.PublicKey import ECC

from week_12.block import MerkleTree, Transaction, Address, MerkleNode


def test_merkle_root():
    sender_key = ECC.generate(curve='P-256')
    sender_address = Address(bytes(sender_key.public_key().export_key(format='DER')))
    receiver_key = ECC.generate(curve='P-256')
    receiver_address = Address(bytes(receiver_key.public_key().export_key(format='DER')))

    transaction1 = Transaction(sender_address, receiver_address, 100, b'random', None)
    transaction1.sign(sender_key)
    transaction2 = Transaction(sender_address, receiver_address, 50, b'random', None)
    transaction2.sign(sender_key)
    transaction3 = Transaction(receiver_address, sender_address, 10, b'random', None)
    transaction3.sign(receiver_key)
    transaction4 = Transaction(sender_address, receiver_address, 60, b'random', None)
    transaction4.sign(sender_key)

    tree = MerkleTree([transaction1, transaction2, transaction3, transaction4])
    h1 = SHA256.new()
    h1.update(transaction1.hash().digest())
    h1.update(transaction2.hash().digest())
    h2 = SHA256.new()
    h2.update(transaction3.hash().digest())
    h2.update(transaction4.hash().digest())
    h3 = SHA256.new()
    h3.update(h1.digest())
    h3.update(h2.digest())
    root = h3.digest()

    assert tree.merkle_root() == root


def test_merkle_root_with_odd_numbers():
    sender_key = ECC.generate(curve='P-256')
    sender_address = Address(bytes(sender_key.public_key().export_key(format='DER')))
    receiver_key = ECC.generate(curve='P-256')
    receiver_address = Address(bytes(receiver_key.public_key().export_key(format='DER')))

    transaction1 = Transaction(sender_address, receiver_address, 100, b'random', None)
    transaction1.sign(sender_key)
    transaction2 = Transaction(sender_address, receiver_address, 50, b'random', None)
    transaction2.sign(sender_key)
    transaction3 = Transaction(receiver_address, sender_address, 10, b'random', None)
    transaction3.sign(receiver_key)
    transaction4 = Transaction(sender_address, receiver_address, 60, b'random', None)
    transaction4.sign(sender_key)
    transaction5 = Transaction(receiver_address, sender_address, 80, b'random', None)
    transaction5.sign(receiver_key)

    tree = MerkleTree([transaction1, transaction2, transaction3, transaction4, transaction5])
    h1 = SHA256.new()
    h1.update(transaction1.hash().digest())
    h1.update(transaction2.hash().digest())
    h2 = SHA256.new()
    h2.update(transaction3.hash().digest())
    h2.update(transaction4.hash().digest())
    h3 = SHA256.new()
    h3.update(h1.digest())
    h3.update(h2.digest())
    h4 = SHA256.new()
    h4.update(h3.digest())
    h4.update(transaction5.hash().digest())

    root = h4.digest()

    assert tree.merkle_root() == root


def test_merkle_tree():
    sender_key = ECC.generate(curve='P-256')
    sender_address = Address(bytes(sender_key.public_key().export_key(format='DER')))
    receiver_key = ECC.generate(curve='P-256')
    receiver_address = Address(bytes(receiver_key.public_key().export_key(format='DER')))

    transaction1 = Transaction(sender_address, receiver_address, 100, b'random', None)
    transaction1.sign(sender_key)
    transaction2 = Transaction(sender_address, receiver_address, 50, b'random', None)
    transaction2.sign(sender_key)
    transaction3 = Transaction(receiver_address, sender_address, 10, b'random', None)
    transaction3.sign(receiver_key)
    transaction4 = Transaction(sender_address, receiver_address, 60, b'random', None)
    transaction4.sign(sender_key)
    transaction5 = Transaction(receiver_address, sender_address, 80, b'random', None)
    transaction5.sign(receiver_key)

    tree = MerkleTree([transaction1, transaction2, transaction3, transaction4, transaction5])

    assert tree.root.left is not None
    assert tree.root.left.left.left.hash == bytes(transaction1.hash().digest())
    assert tree.root.left.left.right.hash == bytes(transaction2.hash().digest())
    assert tree.root.left.right.left.hash == bytes(transaction3.hash().digest())
    assert tree.root.left.right.right.hash == bytes(transaction4.hash().digest())
    assert tree.root.right.hash == bytes(transaction5.hash().digest())
