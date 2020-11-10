from Crypto.PublicKey import ECC

from week_11.cert import Issuer, Holder, Verifier


def test_pki():
    root_key = ECC.generate(curve='P-256')
    root = Issuer(bytes(root_key.export_key(format='DER')))

    holder_key = ECC.generate(curve='P-256')
    holder = Holder(bytes(holder_key.export_key(format='DER')))
    certs = root.issue(holder.public_key())
    holder.set_cert(certs)

    verifier = Verifier(root.public_key())
    nonce = b'123'
    certs, sign = holder.present(nonce)
    assert verifier.verify(certs, holder.public_key(), nonce, sign)


def test_deep_pki():
    root_key = ECC.generate(curve='P-256')
    root = Issuer(bytes(root_key.export_key(format='DER')))

    issuer2_key = ECC.generate(curve='P-256')
    issuer2_key_bytes = bytes(issuer2_key.export_key(format='DER'))
    issuer2_public_key_bytes = bytes(issuer2_key.public_key().export_key(format='DER'))
    issuer2 = Issuer(issuer2_key_bytes, root.issue(issuer2_public_key_bytes))

    issuer3_key = ECC.generate(curve='P-256')
    issuer3_key_bytes = bytes(issuer3_key.export_key(format='DER'))
    issuer3_public_key_bytes = bytes(issuer3_key.public_key().export_key(format='DER'))
    issuer3 = Issuer(issuer3_key_bytes, issuer2.issue(issuer3_public_key_bytes))

    holder_key = ECC.generate(curve='P-256')
    holder = Holder(bytes(holder_key.export_key(format='DER')))
    certs = issuer3.issue(holder.public_key())
    holder.set_cert(certs)

    verifier = Verifier(root.public_key())
    nonce = b'20201111'
    certs, sign = holder.present(nonce)

    assert len(root.cert_chain) == 0
    assert len(issuer2.cert_chain) == 1
    assert len(issuer3.cert_chain) == 2
    assert len(holder.cert) == 3

    assert verifier.verify(certs, holder.public_key(), nonce, sign)


def test_changed_key():
    root_key = ECC.generate(curve='P-256')
    root = Issuer(bytes(root_key.export_key(format='DER')))

    issuer2_key = ECC.generate(curve='P-256')
    issuer2_key_bytes = bytes(issuer2_key.export_key(format='DER'))
    issuer2_public_key_bytes = bytes(issuer2_key.public_key().export_key(format='DER'))
    issuer2 = Issuer(issuer2_key_bytes, root.issue(issuer2_public_key_bytes))

    new_key = ECC.generate(curve='P-256')
    issuer2.change_secret(bytes(new_key.export_key(format='DER')))

    holder_key = ECC.generate(curve='P-256')
    holder = Holder(bytes(holder_key.export_key(format='DER')))
    certs = issuer2.issue(holder.public_key())
    holder.set_cert(certs)

    verifier = Verifier(root.public_key())
    nonce = b'20201111'
    certs, sign = holder.present(nonce)

    assert not verifier.verify(certs, holder.public_key(), nonce, sign)


def test_no_ca():
    holder_key = ECC.generate(curve='P-256')
    holder = Holder(bytes(holder_key.export_key(format='DER')))
    verifier = Verifier(b'')
    nonce = b'20201111'
    certs, sign = holder.present(nonce)
    assert not verifier.verify(certs, holder.public_key(), nonce, sign)


def test_root_ca():
    root_key = ECC.generate(curve='P-256')
    issuer = Issuer(bytes(root_key.export_key(format='DER')))
    holder = Holder(bytes(root_key.export_key(format='DER')))
    verifier = Verifier(holder.public_key())
    nonce = b'20201111'
    certs, sign = holder.present(nonce)
    assert verifier.verify(certs, holder.public_key(), nonce, sign)

