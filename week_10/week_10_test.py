from Crypto.Hash import SHA256
from Crypto.PublicKey import ECC
from Crypto.Signature import DSS

from week_10.cert import load, verify


def test_verify():
    assert verify()


def test_student_id():
    cert = load()
    assert cert['student_id'] != '202099999'


def test_cert_public_key():
    cert = load()
    assert cert['public_key'] is not None
    try:
        ECC.import_key(cert['public_key'])
    except:
        assert False


def test_cert_sign():
    cert = load()
    assert cert['sign'] is not None
    pub_key = ECC.import_key(cert['public_key'])
    sign = bytes.fromhex(cert['sign'])
    verifier = DSS.new(pub_key, 'fips-186-3')
    hash_value = SHA256.new((cert['student_id']+cert['is_success']+str(cert['week'])).encode('utf-8'))
    try:
        verifier.verify(hash_value, sign)
    except:
        assert False
