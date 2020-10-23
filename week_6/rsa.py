
def gcd(a: int, b: int) -> int:
    """
    최대공약수를 구하는 함수
    유클리드 호제법을 이용
    :param a:
    :param b:
    :return:
    """
    while b != 0:
        a, b = b, a % b
    return a


def lcm(a: int, b: int) -> int:
    """
    최소공배수를 구하는 함수
    :param a:
    :param b:
    :return:
    """
    return a * b // gcd(a, b)


def extended_euclidean(a: int, b: int) -> (int, int):
    """
    확장 유클리드 호제법
    :param a:
    :param b:
    :return:
    """
    x0, y0 = 1, 0
    x1, y1 = 0, 1
    while b != 0:
        q, a, b = a // b, b, a % b
        x0, x1 = x1, x0 - q * x1
        y0, y1 = y1, y0 - q * y1
    return x0, y0


def inverse(a: int, mod: int) -> int:
    """
    modular inverse 값
    :param a:
    :param mod:
    :return:
    """
    if gcd(a, mod) != 1:
        raise ValueError("Can't get inverse")
    x, y = extended_euclidean(a, mod)
    return x % mod


class RSAKey:
    def __init__(self, p, q):
        self.p = p
        self.q = q
        self.n = p * q
        self.e = self.public()
        self.d = self.private()

    def public(self, e=2) -> int:
        """
        조건을 만족하는 public key 를 구하는 함수
        :return:
        """
        totient = lcm(self.p-1, self.q-1)
        while gcd(e, totient) != 1:
            e += 1
        return e

    def private(self) -> int:
        """
        public key에 맞는 private key를 계산하는 함수
        :return:
        """
        totient = lcm(self.p-1, self.q-1)
        return inverse(self.e, totient)

    def set_e(self, e: int):
        """
        public key를 설정하는 함수
        :param e:
        :return:
        """
        self.e = self.public(e)
        self.d = self.private()

    def encrypt(self, m: int):
        """
        공개키로 값을 암호화하는 함수
        개인키로 암호화한 값을 복호화할 수 있음
        :param m:
        :return:
        """
        return pow(m, self.e, self.n)

    def decrypt(self, m: int):
        """
        개인키로 값을 암호화하는 함수 ( 서명 )
        공개키로 암호화한 값을 복호화할 수 있음
        :param m:
        :return:
        """
        return pow(m, self.d, self.n)
