from Crypto.PublicKey import ECC

from week_5.rsa import inverse


def bitfield(n):
    return [int(digit) for digit in bin(n)[2:]]


class Curve:
    def __init__(self, a: int, b: int, p: int):
        """
        y^2 = x^3 + ax + b
        :param a:
        :param b:
        :param p:
        """
        self.a = a
        self.b = b
        self.p = p

    def is_zero(self) -> bool:
        return self.p == 0

    @classmethod
    def zero(cls) -> "Curve":
        return Curve(0, 0, 0)


class Point:
    def __init__(self, curve: Curve, x: int, y: int):
        self.curve = curve
        self.x = x
        self.y = y

    def addition(self, point: "Point") -> "Point":
        inc = (point.y - self.y) * inverse(point.x - self.x, self.curve.p) % self.curve.p
        x = (inc * inc - self.x - point.x) % self.curve.p
        y = ((self.x - x) * inc - self.y) % self.curve.p
        return Point(self.curve, x, y)

    def doubling(self) -> "Point":
        inc = (3 * self.x * self.x + self.curve.a) * inverse(2 * self.y, self.curve.p) % self.curve.p
        x = (inc * inc - 2 * self.x) % self.curve.p
        y = ((self.x - x) * inc - self.y) % self.curve.p
        return Point(self.curve, x, y)

    def sign(self, message: int) -> int:
        pass

    def verify(self, signature: int) -> bool:
        pass

    def __eq__(self, other: "Point"):
        return self.x == other.x and self.y == other.y

    def __add__(self, other: "Point") -> "Point":
        if self == self.zero():
            return other
        if other == self.zero():
            return self
        if self.x == other.x and self.y == -other.y:
            return self.zero()
        if self == other:
            return self.doubling()
        return self.addition(other)

    def __sub__(self, other: "Point") -> "Point":
        return self + (-other)

    def __mul__(self, other: int) -> "Point":
        li = bitfield(other)
        li.reverse()
        a = self
        res = self.zero()
        for i in li:
            if i == 1:
                res += a
            a += a
        return res

    def __neg__(self) -> "Point":
        return Point(self.curve, self.x, -self.y)

    def __str__(self):
        return f"point x:{self.x}, y:{self.y}"

    def is_zero(self):
        return self.x == -1 and self.y == -1

    @classmethod
    def zero(cls) -> "Point":
        return Point(Curve.zero(), -1, -1)
