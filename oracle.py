
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5

class Oracle():
  

    def __init__(self):
        """
        Setup keys, secret message and encryption/decryption schemes.
        """
        self._key = RSA.generate(1024)
        self._pkcs = PKCS1_v1_5.new(self._key)
        self._secret = b'.....Using adaptive chosen-ciphertext to attack RSA!.....'
        self._pkcsmsg = self._pkcs.encrypt(self._secret)

    def get_n(self) -> int:
        """
        Returns the public RSA modulus.
        """
        return self._key.n

    def get_e(self) -> int:
        """
        Returns the public RSA exponent.
        """
        return self._key.e

    def get_k(self) -> int:
        """
        Returns the length of the RSA modulus in bytes.
        """
        return (self._key.size() + 1) // 8

    def get_ciphertext(self) -> bytes:
        return self._pkcsmsg

    def check_pkcs_format(self, ciphertext: bytes) -> bool:
        """
        :param ciphertext: Ciphertext that contains the message to recover.
        :return: True if the decrypted message is correctly padded according to PKCS#1 v1.5; otherwise False.
        """

        if len(ciphertext) != self.get_k():
            raise ValueError("Ciphertext with incorrect length.")

        m = self._key.decrypt(ciphertext)

        em = b"\x00" * (self.get_k() - len(m)) + m

        sep = em.find(b"\x00", 2)

        # TODO: Justify oracle strength... --> for testing purposes

        if not em.startswith(b'\x00\x02'):
            return False

        # if not em.startswith(b'\x00\x02') or sep < 10:  
        #    return False

        return True
