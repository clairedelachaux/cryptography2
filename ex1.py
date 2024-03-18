from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
import hashlib


def bytes_XOR(a, b):
    return bytes([_a ^ _b for _a, _b in zip(a, b)])


def increment_byte(a):
    inta = int.from_bytes(a)
    inta = (inta+1) % 256
    return int.to_bytes(inta)


def PKCS5(m):
    l = len(m)
    l_hat = 2 ** 4 - l
    end = bytes(l_hat * [l_hat])
    return m + end


def AES_Keygen():
    aes_k = get_random_bytes(16)
    return aes_k


def AES_Enc(aes_k, m):
    cipher = AES.new(aes_k, AES.MODE_ECB)
    m_prime = PKCS5(m)
    r = get_random_bytes(16)
    c = r
    l = len(m_prime) // 16
    for i in range(l):
        ci = bytes_XOR(cipher.encrypt(r), m[l:(16 * l)])
        c = c + ci
        barr = bytearray(r)
        int_r = (int_r + 1) % (2 ** 16)
        r = int.to_bytes(int_r, byteorder='big')
    return c


def AES_Dec(aes_k, c):
    cipher = AES.new(aes_k, AES.MODE_CTR)
    return cipher.decrypt(c)


def MAC_Keygen():
    k1 = get_random_bytes(16)
    k2 = get_random_bytes(16)
    return (k1, k2)


def MAC(c, kMAC):
    k1 = kMAC[0]
    k2 = kMAC[1]
    h0 = k1 + c
    h1 = hashlib.sha256(h0).digest()
    h2 = k2 + h1
    return hashlib.sha256(h2).digest()


def MAC_CCA_Keygen():
    aes_k = AES_Keygen()
    mac_k = MAC_Keygen()
    return aes_k, mac_k


def MAC_CCA_Enc(m, k):
    aes_k = k[0]
    mac_k = k[1]
    c = AES_Enc(aes_k, m)
    t = MAC(c, mac_k)
    return c, t


def MAC_CCA_Dec(c, k):
    aes_k = k[0]
    mac_k = k[1]
    mprime = c[0]
    tprime = c[1]
    t = MAC(mprime, mac_k)
    if t == tprime:
        return AES_Enc(aes_k, mprime)


m = b"Hello World!!!!!"
m2 = PKCS5(m)
b = b"100001"
b = increment_byte(b)

