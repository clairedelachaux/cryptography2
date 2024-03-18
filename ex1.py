from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
import hashlib


def bytes_XOR(a, b):
    return bytes([_a ^ _b for _a, _b in zip(a, b)])


def increment_byte(a):
    n = len(a)
    b = b""
    c = 1
    for i in range(n - 1, -1, -1):
        sum = a[i] + c
        c = sum // 256
        b = int.to_bytes(sum % 256) + b
    return b


def PKCS5(m):
    l = len(m) // 16
    l_hat = 16 - l
    end = bytes(l_hat * [l_hat])
    return m + end


def AES_Keygen():
    aes_k = get_random_bytes(16)
    return aes_k


def AES_Enc(aes_k, m):
    cipher = AES.new(aes_k, AES.MODE_ECB)
    r = get_random_bytes(16)
    c = r
    l = len(m) // 16
    for i in range(l):
        fi = cipher.encrypt(r)
        ci = bytes_XOR(fi, m[16*i:16*(i + 1)])
        c = c + ci
        r = increment_byte(r)
    return c


def AES_Dec(aes_k, c):
    cipher = AES.new(aes_k, AES.MODE_ECB)
    r = c[0:16]
    m = b""
    l = len(c) // 16
    for i in range(1, l):
        fi = cipher.encrypt(r)
        mi = bytes_XOR(fi, c[16*i:16*(i + 1)])
        m = m + mi
        r = increment_byte(r)
    return m


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
    mprime = PKCS5(m)
    c = AES_Enc(aes_k, mprime)
    t = MAC(c, mac_k)
    return c, t


def MAC_CCA_Dec(c, k):
    aes_k = k[0]
    mac_k = k[1]
    mprime = c[0]
    tprime = c[1]
    t = MAC(mprime, mac_k)
    if t == tprime:
        return AES_Dec(aes_k, mprime)


k = MAC_CCA_Keygen()
m = b"Hello World!"
c1 = MAC_CCA_Enc(m, k)
c2 = (c1[0], b"0"+c1[1][1:])
m1 = MAC_CCA_Dec(c1, k)
m2 = MAC_CCA_Dec(c2, k)
print(m, m1, m2, sep="\n")
