from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
import hashlib


def PKCS5(m):
    l = len(m)
    l_hat = 2 ** 4 - l
    end = bytes(l_hat * [l_hat])
    return m + end


def AES_Keygen():
    aes_k = get_random_bytes(16)
    return aes_k


def AES_Enc(aes_k, m):
    cipher = AES.new(aes_k, AES.MODE_CTR, nonce=nonce)
    return cipher.encrypt(m)


def AES_Dec(aes_k, c):
    cipher = AES.new(aes_k, AES.MODE_CTR, nonce=nonce)
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


global nonce
nonce = get_random_bytes(8)
data = b"Hello World!"
data2 = b"Another message"
key = MAC_CCA_Keygen()
c = MAC_CCA_Enc(data, key)
c2 = [data2, c[1]]
m = MAC_CCA_Dec(c, key)
m2 = MAC_CCA_Dec(c2, key)
print(m, "\n", m2)
