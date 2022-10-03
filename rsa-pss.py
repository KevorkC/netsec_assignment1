import hashlib
from hashlib import sha256
from logging import exception
import math
import os
import sys
from secret_data import rsa_key
#import DataPrimitives
#from DataPrimitives import I20SP, OS2IP, mgf1
from Crypto.PublicKey import RSA
from Crypto.Signature.pss import MGF1


def xor(a: bytes, b: bytes) -> bytes:
    return bytes(_a ^ _b for _a, _b in zip(a, b))


def i2osp_ecc(x: int, xlen: int) -> bytes:
    """
    Convert a nonnegative integer `x` to an octet string of a specified length `xlen`.
    https://tools.ietf.org/html/rfc8017#section-4.1
    """
    return x.to_bytes(xlen, byteorder='big', signed=False)


def os2ip_ecc(x: bytes) -> int:
    """
    Convert an octet string `x` to a nonnegative integer.
    https://tools.ietf.org/html/rfc8017#section-4.2
    """
    return int.from_bytes(x, byteorder='big', signed=False)
I20SP = i2osp_ecc
OS2IP = os2ip_ecc

# # Source: https://en.wikipedia.org/wiki/Mask_generation_function
# def mgf1(seed: bytes, length: int, hash_func=hashlib.sha256) -> bytes:
#     hLen = hash_func().digest_size
#     # https://www.ietf.org/rfc/rfc2437.txt
#     # 1.If l > 2^32(hLen), output "mask too long" and stop.
#     if length > (hLen << 32):
#         raise ValueError("mask too long")
#     # 2.Let T  be the empty octet string.
#     T = b""
#     # 3.For counter from 0 to \lceil{l / hLen}\rceil-1, do the following:
#     # Note: \lceil{l / hLen}\rceil-1 is the number of iterations needed,
#     #       but it's easier to check if we have reached the desired length.
#     counter = 0
#     while len(T) < length:
#         # a.Convert counter to an octet string C of length 4 with the primitive I20SP: C = I20SP (counter, 4)
#         C = int.to_bytes(counter, 4, 'big')
#         # b.Concatenate the hash of the seed Z and C to the octet string T: T = T || Hash (Z || C)
#         T += hash_func(seed + C).digest()
#         counter += 1
#     # 4.Output the leading l octets of T as the octet string mask.
#     return T[:length]

# def mgf1(mgf_seed, mask_len, hash_class=hashlib.sha1):
#     '''
#        Mask Generation Function v1 from the PKCS#1 v2.0 standard.
#        mgs_seed - the seed, a byte string
#        mask_len - the length of the mask to generate
#        hash_class - the digest algorithm to use, default is SHA1
#        Return value: a pseudo-random mask, as a byte string
#        '''
#     h_len = hash_class().digest_size
#     if mask_len > 0x10000:
#         raise ValueError('mask too long')
#     T = b''
#     for i in range(0, math.ceil(mask_len, h_len)):
#         C = I20SP(i, 4)
#         T = T + hash_class(mgf_seed + C).digest()
#     return T[:mask_len]

# Source: https://stackoverflow.com/questions/39964383/implementation-of-i2osp-and-os2ip
# def OS2IP(X: bytes) -> int:
#     """ Convert an octet string to an integer
#     Input:
#     X        octet string to be converted

#     Output:
#     x        corresponding nonnegative integer """
#     assert isinstance(X, bytes), "X must be a byte string"
#     xLen = len(X)
#     X = X[::-1]
#     x = 0
#     for i in range(xLen):
#         x += X[i] * 256**i
#     return x




def emsa_pss_encode(M: bytes, emBits: int, hash_func=hashlib.sha256, MGF=MGF1, sLen: int=0) -> bytes:
    """ Options:

    Hash     hash function (hLen denotes the length in octets of the hash
            function output)
    MGF      mask generation function
    sLen     intended length in octets of the salt

    Input:
    M        message to be encoded, an octet string
    emBits   maximal bit length of the integer OS2IP (EM) (see Section
            4.2), at least 8hLen + 8sLen + 9

    Output:
    EM       encoded message, an octet string of length emLen = \ceil
            (emBits/8) """

    # Step 1. If the length of M is greater than the input limitation for
    # the hash function (2^61 - 1 octets for SHA-1), output "message too
    # long" and stop.

    # We're defaulting to SHA-256, which has an input limitation of 2^64 - 1
    if(len(M) > 2**64 - 1):
        raise Exception("Message too long")
    
    # Step 2. Let mHash = Hash(M), an octet string of length hLen.
    mHash = hash_func(M).digest()

    # Step 3. If emLen < hLen + sLen + 2, output "encoding error" and stop.
    hLen = hash_func().digest_size
    emLen = math.ceil(emBits / 8)
    if(emLen < hLen + sLen + 2):
        raise Exception("Encoding error")

    # Step 4. Generate a random octet string salt of length sLen; if sLen = 0,
    # then salt is the empty string.
    salt = b""
    if(sLen > 0):
        salt = os.urandom(sLen)
    
    # Step 5. Let
    #   M' = (0x)00 00 00 00 00 00 00 00 || mHash || salt;
    # M' is an octet string of length 8 + hLen + sLen with eight
    # initial zero octets.
    M_prime = b"0x00" * 8 + mHash + salt

    # Step 6. Let H = Hash(M'), an octet string of length hLen.
    H = hash_func(M_prime).digest()

    # Step 7. Generate an octet string PS consisting of emLen - sLen - hLen - 2
    # zero octets.  The length of PS may be 0.
    PS = b"\x00" * (emLen - sLen - hLen - 2)

    # Step 8. Let DB = PS || 0x01 || salt; DB is an octet string of length
    # emLen - hLen - 1.
    DB = PS + b"\x01" + salt

    # Step 9. Let dbMask = MGF(H, emLen - hLen - 1).
    dbMask = MGF(H, emLen - hLen - 1, hash_func())

    # Step 10. Let maskedDB = DB \xor dbMask.
    # TODO: Use consistent xor in encode and verify
    maskedDB = bytes([a ^ b for a, b in zip(DB, dbMask)])

    # Step 11. Set the leftmost 8*emLen - emBits bits of the leftmost octet in
    # maskedDB to zero.
    nr_bits_to_zero = 8 * emLen - emBits
    # Example: nr_bits_to_zero=3 then 0b11111111 >> 3 = 0b00011111
    mask = 0xFF >> nr_bits_to_zero
    modified_leftmost_byte = maskedDB[0] & mask
    # Set the leftmost bits to zero
    maskedDB = modified_leftmost_byte.to_bytes(1, 'big') + maskedDB[1:]

    # Step 12. Let EM = maskedDB || H || 0xbc.
    EM = maskedDB + H + b"\xbc"
    
    return EM

def RSASP1(N: int, d: int, m: int) -> int:
    """ Textbook RSA message signing  
    Input:
    (N, d)  private RSA key pair
    m       message representative, an integer between 0 and N - 1
    Output:
    s       signature representative, an integer between 0 and N - 1
    """

    # Step 1. If m is not an integer between 0 and n - 1, output "message
    # representative out of range" and stop.
    assert isinstance(m, int), "Message representative must be an integer"
    assert 0 < m and m < N, "Message representative out of range"
    
    # Step 2 Compute s = m^d mod N.
    s = pow(m, d, N)

    return s

def RSAVP1(N: int, e: int, s: int) -> int:
    """
    Input:
    (n, e)   RSA public key
    s        signature representative, an integer between 0 and n - 1

    Output:
    m        message representative, an integer between 0 and n - 1

    Error: "signature representative out of range"
    """
    assert isinstance(s, int), "Signature representative must be an integer"
    assert 0 < s and s < N, "Signature representative out of range"
    
    m = pow(s, e, N)
    return m

def emsa_pss_verify(M: bytes, EM: bytes, emBits: int, hash_func=hashlib.sha256, sLen: int=0, MGF=MGF1) -> bool:
    """     
    Input:
    M        message to be verified, an octet string
    EM       encoded message, an octet string of length emLen = \ceil
            (emBits/8)
    emBits   maximal bit length of the integer OS2IP (EM) (see Section
            4.2), at least 8hLen + 8sLen + 9

    Output:
    True if consistent, False if inconsistent

    Step 1. If the length of M is greater than the input limitation for
    the hash function (2^61 - 1 octets for SHA-1), output "inconsistent"
    and stop. 
    """
    assert isinstance(EM, bytes), "EM must be a byte string"
    assert isinstance(M, bytes), "M must be a byte string"
    assert len(M) < 2**64 - 1, f"length of M ({len(M)}, {len(M)-2**64-1} too large) is greater than the input limitation for the hash function (2^64 - 1 octets for SHA-256)"
    #if(len(M) > 2**61 - 1):
    #    return False
    
    # Step 2. Let mHash = Hash(M), an octet string of length hLen.
    mHash = hash_func(M).digest()

    # Step 3. If emLen < hLen + sLen + 2, output "inconsistent" and stop.
    hLen = hash_func().digest_size
    assert hash_func().digest_size == len(mHash)
    emLen = math.ceil(emBits / 8)

    assert emLen >= hLen + sLen + 2, f"emLen ({emLen}) < hLen ({hLen}) + sLen ({sLen}) + 2"
    
    # Step 4. If the rightmost octet of EM does not have hexadecimal value
    # 0xbc, output "inconsistent" and stop.
    assert EM[-1] == 0xbc, "Rightmost octet of EM does not have hexadecimal value 0xbc"
    
    # Step 5. Let maskedDB be the leftmost emLen - hLen - 1 octets of EM,
    # and let H be the next hLen octets.
    maskedDB = EM[:emLen - hLen - 1]
    H = EM[emLen - hLen - 1:- 1]

    # Step 6. If the leftmost 8*emLen - emBits bits of the leftmost octet in
    # maskedDB are not all equal to zero, output "inconsistent" and stop.
    leftmost_octet_in_maskedDB = maskedDB[0]
    number_of_leftmost_bits = 8 * emLen - emBits

    # TODO: A diagram to check if this is correct
    assert isinstance(leftmost_octet_in_maskedDB, int)
    if(0 | leftmost_octet_in_maskedDB >> (8 - number_of_leftmost_bits) != 0):
        return False

    # Step 7. Let dbMask = MGF(H, emLen - hLen - 1).
    dbMask = MGF(H, emLen - hLen - 1, hash_func)

    # Step 8. Let DB = maskedDB \xor dbMask.
    DB = bytes([maskedDB[i] ^ dbMask[i] for i in range(len(maskedDB))])

    # Step 9. Set the leftmost 8*emLen - emBits bits of the leftmost octet in
    # DB to zero.
    # TODO: Maybe implement this line in multiple steps
    DB = bytes([DB[0] & (0xff >> number_of_leftmost_bits)]) + DB[1:]

    # Step 10. If the emLen - hLen - sLen - 2 leftmost octets of DB are not
    # zero or if the octet at position emLen - hLen - sLen - 1 (the leftmost
    # position is "position 1") does not have hexadecimal value 0x01,
    # output "inconsistent" and stop.
    for b in DB[:emLen - hLen - sLen - 2]:
        if b != 0x00:
            return False

    if not DB[emLen - hLen - sLen - 2] == 0x01:
        return False

    # Step 11. Let salt be the last sLen octets of DB.
    salt = b""
    if sLen != 0: # If sLen is 0, then DB[-0:] would return the entire DB
        salt = DB[-sLen:]

    # Step 12. Let M' = (0x)00 00 00 00 00 00 00 00 || mHash || salt;
    # M' is an octet string of length 8 + hLen + sLen with eight
    # initial zero octets.
    assert isinstance(mHash, bytes) and isinstance(salt, bytes)
    M_ = b"\x00" * 8 + mHash + salt
    
    # Step 13. Let H' = Hash(M'), an octet string of length hLen.
    H_ = hash_func(M_).digest()

    # Step 14. If H = H', output "consistent." Otherwise, output
    # "inconsistent."

    print(f"H:  {H.hex()}")
    print(f"H': {H_.hex()}")
    return H == H_


#                           +-----------+
#                           |     M     |
#                           +-----------+
#                                 |
#                                 V
#                               Hash
#                                 |
#                                 V
#                   +--------+----------+----------+
#              M' = |Padding1|  mHash   |   salt   |
#                   +--------+----------+----------+
#                                  |
#        +--------+----------+     V
#  DB =  |Padding2|maskedseed|   Hash
#        +--------+----------+     |
#                  |               |
#                  V               |    +--+
#                 xor <--- MGF <---|    |bc|
#                  |               |    +--+
#                  |               |      |
#                  V               V      V
#        +-------------------+----------+--+
#  EM =  |    maskedDB       |maskedseed|bc|
#        +-------------------+----------+--+

def sign(K: int, N: int, M: bytes) -> bytes:
    """ Sign a message using RSA-PSS
    Input:
    K        signer's RSA private key
    M        message to be signed, an octet string
    N        the modulus of the RSA public key
    Output:
    S       signature, an octet string of length k, where k is the
            length in octets of the RSA modulus n """

    # e = 2**16 - 1 # 65535 public_key
    # d = 0 # private_key
    # N = 0 # modulus

    # Step 1. EMSA-PSS encoding: Apply the EMSA-PSS encoding operation
    # to the message M to produce an encoded message EM of length
    # emLen = \ceil((modBits - 1)/8) octets, such that the bit length of the
    # integer OS2IP (EM) (see Section 4.2) is at most modBits - 1, where
    # modBits is the length in bits of the RSA modulus n:

    modBits = N.bit_length()
    try:
        EM = emsa_pss_encode(M, modBits - 1)
    except Exception as e:
        print(e)
        raise ValueError("invalid input")
    # Step 2.a Convert the encoded message EM to an integer message
    # representative m
    m = OS2IP(EM)

    # Step 2.b Apply the RSASP1 signature primitive to the RSA
    # private key K and the message representative m to produce an
    # integer signature representative s
    s = RSASP1(N, K, m)

    # Step 3.c Convert the signature representative s to a signature
    # S of length k octets
    k = N.bit_length()
    S = I20SP(s, k)

    assert len(S) == k, "length of signature must equal k"
    return S


def verify(n: int, e: int, M: bytes, S: bytes) -> bool:
    """ Verify a signature using RSA-PSS 
    Input:
    (n, e)   signer's RSA public key
    M        message whose signature is to be verified, an octet string
    S        signature to be verified, an octet string of length k, where
            k is the length in octets of the RSA modulus n
   Output:
   "valid signature" or "invalid signature"
    """
    assert(len(S) == n.bit_length())

    # Step 1. Check that the length of the signature is k octets 
    # where k is the length in octets of the RSA modulus n
    k = n.bit_length()
    print(f"S: {len(S)}, k: {k}")
    if(len(S) != k):
        raise ValueError("invalid signature")

    # Step 2.a Convert the signature to an integer
    s: int = OS2IP(S)

    # Step 2.b Apply the RSAVP1 verification primitive (Section 5.2.2) to the 
    # RSA public key (n, e) and the signature representative s to produce an 
    # integer message representative m:
    m: int = RSAVP1(n, e, s)

    modBits = n.bit_length()

    # Step 2.c Convert the message representative m to an encoded message EM
    # of length emLen = \ceil ((modBits - 1)/8) octets, where modBits is the 
    # length in bits of the RSA modulus n (see Section 4.1):
    emLen = math.ceil((modBits - 1) / 8)

    try:
        EM = I20SP(m, emLen)
    except ValueError: # integer too large
        print("integer too large")
        return False

    return emsa_pss_verify(M, EM, modBits - 1)

if __name__ == '__main__':
    N = rsa_key['_n']
    e = rsa_key['_e']
    d = rsa_key['_d']
    m = b'Sign this message'

    key = RSA.generate(2048)
    print(f"key.d: {key.d}")
    print(f"key.n: {key.n}")
    print(f"key.e: {key.e}")
    N = key.n
    e = key.e
    d = key.d

    s = sign(d, N, m)
    print(f"s: {s}")
    result = verify(N, e, m, s)
    print(f"result: {result}")

    # print(I20SP(255, 1))
    # print(OS2IP(b'\xff'))

    # This signing & verification test should pass
    # try:
    #     s = sign(d, N, m)
    #     print(f"s: {s}")
    #     assert verify(N, e, m, s)
    # except AssertionError:
    #     print("First signing & verification test failed")
    #     sys.exit(1)

    # # This verification test should fail, because the signature is invalid
    # try:
    #     s = sign(d, N, m)
    #     assert verify(N, e, m, s)
    # except AssertionError:
    #     print("Second signing & verification test failed")
    #     sys.exit(1)