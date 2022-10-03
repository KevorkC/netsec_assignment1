import hashlib
from hashlib import sha256
import math
import os
import sys

""" The following couple feunctions are helper functions """

# Source: https://en.wikipedia.org/wiki/Mask_generation_function
def mgf1(seed: bytes, length: int, hash_func=hashlib.sha256) -> bytes:
    hLen = hash_func().digest_size
    # https://www.ietf.org/rfc/rfc2437.txt
    # 1.If l > 2^32(hLen), output "mask too long" and stop.
    if length > (hLen << 32):
        raise ValueError("mask too long")
    # 2.Let T  be the empty octet string.
    T = b""
    # 3.For counter from 0 to \lceil{l / hLen}\rceil-1, do the following:
    # Note: \lceil{l / hLen}\rceil-1 is the number of iterations needed,
    #       but it's easier to check if we have reached the desired length.
    counter = 0
    while len(T) < length:
        # a.Convert counter to an octet string C of length 4 with the primitive I2OSP: C = I2OSP (counter, 4)
        C = int.to_bytes(counter, 4, 'big')
        # b.Concatenate the hash of the seed Z and C to the octet string T: T = T || Hash (Z || C)
        T += hash_func(seed + C).digest()
        counter += 1
    # 4.Output the leading l octets of T as the octet string mask.
    return T[:length]

# Source: https://stackoverflow.com/questions/39964383/implementation-of-i2osp-and-os2ip
def os2ip(X):
        xLen = len(X)
        X = X[::-1]
        x = 0
        for i in range(xLen):
            x += X[i] * 256**i
        return x

# Source: https://stackoverflow.com/questions/39964383/implementation-of-i2osp-and-os2ip
def i2osp(x, xLen):
        if x >= 256**xLen:
            raise ValueError("integer too large")
        digits = []

        while x:
            digits.append(int(x % 256))
            x //= 256
        for i in range(xLen - len(digits)):
            digits.append(0)
        return digits[::-1]


def emsa_pss_encode(M: bytes, emBits: int, hash_func=hashlib.sha256, MGF=mgf1, sLen: int=0) -> bytes:
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
    dbMask = MGF(H, emLen - hLen - 1)

    # Step 10. Let maskedDB = DB \xor dbMask.
    # TODO: Use consistent xor in encode and verify
    maskedDB = bytes([a ^ b for a, b in zip(DB, dbMask)])

    # Step 11. Set the leftmost 8*emLen - emBits bits of the leftmost octet in
    # maskedDB to zero.
    # FIXME: Could be wrong
    maskedDB = maskedDB[:-1] + bytes([maskedDB[-1] & (0xff >> (8 * emLen - emBits))])

    # Step 12. Let EM = maskedDB || H || 0xbc.
    EM = maskedDB + H + b"\xbc"
    
    return EM

# Input:
#    (n, e)   RSA public key
#    s        signature representative, an integer between 0 and n - 1

#    Output:
#    m        message representative, an integer between 0 and n - 1

#    Error: "signature representative out of range"
def RSAVP1(n: int, e: int, s: int) -> int:
    if(s < 0 or s > n - 1):
        raise Exception("Signature representative out of range")

    m = pow(s, e, n)
    return m

def emsa_pss_verify(M: bytes, EM: bytes, emBits: int, hash_func=hashlib.sha256, sLen: int=0, MGF=mgf1) -> bool:
    # Input:
    # M        message to be verified, an octet string
    # EM       encoded message, an octet string of length emLen = \ceil
    #         (emBits/8)
    # emBits   maximal bit length of the integer OS2IP (EM) (see Section
    #         4.2), at least 8hLen + 8sLen + 9

    # Output:
    # True if consistent, False if inconsistent

    # Step 1. If the length of M is greater than the input limitation for
    # the hash function (2^61 - 1 octets for SHA-1), output "inconsistent"
    # and stop.
    if(len(M) > 2**61 - 1):
        return False
    
    # Step 2. Let mHash = Hash(M), an octet string of length hLen.
    mHash = hash_func(M).digest()

    # Step 3. If emLen < hLen + sLen + 2, output "inconsistent" and stop.
    hLen = hash_func().digest_size
    emLen = math.ceil(emBits / 8)

    if(emLen < hLen + sLen + 2):
        return False
    
    # Step 4. If the rightmost octet of EM does not have hexadecimal value
    # 0xbc, output "inconsistent" and stop.
    if(EM[-1] != 0xbc):
        return False
    
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
    #modBits = 0
    EM = emsa_pss_encode(M, modBits - 1)
    # Convert the encoded message EM to an integer message
        #  representative m
    m = os2ip(EM)
    # Apply the RSASP1 signature primitive (Section 5.2.1) to the RSA
        #  private key K and the message representative m to produce an
        #  integer signature representative s:
    s = rsasp1(d, m)


    s: bytes = b'' 
    if len(s) != k:
        raise ValueError('message to long')
    return s


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
    # Step 1. Check that the length of the signature is k octets 
    # where k is the length in octets of the RSA modulus n
    k = n.bit_length()
    print(f"S: {len(S)}, k: {k}")
    if(len(S) != k):
        raise ValueError("invalid signature")

    # Step 2.a Convert the signature to an integer
    s: int = os2ip(S)

    # Step 2.b Apply the RSAVP1 verification primitive (Section 5.2.2) to the 
    # RSA public key (n, e) and the signature representative s to produce an 
    # integer message representative m:
    m: int = RSAVP1(n, e, s)

    # Step 2.c Convert the message representative m to an encoded message EM
    # of length emLen = \ceil ((modBits - 1)/8) octets, where modBits is the 
    # length in bits of the RSA modulus n (see Section 4.1):
    emLen = math.ceil((n.bit_length() - 1) / 8)

    try:
        EM = i2osp(m, emLen)
    except ValueError: # integer too large
        return False

    modBits = n.bit_length()

    return emsa_pss_verify(M, EM, modBits - 1)

if __name__ == '__main__':
    # This signing & verification test should pass
    try:
        m = b'Sign this message'
        s = sign(m)
        assert verify(s, m)
    except AssertionError:
        print("First signing & verification test failed")
        sys.exit(1)

    # This verification test should fail, because the signature is invalid
    try:
        m = b'Sign this message'
        s = sign(m)
        assert verify(s, b'Hello, world?')
    except AssertionError:
        print("Second signing & verification test failed")
        sys.exit(1)