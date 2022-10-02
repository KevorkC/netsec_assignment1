import hashlib
from hashlib import sha256
import math
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


def emsa_pss_encode(m: bytes, modbits) -> bytes:
    pass


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

def emsa_pss_verify(M: bytes, EM: bytes, modBits: int) -> bool:
    
    


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

def sign(M: bytes) -> bytes:
    e = 2**16 - 1 # 65535 public_key
    d = 0 # private_key
    N = 0 # modulus

    modbits = 0
    EM = emsa_pss_encode(M, modbits - 1)
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