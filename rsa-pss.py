#!/usr/bin/env python

import math
import os
from pprint import pp

from colors import color  # pip install ansicolors
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA  # Only for key generation
from Crypto.Signature import pss  # only used for testing purposes
from Crypto.Signature.pss import MGF1

MGF = lambda x, y: MGF1(x, y, SHA256) # Wrapping pycryptodome's MGF1 function to use SHA256 

def xor(a: bytes, b: bytes) -> bytes:
    return bytes(_a ^ _b for _a, _b in zip(a, b))

def byte2int(b: bytes) -> int:
    """
    example: byte2int('\x14') == 20
    """
    assert isinstance(b, bytes), f"Expected bytes, got {type(b)}"
    return int.from_bytes(b, byteorder='big')

def int2byte(n: int) -> bytes:
    """
    example: int2byte(20) == b'\x14'
    """
    return n.to_bytes(1, byteorder='big')

def I20SP(x: int, xlen: int) -> bytes:
    """
    Convert a nonnegative integer `x` to an octet string of a specified length `xlen`.
    https://www.rfc-editor.org/rfc/rfc3447#section-4.1
    """
    return x.to_bytes(xlen, byteorder='big', signed=False)

def OS2IP(x: bytes) -> int:
    """
    Convert an octet string `x` to a nonnegative integer.
    https://www.rfc-editor.org/rfc/rfc3447#section-4.2
    """
    return int.from_bytes(x, byteorder='big', signed=False)

def EMSA_PSS_ENCODE(M: bytes, emBits: int, hash_func=SHA256, MGF=MGF, sLen: int=0) -> bytes:
    """ 
    https://www.rfc-editor.org/rfc/rfc3447#section-9.1.1
    Options:
    Hash    hash function (hLen denotes the length in octets of the hash
            function output)
    MGF     mask generation function
    sLen    intended length in octets of the salt

    Input:
    M       message to be encoded, an octet string
    emBits  maximal bit length of the integer OS2IP (EM) (see Section
            4.2), at least 8hLen + 8sLen + 9

    Output:
    EM      encoded message, an octet string of length emLen = \ceil
            (emBits/8) 
    """
    hLen = hash_func.digest_size
    assert emBits >= 8* hLen + 8* sLen + 9, "Intended encoded message length too short"

    # Step 1. If the length of M is greater than the input limitation for
    # the hash function (2^61 - 1 octets for SHA-1), output "message too
    # long" and stop.

    # We're defaulting to SHA-256, which has an input limitation of 2^64 - 1
    assert len(M) <= 2**64 - 1, "Message too long"
    
    # Step 2. Let mHash = Hash(M), an octet string of length hLen.
    mHash = hash_func.new(M).digest()

    # Step 3. If emLen < hLen + sLen + 2, output "encoding error" and stop.
    emLen = math.ceil(emBits / 8)
    assert emLen >= hLen + sLen + 2, "Encoding error"

    # Step 4. Generate a random octet string salt of length sLen; if sLen = 0,
    # then salt is the empty string.
    salt = b""
    if(sLen > 0):
        salt = os.urandom(sLen)
    
    # Step 5. Let
    # M' = (0x)00 00 00 00 00 00 00 00 || mHash || salt;
    # M' is an octet string of length 8 + hLen + sLen with eight
    # initial zero octets.
    M_prime = b"\x00" * 8 + mHash + salt

    # Step 6. Let H = Hash(M'), an octet string of length hLen.
    H = hash_func.new(M_prime).digest()

    # Step 7. Generate an octet string PS consisting of emLen - sLen - hLen - 2
    # zero octets.  The length of PS may be 0.
    PS = b"\x00" * (emLen - sLen - hLen - 2)

    # Step 8. Let DB = PS || 0x01 || salt; DB is an octet string of length
    # emLen - hLen - 1.
    DB = PS + b"\x01" + salt
    assert len(DB) == emLen - hLen - 1, "DB length error"

    # Step 9. Let dbMask = MGF(H, emLen - hLen - 1).
    dbMask = MGF(H, emLen - hLen - 1)

    # Step 10. Let maskedDB = DB \xor dbMask.
    maskedDB = xor(DB, dbMask)

    # Step 11. Set the leftmost 8*emLen - emBits bits of the leftmost octet in
    # maskedDB to zero.
    nr_bits_to_zero = 8 * emLen - emBits
    # Example: nr_bits_to_zero=3 then 0b11111111 >> 3 = 0b00011111
    mask = 0xFF >> nr_bits_to_zero
    modified_leftmost_byte = maskedDB[0] & mask
    # Set the leftmost bits to zero
    maskedDB = int2byte(modified_leftmost_byte) + maskedDB[1:]

    # Step 12. Let EM = maskedDB || H || 0xbc.
    EM = maskedDB + H + b"\xbc"
    
    return EM


def RSASP1(N: int, d: int, m: int) -> int:
    """ 
    Textbook RSA message signing  
    https://www.rfc-editor.org/rfc/rfc3447#section-5.2.1
    Input:
    (N, d)  private RSA key pair
    m       message representative, an integer between 0 and N - 1
    Output:
    s       signature representative, an integer between 0 and N - 1
    """

    # Step 1. If m is not an integer between 0 and n - 1, output "message
    # representative out of range" and stop.
    assert isinstance(m, int), "Message representative must be an integer"
    assert 0 < m and m <= N - 1, "Message representative out of range"
    
    # Step 2 Compute s = m^d mod N.
    s = pow(m, d, N)

    return s


def RSAVP1(N: int, e: int, s: int) -> int:
    """
    https://www.rfc-editor.org/rfc/rfc3447#section-5.2.2
    Input:
    (n, e)  RSA public key
    s       signature representative, an integer between 0 and n - 1

    Output:
    m       message representative, an integer between 0 and n - 1

    Error: "signature representative out of range"
    """
    assert isinstance(s, int), "Signature representative must be an integer"
    assert 0 < s and s < N, "Signature representative out of range"
    
    m = pow(s, e, N)
    return m


def EMSA_PSS_VERIFY(M: bytes, EM: bytes, emBits: int, hash_func=SHA256, sLen: int=0, MGF=MGF) -> bool:
    """     
    https://www.rfc-editor.org/rfc/rfc3447#section-9.1.2
    Options:
    Hash    hash function (hLen denotes the length in octets of the hash
            function output)
    MGF     mask generation function
    sLen    intended length in octets of the salt

    Input:
    M       message to be verified, an octet string
    EM      encoded message, an octet string of length emLen = \ceil
            (emBits/8)
    emBits  maximal bit length of the integer OS2IP (EM) (see Section
            4.2), at least 8hLen + 8sLen + 9

    Output:
    True if consistent, False if inconsistent
    """

    assert isinstance(EM, bytes), "EM must be a byte string"
    assert isinstance(M, bytes), "M must be a byte string"

    # Step 1. If the length of M is greater than the input limitation for
    # the hash function (2^61 - 1 octets for SHA-1), output "inconsistent"
    # and stop. 
    assert len(M) < 2**64 - 1, f"length of M ({len(M)}, {len(M)-2**64-1} too large) is greater than the input limitation for the hash function (2^64 - 1 octets for SHA-256)"
    
    # Step 2. Let mHash = Hash(M), an octet string of length hLen.
    mHash = hash_func.new(M).digest()

    # Step 3. If emLen < hLen + sLen + 2, output "inconsistent" and stop.
    hLen = hash_func.digest_size
    assert hash_func.digest_size == len(mHash)
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
    if(0 | leftmost_octet_in_maskedDB >> (8 - number_of_leftmost_bits) != 0):
        return False

    # Step 7. Let dbMask = MGF(H, emLen - hLen - 1).
    dbMask: bytes = MGF(H, emLen - hLen - 1)

    # Step 8. Let DB = maskedDB \xor dbMask.
    DB: bytes = xor(maskedDB, dbMask)

    # Step 9. Set the leftmost 8*emLen - emBits bits of the leftmost octet in
    # DB to zero.
    assert isinstance(DB, bytes), 'DB must be of type bytes'
    DB0_as_int: int = DB[0]
    # if number_of_leftmost_bits = 2 then (0xFF >> 2) == '00111111'
    # so when you & with it the 2 leftmost bits will be zeroed
    modified_DB0_as_int: int = DB0_as_int & (0xFF >> number_of_leftmost_bits)
    modified_DB0_as_byte: bytes = int2byte(modified_DB0_as_int)
    DB: bytes = modified_DB0_as_byte + DB[1:]

    # Step 10. If the emLen - hLen - sLen - 2 leftmost octets of DB are not
    # zero or if the octet at position emLen - hLen - sLen - 1 (the leftmost
    # position is "position 1") does not have hexadecimal value 0x01,
    # output "inconsistent" and stop.
    for b in DB[:emLen - hLen - sLen - 2]:
        if b != 0x00:
            assert False, "The emLen - hLen - sLen - 2 leftmost octets of DB are not zero"

    if not DB[emLen - hLen - sLen - 2] == 0x01:
        assert False, "The octet at position emLen - hLen - sLen - 1 does not have hexadecimal value 0x01"

    # Step 11. Let salt be the last sLen octets of DB.
    salt = b""
    if sLen != 0: # If sLen is 0, then DB[-0:] would return the entire DB
        salt = DB[-sLen:]

    # Step 12. Let M' = (0x)00 00 00 00 00 00 00 00 || mHash || salt;
    # M' is an octet string of length 8 + hLen + sLen with eight
    # initial zero octets.
    assert isinstance(mHash, bytes) and isinstance(salt, bytes)
    M_ = b"\x00" * 8 + mHash + salt
    assert len(M_) == 8 + hLen + sLen, f"len(M_) ({len(M_)}) != 8 + hLen ({hLen}) + sLen ({sLen})"
    
    # Step 13. Let H' = Hash(M'), an octet string of length hLen.
    H_ = hash_func.new(M_).digest()

    # Step 14. If H = H', output "consistent." Otherwise, output
    # "inconsistent."
    print(f"H:  {H.hex()}")
    print(f"H': {H_.hex()}")
    return H == H_


def sign(K: int, N: int, M: bytes, sLen: int) -> bytes:
    """ 
    Sign a message using RSA-PSS
    https://www.rfc-editor.org/rfc/rfc3447#section-8.1.1
    Input:
    K        signer's RSA private key
    M        message to be signed, an octet string
    N        the modulus of the RSA public key
    Output:
    S       signature, an octet string of length k, where k is the
            length in octets of the RSA modulus n 
    """
    assert isinstance(M, bytes), 'M must be of type bytes'
    assert isinstance(N, int), 'N must be of type int'
    assert isinstance(K, int), 'K must be of type int'

    # Step 1. EMSA-PSS encoding: Apply the EMSA-PSS encoding operation
    # to the message M to produce an encoded message EM of length
    # emLen = \ceil((modBits - 1)/8) octets, such that the bit length of the
    # integer OS2IP (EM) (see Section 4.2) is at most modBits - 1, where
    # modBits is the length in bits of the RSA modulus n:
    modBits = N.bit_length()
    EM = EMSA_PSS_ENCODE(M, modBits - 1, sLen=sLen)
    assert isinstance(EM, bytes), 'EM must be of type bytes'
    assert len(EM) == math.ceil((modBits - 1) / 8), f"len(EM) ({len(EM)}) != ceil((modBits - 1) / 8) ({math.ceil((modBits - 1) / 8)})"

    # Step 2.a Convert the encoded message EM to an integer message
    # representative m
    m: int = OS2IP(EM)
    assert m.bit_length() <= modBits - 1, f"m.bit_length() ({m.bit_length()}) > modBits - 1 ({modBits - 1})"

    # Step 2.b Apply the RSASP1 signature primitive to the RSA
    # private key K and the message representative m to produce an
    # integer signature representative s
    s: int = RSASP1(N, K, m)

    # Step 3.c Convert the signature representative s to a signature
    # S of length k octets
    # k is length in octets/bytes
    k = math.ceil(N.bit_length() / 8)
    S = I20SP(s, k)

    assert len(S) == k, "length of signature must equal k"
    return S


def verify(n: int, e: int, M: bytes, S: bytes, sLen: int) -> bool:
    """ 
    Verify a signature using RSA-PSS 
    https://www.rfc-editor.org/rfc/rfc3447#section-8.1.2
    Input:
    (n, e)  signer's RSA public key
    M       message whose signature is to be verified, an octet string
    S       signature to be verified, an octet string of length k, where
            k is the length in octets of the RSA modulus n
    sLen    intended length in octets of the salt, a non-negative

    Output:
    "valid signature" or "invalid signature"
    """
    # Step 1. Check that the length of the signature is k octets 
    # where k is the length in octets of the RSA modulus n
    k = math.ceil(N.bit_length() / 8)
    assert(len(S) == k), "length of signature must equal k"

    # Step 2.a Convert the signature to an integer
    s: int = OS2IP(S)

    # Step 2.b Apply the RSAVP1 verification primitive (Section 5.2.2) to the 
    # RSA public key (n, e) and the signature representative s to produce an 
    # integer message representative m:
    m: int = RSAVP1(n, e, s)

    # Step 2.c Convert the message representative m to an encoded message EM
    # of length emLen = \ceil ((modBits - 1)/8) octets, where modBits is the 
    # length in bits of the RSA modulus n (see Section 4.1):
    modBits = n.bit_length()
    emLen = math.ceil((modBits - 1) / 8)
    EM = I20SP(m, emLen)

    # Step 3. EMSA-PSS verification: Apply the EMSA-PSS verification operation
    # to the message M, the encoded message EM, and the length of the salt sLen
    # to produce an error result:
    result = EMSA_PSS_VERIFY(M, EM, modBits - 1, sLen=sLen)
    
    # Step 4. If result is "consistent", output "valid signature".
    # Otherwise, output "invalid signature".
    return result


# TEST IMPLEMENTATION
if __name__ == '__main__':
    columns = os.get_terminal_size().columns
    print_horizontal_line = lambda: print("-" * columns)

    key = RSA.generate(2048)
    N = key.n
    e = key.e
    d = key.d 
    
    test_id = 1
    def test_our_implementation_against_pycryptodome_implementation(m: bytes, salt_length: int) -> None:
        m_hash = SHA256.new(m)
        global test_id

        print_horizontal_line()
        print()
        print("Each test tests if the generated RSA-PSS signature, can also verified with RSA-PSS-VERIFY.")

        pycryptodome_rsa_pss = pss.new(key, mask_func=MGF, salt_bytes=salt_length)

        # pycryptodome expects the message m to be hashed beforehand.
        # this is not standard in RFC 3447
        print_horizontal_line()
        print(color(f"TEST CASE {test_id}.1:", 'blue'), end='')
        print(" Using pycryptodome for signature and verification")
        pycryptodome_signature = pycryptodome_rsa_pss.sign(m_hash)
        try:
            pycryptodome_rsa_pss.verify(m_hash, pycryptodome_signature)
            print(color("Test SUCCESSFUL.", 'green'))
        except (ValueError, TypeError):
            print(color("Test FAILED.",'red'))

        
        print_horizontal_line()
        print(color(f"TEST CASE {test_id}.2:", 'blue'), end='')
        print(" Using our signature, and pycryptodome for verification")
        our_signature = sign(d,N, m, salt_length)
        try:
            pycryptodome_rsa_pss.verify(m_hash, our_signature)
            
            print(color("Test SUCCESSFUL.", 'green'))
        except (ValueError, TypeError):
            print(color("Test FAILED.",'red'))

        print_horizontal_line()
        print(color(f"TEST CASE {test_id}.3:", 'blue'), end='')
        print(" Using pycryptodome for signature, and our verification")
        pycryptodome_signature = pycryptodome_rsa_pss.sign(m_hash)
        verified: bool = verify(N, e, m, pycryptodome_signature, salt_length)
        if verified:
            print(color("Test SUCCESSFUL.", 'green'))
        else:
            print(color("Test FAILED.",'red'))

        print_horizontal_line()
        print(color(f"TEST CASE {test_id}.4:", 'blue'), end='')
        print(" Our signature and verification")
        our_signature = sign(d,N, m, salt_length)
        verified: bool = verify(N, e, m, our_signature, salt_length)
        if verified:
            print(color("Test SUCCESSFUL.", 'green'))
        else:
            print(color("Test FAILED.",'red'))

        print_horizontal_line()
        test_id += 1


    # We test with three different salt lengths: [0, 1, SHA256.digest_size]
    # When the salt length is 0, the signature becomes deterministic.
    # 1 is to try a salt length that is not 0.
    # SHA256.digest_size also known as hLen is the length recomenneded by the pycryptodome library:
    # https://www.pycryptodome.org/src/signature/pkcs1_pss?highlight=pss#Crypto.Signature.pss.new
    for salt_length in [0, 1, SHA256.digest_size]:
        print('First test we try with the following string as m:')
        m = b'Its me Mario!'
        print(f'm = {m}')
        test_our_implementation_against_pycryptodome_implementation(m, salt_length=salt_length)

        print('testing with a jpeg file ./spiderman.jpg')
        with open('spiderman.jpg', 'rb') as f:
            image = f.read()
            test_our_implementation_against_pycryptodome_implementation(image, salt_length=salt_length)