import base64
import textwrap
from pprint import pp
import re

import requests
from Crypto.Cipher import AES  # Requires PyCryptodome
from Crypto.Util.Padding import pad, unpad

BLOCK_SIZE = 16

p = lambda *args, **kvargs: print(*args, **kvargs)
pt = lambda *args, **kvargs: p(*[type(a) for a in args], **kvargs)
bhex = lambda arr: bytearray(bytearray.hex(arr), encoding='utf-8')

# hexstr2bytearray = lambda s: bytearray.fromhex(s)

LOCAL_PORT = 5000
LOCAL_IP = "127.0.0.1"
URL = f"http://{LOCAL_IP}:{LOCAL_PORT}/"

REMOTE_DOMAIN = "https://cbc-rsa.netsec22.dk:"
REMOTE_PORT = 8000


xor = lambda A, B: bytearray([a ^ b for a, b in zip(A, B)])


def ask_oracle_about_valid_padding(ciphertext: bytes):
    p("sending this ciphertext to server:", ciphertext)
    cookies = {
        # 'authtoken': bytes.hex(b''.join([b'0x00' * 15, b'0x01']))
        "authtoken": ciphertext.hex()
    }
    resp = requests.get(URL + "/quote/", cookies=cookies)
    # p({"resp.content": resp.content})
    return resp.text == "No quote for you!"


def ciphertext_block_to_cleartext_block(
    current_ciphertext_block: bytearray, previous_ciphertext_block: bytearray
) -> str:

    # [0x00, 0x00, ..., 0x00] NOT valid padding, but initial value
    # [..., 0x01]
    # [..., 0x02, 0x02]
    # [..., 0x03,0x03,0x03]
    # ...
    # [0x10, 0x10, ..., 0x10]
    plaintext_bytes = bytearray([0 for _ in range(16)])

    for i in range(
        16
    ):  # loop through each byte in 128 bit (16 bytes) AES ciphertext block.
        # [0x00, 0x00, ..., 0x00]
        # [0x00, 0x00, ..., 0x01]
        # [0x00, 0x00, ..., 0x02, 0x02]
        # [0x00, 0x00, ..., 0x03, 0x03, 0x03]
        expected_padding = bytearray(
            [0 for _ in range(16 - i)] + [(i + 1) for _ in range(i)]
        )
        modified_previous_ciphertext_block = xor(
            xor(expected_padding, plaintext_bytes),
            previous_ciphertext_block,
        )

        for byte in range(
            0, 256
        ):  # loop through each byte value that the padding byte can have.
            # [0x00, 0x00, ..., 0x00]
            # [0x00, 0x00, ..., 0x01]
            # [0x00, 0x00, ..., 0x02]
            # ...
            # [0x00, 0x00, ..., 0xff]
            # p(modified_previous_ciphertext_block)
            # modified_previous_ciphertext_block = bhex(modified_previous_ciphertext_block)
            modified_previous_ciphertext_block[15 - i] = byte
            # p("byte:", byte)
            pp(modified_previous_ciphertext_block)

            # p({"modified_previous_ciphertext_block": modified_previous_ciphertext_block})
            #to_test = base64.b64encode((c_prime + bytearray(current_ciphertext_block, encoding="utf-8"))).decode("utf-8")
            # pt(modified_previous_ciphertext_block)
            # pt(current_ciphertext_block)
            # p(modified_previous_ciphertext_block)

            block = modified_previous_ciphertext_block + current_ciphertext_block
            # pp(block)
            to_test = block
            # to_test = bytes.fromhex(str(block))

            # to_test = bytes.fromhex(modified_previous_ciphertext_block + current_ciphertext_block)
            # p({"to_test": to_test})
            
            # try decryption
            # i.e. send request to server
            correct = ask_oracle_about_valid_padding(to_test)
            # if successful
            if correct:
                plaintext_bytes[15 - i] = byte ^ (i + 1) ^ current_block[15 - i]

    return str(plaintext_bytes, encoding="utf-8")


# assume that ciphertext % block_size == 0
def split_into_ciphertext_blocks(ciphertext: str, block_size: int = 16):
    return textwrap.wrap(ciphertext, block_size)


if __name__ == "__main__":
    headers = {"Accept-Encoding": "identity"}
    # send get request to server to get authtoken
    r = requests.get(URL, headers=headers)
    authtoken = r.headers.get("Set-Cookie").split(";")[0].split("=")[1]
    iv = authtoken[:16]
    ct = authtoken[16:]
    pp({'ct': ct})
    ct_blocks = split_into_ciphertext_blocks(ct)

    if re.match(r"[^0-9a-f]", ct):
        p('very bad')
        exit(1)
    

    cleartext = ""
    for i in range(len(ct_blocks)-1):
        # pp({"len(ct_blocks)": len(ct_blocks), "i": i})
        current_block = ct_blocks[len(ct_blocks)-i-1]
        previous_block = ct_blocks[len(ct_blocks)-i-2]
        pp({"current_block": current_block, "previous_block": previous_block})
        current_block = bytearray.fromhex(current_block)
        previous_block = bytearray.fromhex(previous_block)
        pp({"current_block": current_block, "previous_block": previous_block, 'len(current_block)': len(current_block), 'len(previous_block)': len(previous_block), 'i': i})
        # current_block = bytearray(ct_blocks[len(ct_blocks) - i - 1], encoding="utf-8")
        # previous_block = bytearray(ct_blocks[len(ct_blocks) - i - 2], encoding="utf-8")
        pp({'cleartext': cleartext})
        cleartext = (
            ciphertext_block_to_cleartext_block(
                current_block, previous_block
            )
            + cleartext
        )

    # the first block does not have a previous block, it used the iv instead
    cleartext = (
        ciphertext_block_to_cleartext_block(bytearray(ct_blocks[0], encoding='utf-8'), bytearray(iv, encoding='utf-8')) + cleartext
    )

    p("cleartext: " + cleartext)
