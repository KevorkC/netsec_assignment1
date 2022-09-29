import textwrap
from pprint import pp

import requests
from Crypto.Cipher import AES  # Requires PyCryptodome
from Crypto.Util.Padding import pad, unpad

BLOCK_SIZE = 16

p = lambda *args, **kvargs: print(*args, **kvargs)


LOCAL_PORT = 5000
LOCAL_IP = "127.0.0.1"
URL = f"http://{LOCAL_IP}:{LOCAL_PORT}/"

REMOTE_DOMAIN = "https://cbc-rsa.netsec22.dk:"
REMOTE_PORT = 8000


xor = lambda A, B: bytearray([a ^ b for a, b in zip(A, B)])


def ask_oracle_about_valid_padding(ciphertext: str):
    p("ciphertext:", ciphertext)
    cookies = {
        # 'authtoken': bytes.hex(b''.join([b'0x00' * 15, b'0x01']))
        "authtoken": ciphertext
    }
    resp = requests.get(URL + "quote", cookies=cookies)
    p({"resp.content": resp.content})
    return resp.content == "No quote for you!"


def ciphertext_block_to_cleartext_block(
    ct_blocks, current_ciphertext_block: str, previous_ciphertext_block: str
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
        c_prime = xor(
            xor(expected_padding,plaintext_bytes),
            bytearray(previous_ciphertext_block, encoding="ascii"),
        )

        for byte in range(
            0, 256
        ):  # loop through each byte value that the padding byte can have.
            # [0x00, 0x00, ..., 0x00]
            # [0x00, 0x00, ..., 0x01]
            # [0x00, 0x00, ..., 0x02]
            # ...
            # [0x00, 0x00, ..., 0xff]
            c_prime[15 - i] = byte
            p("byte:", byte)
            p({"c_prime": c_prime})
            to_test = str(c_prime, encoding="ascii") + current_ciphertext_block
            p({"to_test": to_test})
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
    ct_blocks = split_into_ciphertext_blocks(ct)

    cleartext = ""
    for i in range(len(ct_blocks)-1):
        p({"len(ct_blocks)": len(ct_blocks), "i": i})
        current_block = ct_blocks[len(ct_blocks) - i - 1]
        previous_block = ct_blocks[len(ct_blocks) - i - 2]
        cleartext = (
            ciphertext_block_to_cleartext_block(
                ct_blocks, current_block, previous_block
            )
            + cleartext
        )

    # the first block does not have a previous block, it used the iv instead
    cleartext = (
        ciphertext_block_to_cleartext_block(ct_blocks, ct_blocks[0], iv) + cleartext
    )

    p("cleartext: " + cleartext)
