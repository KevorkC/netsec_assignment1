from Crypto.Cipher import AES  # Requires PyCryptodome
from Crypto.Util.Padding import pad, unpad
import requests
from pprint import pp

BLOCK_SIZE = 16

def single_block_attack(block, oracle):
    """Returns the decryption of the given ciphertext block"""

    # zeroing_iv starts out nulled. each iteration of the main loop will add
    # one byte to it, working from right to left, until it is fully populated,
    # at which point it contains the result of DEC(ct_block)
    zeroing_iv = [0] * BLOCK_SIZE

    for pad_val in range(1, BLOCK_SIZE+1):
        padding_iv = [pad_val ^ b for b in zeroing_iv]

        for candidate in range(256):
            padding_iv[-pad_val] = candidate
            iv = bytes(padding_iv)
            if oracle(iv, block):
                if pad_val == 1:
                    # make sure the padding really is of length 1 by changing
                    # the penultimate block and querying the oracle again
                    padding_iv[-2] ^= 1
                    iv = bytes(padding_iv)
                    if not oracle(iv, block):
                        continue  # false positive; keep searching
                break
        else:
            raise Exception("no valid padding byte found (is the oracle working correctly?)")

        zeroing_iv[-pad_val] = candidate ^ pad_val

    return zeroing_iv

LOCAL_PORT = 5000
LOCAL_IP = "127.0.0.1"
URL = f"http://{LOCAL_IP}:{LOCAL_PORT}/"

REMOTE_DOMAIN = "https://cbc-rsa.netsec22.dk:"
REMOTE_PORT = 8000

if __name__ ==  '__main__':
    headers = {'Accept-Encoding': 'identity'}
    r = requests.get( URL, headers=headers)

    #print(r.text)
    authtoken = r.headers.get('Set-Cookie').split(';')[0].split('=')[1]
    # print(authtoken)
    iv = authtoken[:16]
    ct = authtoken[16:]
    pp({'iv':iv,'ct':ct})
    # print(f'iv = {iv}')
    len_of_ct = len(bytes.hex(bytes(ct,'utf-8')))
    print(len_of_ct)
    # assert len_of_ct == 128

    cookies = {
        'authtoken': bytes.hex(b''.join([b'0x00' * 15, b'0x01']))
    }
    pp(cookies)
    
    # Checking if a quote is recieved
    possible_quote = requests.get(URL + "quote", cookies=cookies)
    print(f"QUOTE REPLY: {possible_quote.text}")
    """
    if(possible_quote.text != "No quote for you!"): # or possible_quote.text != "<p>Here, have a cookie!</p>"
        print("Task not completed")
    else:
        print(f"TASK COMPLETED! Quote is: {possible_quote.text}")
    """