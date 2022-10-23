
# import required module
import sys
from Crypto.Cipher import AES

def decrypt_file(file_filename, key_filename):
    # opening the key
    with open(f'../public/decryption/{key_filename}', 'rb') as filekey:
        key = filekey.read()
    
    # opening the encrypted file
    with open('../public/decryption/'+file_filename, 'rb') as enc_file:
        enc_bytes = enc_file.readlines()

    tag = enc_bytes[0]
    size = len(tag)
    tag = tag[: size - 2]

    nonce = enc_bytes[1]
    size = len(nonce)
    nonce = nonce[: size - 2]

    ciphertext = enc_bytes[2]
    
    # decrypting the file
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    decrypted = cipher.decrypt(ciphertext)

    # check integrity
    try:
        cipher.verify(tag)
        print("Integrity check: The file is authentic:", decrypted)
    except ValueError:
        print("Integrity check: Key incorrect or file corrupted")

    # opening the file in write mode and
    # writing the decrypted data
    with open('../public/decryption/decrypted.txt', 'wb') as dec_file:
         dec_file.write(decrypted)

    # print('\n--> decryption\ntag: ', tag, '\nnonce: ', nonce, '\nencrypted: ', ciphertext, '\ndecrypted: ', decrypted,
    #     '\nplain text: ', plaintext, '\n<--\n',
    #       file=sys.stderr)
       