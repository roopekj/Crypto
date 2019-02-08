from Crypto.Cipher import AES
from binascii import hexlify, unhexlify
from base64 import b64decode, b64encode
from random import randint
from math import floor, ceil
import datetime, os, sys

def encode_repeating_key(s, key):
    return hexlify(bytes([s[i] ^ key[i % len(key)] for i in range(len(s))]))
def xor(binary_data_1, binary_data_2):
    return bytes([d1 ^ d2 for d1, d2 in zip(binary_data_1, binary_data_2)])
def xor_alt(i1, i2):
    output = b''
    for a1, a2 in zip(i1, i2):
        output += bytes(a1 ^ a2)
    return output
def pad(string, length):    # Pads the string-variable with pkcs7 up to the length-variable or a multiple of it
    str_len = len(string)
    if str_len % length == 0 or str_len == length:
        return string

    if str_len > length:
            num = (ceil(str_len / length)) * length - str_len
            return string + (bytes([num]) * num)
    else:
        num = length - str_len
        return string + (bytes([num]) * num)
def decrypt_ecb(cipher, key):
    aes_obj = AES.new(key, AES.MODE_ECB)
    return aes_obj.decrypt(cipher)
def encrypt_ecb(plaintext, key):
    aes_obj = AES.new(key, AES.MODE_ECB)
    return aes_obj.encrypt(plaintext)

# NOTE: The CBC-mode encryption/decryption-functions could be made significantly simpler by using the pycryptodome's built-in cbc-mode, but that would be against the rules of the exercises they are used in.
def decrypt_cbc(ciphertext, key, iv):
    plaintext = b''
    previous = iv
    for i in range(0, len(ciphertext), AES.block_size):
        cipher_block = bytes(ciphertext[i:i + AES.block_size])
        decrypted_block = decrypt_ecb(cipher_block, key)
        plaintext += xor(decrypted_block, previous)
        previous = cipher_block
    return plaintext
def encrypt_cbc(plaintext, key, iv):
    plaintext = pad(plaintext, AES.block_size)

    previous = iv
    ciphertext = b''
    for i in range(0, len(plaintext), AES.block_size):
        plaintext_block = pad(plaintext[i:i + AES.block_size], AES.block_size)
        cipher_block = xor(plaintext_block, previous)
        encrypted_block = encrypt_ecb(cipher_block, key)
        ciphertext += encrypted_block
        previous = encrypted_block

    return ciphertext

def ecb_cbc_random_oracle(input):
    added_to_beginning = os.urandom(randint(5, 50))
    added_to_end = os.urandom(randint(5, 50))

    s = added_to_beginning + input + added_to_end
    s = pad(s, AES.block_size)

    random_choice = randint(0, 1)
    key = os.urandom(AES.block_size)    # We need this no matter what the choice is
    if random_choice == 1:
        ecb_encrypted = encrypt_ecb(s, key)
        return ecb_encrypted
    else:
        iv = os.urandom(AES.block_size)
        cbc_encrypted = encrypt_cbc(s, key, iv)
        return cbc_encrypted
def oracle_extended(s, appendix, key):  # All inputs in bytes
    return encrypt_ecb(pad(s + appendix, AES.block_size), key)
def oracle_extended_and_prepended(s, prefix, target, key):  # All inputs in bytes
    return encrypt_ecb(pad(prefix + s + target, AES.block_size), key)
def detect_ecb(s):      # Assumes we have given the oracle a long input of repeating characters, that would cause repeating blocks of AES.block_size-length in the output
    substrings = []
    for substring_index in range(0, len(s), AES.block_size):
        substring_found = s[substring_index:substring_index + AES.block_size]
        if ''.join(str(substring_found)) in substrings:
            return True
        substrings.append(str(substring_found))
    return False
def calculate_hamming_distance(first, second):
    a = str(bin(int.from_bytes(first, 'big')))[2:]
    b = str(bin(int.from_bytes(second, 'big')))[2:]
    count = 0
    for i in range(min(len(a), len(b))):
        if a[i] != b[i]:
            count = count + 1
    return count
def freq(string):   # Frequency of characters that imply the parameter is written in english
    count = 0
    letters = list(
        'etaoinshrdlu ')  # 10 most used letters of the english language + space, capitalization could provide better results with some inputs
    for letter in letters:
        count = count + string.count(letter)
    return count / len(
        string)  # We divide the found characters by the length of the string so that long string don't have an edge in the evaluation
def pkcs7_strip(s):     # Check for whether or not s in padded with pkcs7 (raises an exception if not)
    byte = s[-1]
    if byte == 0 or type(byte) != int:
        raise ValueError('Invalid padding')
    for i in range(len(s) - 1, len(s) - 1 - byte, -1):
        if s[i] != byte:
            raise ValueError('Invalid padding')
    return s[:-byte]
def create_kv(s):
    if '&' in s:
        parts = s.split('&')
    else:
        parts = [s]
    dict = {}
    for part in parts:
        if '=' in part:
            type, value = part.split('=')
            dict[type] = value
    return dict
def profile_for(email):
    email = email.replace('=', '').replace(';', '')
    dict = create_kv(email)
    dict['email'] = email
    if dict.get('uid', -1) == -1:
        dict['uid'] = 10
    if dict.get('role', -1) == -1:
        dict['role'] = 'user'
    return dict
def break_oracle(function):     # Finds the secret by which the input-oracle is extending its parameter
    #   First we need to isolate the oracle's potential prefix. We don't really need to know it's length or contents, just how many bytes of nonsense we need to feed the oracle until the prefix being a factor in the oracle's outputs

    default = function(b'')

    #   We need to find out how much of the output already stays the same due to the prepend
    slightly_modified = function(b'z')
    multiplier_default = 0
    for stays_same in range(0, len(default), AES.block_size):
        if default[stays_same:stays_same + AES.block_size] == slightly_modified[stays_same:stays_same + AES.block_size]:
            multiplier_default += 1
        else:
            break

    previous_16 = default[multiplier_default * AES.block_size:(multiplier_default + 1) * AES.block_size]
    prefix = b''    # This is the nonsense we need to start out input with
    for amount_of_nonsense in range(1, 17):
        output = function(b'\x21' * amount_of_nonsense)
        first_16 = output[multiplier_default * AES.block_size:(multiplier_default + 1) * AES.block_size]
        if first_16 == previous_16:     # If the first 16 bytes of output don't change, we know the amount of nonsense required to evade the prefix of the oracle
            prefix = b'X' * (amount_of_nonsense - 2)
            break
        previous_16 = first_16
    if len(prefix) > 0:
        prefix += b'X'

    time_1 = datetime.datetime.now()
    decrypted = b''
    no_prepend = False
    for index in range(1, 2000):
        index_orig = int(index)
        if len(prefix) == 17 or len(prefix) == 0:
            no_prepend = True

        if no_prepend:
            prefix = b''
            to_be_added = 0
        else:
            to_be_added = 1

        multiplier = multiplier_default
        while True:
            if index_orig > 16:
                multiplier += 1
                index_orig -= 16
            else:
                break

        my_string = prefix + b'A' * (((multiplier - multiplier_default) * 16) + AES.block_size - index) + decrypted

        dict = {}
        for ordinal in range(128):
            dict_input = my_string + bytes(chr(ordinal).encode())
            dict_input_enc = function(dict_input)
            dict[decrypted + bytes(chr(ordinal).encode())] = dict_input_enc[(multiplier + to_be_added) * 16:(multiplier + 1 + to_be_added) * 16]

        input = prefix + b'A' * (((multiplier - multiplier_default) * 16) + 16 - index)
        output = function(input)

        decrypted_temp = str(decrypted)
        for key, value in dict.items():
            if value == output[(multiplier + to_be_added) * 16:(multiplier + 1 + to_be_added) * 16]:
                decrypted += key[-1:]
                break

        if decrypted_temp == str(
                decrypted):  # If the decrypted-bytearray has not changed, we have not found any new characters. Even if there is more message left, no amount of iterations would get us more of it, so we interrupt runtime
            break

    print('Process took: ' + str(datetime.datetime.now() - time_1) + ' hours. The oracle\'s secret string is:')
    print(decrypted.decode()[:-1])
