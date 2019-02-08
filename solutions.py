import sys, os, binhex, codecs, time, datetime
from Crypto.Cipher import AES
from binascii import hexlify, unhexlify
from base64 import b64encode, b64decode
import Crypto.Random
from random import randint
from tools import *

def solve_1_1():
    print('Hex-string to convert to base64: ', end='')
    input_str = input().encode()
    if len(input_str) == 0 or len(input_str) % 2 != 0:
        print('Invalid input')
    else:
        try:
            converted_str = codecs.encode(codecs.decode(input_str, 'hex'), 'base64').decode().strip()
            print('Converted output is: ' + str(converted_str))
        except:
            print('Invalid input')
def solve_1_2():
    print('First hex-value: ', end='')
    first = input()
    if len(first) == 0 or len(first) % 2 != 0:
        first = '1c0111001f010100061a024b53535009181c'

    print('Second hex-value: ', end='')
    second = input()
    if len(second) == 0 or len(second) % 2 != 0:
        second = '686974207468652062756c6c277320657965'

    try:
        result = hex(int(first, 16) ^ int(second, 16))[2:]
        print('%s ^ %s -> ' % (first, second) + result)
    except:
        print('Invalid input')
def solve_1_3():
    print('Enter hex-encoded message encrypted with single-byte XOR cipher: ', end='')
    message_encrypted = input()
    if len(message_encrypted) == 0 or len(message_encrypted) % 2 != 0:
        message_encrypted = '1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736'
    chars = binascii.unhexlify(message_encrypted)
    print('Encrypted message: ' + str(chars.decode()))
    outputs = []
    for key in range(256):
        output = ''.join(chr(char ^ key) for char in chars)
        if output.isprintable():    # Non-printable outputs are of no interest to us
            outputs.append(output)

    result = max(outputs, key=freq)
    print('Decrypted message: ' + result)
def solve_1_4():
    file = open('1-4.txt', 'r')
    ciphers = file.readlines()

    results = []

    for cipher in ciphers:
        cipher = cipher.strip().replace('\n', '')  # Strip-method used to get rid of newlines

        if len(
                cipher) % 2 != 0:  # If the cipher is odd odd-length, we can't use it and it most definitely isn't what we're looking for
            print('ODD-LENGTH CIPHER -> ' + cipher)
            continue

        outputs = []
        for key in range(256):
            output = ''.join(
                chr(char ^ key) for char in unhexlify(cipher)).strip()  # a ^ b = c -> c ^ a = b
            if output.isprintable():  # If the output is not printable we most likely have no use for it (NOTE: for example the newline character is not 'printable', inputs need to be sanitized beforehand)
                outputs.append(output)
        if len(outputs) > 0:
            results.append(max(outputs, key=freq))

    if len(results) == 0:
        sys.exit('No usable ciphers found.')

    result_final = max(results, key=freq)
    print('The message was:\t\'' + result_final + '\'\nAmount of usable ciphers: ' + str(
        len(results)) + '\nTotal amount of ciphers: ' + str(len(ciphers)))
def solve_1_5():
    key = b'ICE'
    plaintext = b'''Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal'''
    ciphertext = encode_repeating_key(plaintext, key)

    print(ciphertext.decode())
def solve_1_6():
    base64encoded = open('1-6.txt', 'r').read()
    asciiencoded = bytes(base64.b64decode(base64encoded))

    distance_results = {}
    for keysize in range(2, 40):
        for i in range(int(len(asciiencoded) / keysize)):
            distance_result = calculate_hamming_distance(asciiencoded[keysize * i: (i + 1) * keysize],
                                       asciiencoded[(i + 1) * keysize: (i + 2) * keysize]) / keysize
            distance_results[keysize] = distance_result

    keysizes = []
    for key, value in distance_results.items():
        if value < 1:
            keysizes.append(key)
    results = []
    for keysize in keysizes:
        substrings = []  # Splitting the string into substrings with the length of our assumed key size
        amount = int(len(asciiencoded) / keysize)
        for i in range(0, keysize):
            to_append = ''
            for s in range(0, amount):
                to_append = to_append + str(asciiencoded[i + (s * keysize)]) + ' '
            substrings.append(to_append.split(' '))

        keys = []
        for substring_list in substrings:
            outputs = {}
            for key_temp in range(0, 256):
                output = ''
                for substring in substring_list:
                    if substring == '':
                        continue
                    output = output + chr(int(substring) ^ key_temp)
                outputs[key_temp] = output

            if len(outputs) > 0:
                assumed_output = max(outputs.values(), key=freq)
                for key, value in outputs.items():
                    if value == assumed_output:
                        keys.append(chr(key))
            else:
                exit(-10)
        result = ''
        for i in range(len(asciiencoded)):
            result = result + ''.join(chr(asciiencoded[i] ^ ord(keys[i % len(keys)])))
        print('With keysize %s the decrypted result is:\t' % str(keysize) + result[:10] + '...')
        results.append(result)
    print('\nDecrypted message is:\n' + str(
        max(results, key=freq)))
def solve_1_7():
    AES128encrypted = bytes(open('1-7.txt', 'r').read().encode())
    cipher = b64decode(AES128encrypted)
    key = b'YELLOW SUBMARINE'
    print('(AES-128) Decrypted: ' + decrypt_ecb(cipher, key).decode().replace('\n', r'\n'))
def solve_1_8():
    file = open('1-8.txt', 'r')
    lines = file.readlines()
    ecb_encrypted_ciphers = []
    for line_read in lines:
        substrings = []
        for index in range(int(len(line_read) / 16)):
            substring = line_read[index * 16:(index + 1) * 16]
            substrings.append(substring)

        for substring_index in range(len(substrings)):
            substring_found = substrings[substring_index]
            substrings[substring_index] = ''
            if ''.join(substring_found) in substrings:
                ecb_encrypted_ciphers.append(line_read)
                break
    if len(ecb_encrypted_ciphers) == 0:
        print('No ecb-encrypted ciphers found.')
    else:
        print(str(len(ecb_encrypted_ciphers)) + ' ecb-encrypted cipher(s) found:')
        for cipher in ecb_encrypted_ciphers:
            print(cipher)
def solve_2_1():
    message = input('Insert message to add padding to: ')
    length_to_pad = int(input('Insert multiple of length of message after padding: '))
    print('Message padded with PKCS#7 -> ', end='')
    print(pad(bytes(message.encode()), length_to_pad))
def solve_2_2():
    cipher = b64decode(open('2-2.txt', 'r').read())
    iv = b'\x00' * AES.block_size
    key = b'YELLOW SUBMARINE'

    decrypted = decrypt_cbc(cipher, key, iv)
    re_encrypted = encrypt_cbc(decrypted, key, iv)
    print('Encrypted:\t\t' + str(cipher)[:20] + '\nDecrypted:\t\t' + str(decrypted)[:20] + '\nRe-encrypted:\t' + str(
        re_encrypted)[:20])
def solve_2_3():
    message = b'A' * 100
    encrypted = ecb_cbc_random_oracle(message)

    if detect_ecb(encrypted):
        print('This cipher has been encrypted using ECB')
    else:
        print('This cipher has been encrypted using CBC')
def solve_2_4():
    def extension_oracle(s):
        key = b'8884602576695132'
        appendix = b'Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK'
        appendix_decoded = b64decode(appendix)

        return encrypt_ecb(pad(s + appendix_decoded, AES.block_size), key)

    time_1 = datetime.datetime.now()
    decrypted = b''
    for index in range(1, 200):
        index_orig = int(index)
        multiplier = 0
        while True:
            if index_orig > 16:
                multiplier += 1
                index_orig -= 16
            else:
                break

        my_string = b'A' * ((multiplier * 16) + AES.block_size - index) + decrypted

        dict = {}
        for ordinal in range(128):
            dict_input = my_string + bytes(chr(ordinal).encode())
            dict_input_enc = extension_oracle(dict_input)
            dict[decrypted + bytes(chr(ordinal).encode())] = dict_input_enc[multiplier * 16:(multiplier + 1) * 16]

        input = b'A' * ((multiplier * 16) + 16 - index)
        output = extension_oracle(input)
        decrypted_temp = str(decrypted)
        for key, value in dict.items():
            if value == output[multiplier * 16:(multiplier + 1) * 16]:
                decrypted += key[-1:]
                break

        if decrypted_temp == str(
                decrypted):  # If the decrypted-bytearray has not changed, we have not been able to discover any new characters. Even if there is any more message left, no amount of iterations would get us more of it, so we interrupt the program
            break

    print('Decryption took: ' + str(datetime.datetime.now() - time_1) + ' hours. The oracle\'s secret string is:\n' + decrypted.decode().replace('\n', r'\n'))

    # NOTE: We could also use the general break_oracle-function from tools.py, but that would be a bit slower
def solve_2_5():
    print(create_kv('foo=bar&baz=qux&zap=zazzle'))
    print(profile_for('my_email@email.com&role=admin'))
def solve_2_6():
    def oracle(s):
        key = b'8884602576695132'
        prefix = b'\xeb\x85s\xf5\xdaT\x9b\xbb'
        target = b'TG9yZW0gaXBzdW0gZG9sb3Igc2l0IGFtZXQsIGNvbnNlY3RldHVyIGFkaXBpc2NpbmcgZWxpdCwgc2VkIGRvIGVpdXNtb2QgdGVtcG9yIGluY2lkaWR1bnQgdXQgbGFib3JlIGV0IGRvbG9yZSBtYWduYSBhbGlxdWEuIFV0IGVuaW0gYWQgbWluaW0gdmVuaWFtLCBxdWlzIG5vc3RydWQgZXhlcmNpdGF0aW9uIHVsbGFtY28gbGFib3JpcyBuaXNpIHV0IGFsaXF1aXAgZXggZWEgY29tbW9kbyBjb25zZXF1YXQuIER1aXMgYXV0ZSBpcnVyZSBkb2xvciBpbiByZXByZWhlbmRlcml0IGluIHZvbHVwdGF0ZSB2ZWxpdCBlc3NlIGNpbGx1bSBkb2xvcmUgZXUgZnVnaWF0IG51bGxhIHBhcmlhdHVyLiBFeGNlcHRldXIgc2ludCBvY2NhZWNhdCBjdXBpZGF0YXQgbm9uIHByb2lkZW50LCBzdW50IGluIGN1bHBhIHF1aSBvZmZpY2lhIGRlc2VydW50IG1vbGxpdCBhbmltIGlkIGVzdCBsYWJvcnVtLg=='
        target_decoded = b64decode(target)

        return encrypt_ecb(pad(prefix + s + target_decoded, AES.block_size), key)

    break_oracle(oracle)
def solve_2_7():
    print('String with PKCS#7-padding removed:\t' + str(pkcs7_strip(b'ICE ICE BABY\x04\x04\x04\x04')))
def solve_2_8():
    # These values are constant and provided to both functions
    key = os.urandom(16)
    iv = os.urandom(16)

    def func_1(s, key, iv):
        prepend = b'comment1=cooking%20MCs;userdata='
        extend = b';comment2=%20like%20a%20pound%20of%20bacon'
        s_f = bytearray(prepend + s.replace(b';', b'').replace(b'=', b'') + extend)     # Removing the potentially dangerous ';'- and '='-characters

        return encrypt_cbc(pad(s_f, AES.block_size), key, iv)
    def func_2(s, key, iv):
        return b';admin=true;' in decrypt_cbc(s, key, iv)

    admin_boolean = b':admin<true'
    payload = b'A' * (AES.block_size * 2 + (AES.block_size - len(admin_boolean))) + admin_boolean
    ciphertext = func_1(payload, key, iv)
    for i in range (1, -2, -1):     # In theory i = 1 & j = 1 should suffice, but in some cases it takes different values to produce the correct output. This loop takes AT MOST 9 iterations.
        for j in range(1, -2, -1):
            ciphertext_ = bytearray(ciphertext)
            ciphertext_[3 * AES.block_size + 5] += i
            ciphertext_[3 * AES.block_size + 11] += j
            output = func_2(ciphertext_, key, iv)
            if output:
                print('Admin granted.')
                return
    raise Exception('Admin not granted')    # If no output has decrypted into a form that grants admin we raise an exception as the encryption/decryption scheme has not been broken
