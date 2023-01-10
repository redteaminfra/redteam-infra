#!/usr/bin/env python3
# Copyright (c) 2023, Oracle and/or its affiliates.


import sys
import os
import subprocess
import datetime
import hashlib

def usage():
    sys.stderr.write(f"usage: {sys.argv[0]} <plaintext_file> [ciphertext_file]\n")
    sys.stderr.write("\n")
    sys.stderr.write("\t <plaintext_file>: filename to encrypt\n")
    sys.stderr.write("\t [ciphertext_file]: output filename, <plaintext_file>.enc if unset\n")
    sys.stderr.write("\n")
    sys.exit(1)


def generate_passphrase():
    args = ['openssl', 'rand', '-rand', '/dev/urandom', '-base64', '16']
    p = subprocess.run(args, stdout=subprocess.PIPE, check=True)
    return p.stdout.decode('utf-8').strip()


def encrypt(passphrase, infile, outfile):
    # Eat deprecated passphrase derivation warning on encryption
    # libressl's implementation of openssl does not support pbkdf2 or iterations, so we use
    # the "insecure" kdf. The password is 16 bytes cryptographically secure random data.
    args = ['openssl', 'enc', '-aes256', '-in', infile, '-out', outfile, '-pass', f'pass:{passphrase}']
    p = subprocess.run(args, check=True, stderr=subprocess.PIPE)

def hashit(algo, data):
    m = hashlib.new(algo)
    m.update(data)
    return m.hexdigest()

def getIoC(filename):
    contents = None
    with open(filename, 'rb') as f:
        contents = f.read()
    algos = ['md5', 'sha1', 'sha256']
    ioc = {}
    for algo in algos:
        digest = hashit(algo, contents)
        ioc[algo] = digest
    return ioc

def printIoC(filename, prefix):
    ioc = getIoC(filename)
    for items in ioc.items():
        print(f"[+] {prefix} {items[0]}: '{items[1]}'")


def main():
    if (len(sys.argv) < 2 or len(sys.argv) > 3):
        usage()
    plantext_file = sys.argv[1]
    if not os.path.exists(plantext_file):
        usage()
    cipherext_file = f"{plantext_file}.enc"
    if len(sys.argv) == 3:
        cipherext_file = sys.argv[2]
    if os.path.exists(cipherext_file):
        print(f"[-] ciphertext_file '{cipherext_file} exists.")
        sys.exit(1)

    print(f"implant encryptor @ {datetime.datetime.now().isoformat()}")
    print(f"[*] input: '{plantext_file}'")
    print(f"[*] output: '{cipherext_file}'")
    printIoC(plantext_file, "plaintext")
    passphrase = generate_passphrase()
    print(f"[+] encryption passphrase: '{passphrase}'")
    encrypt(passphrase, plantext_file, cipherext_file)
    decrypt_cmd = f'openssl enc -aes256 -d -pass pass:"{passphrase}" -md sha256 -in {cipherext_file}'
    print(f"[*] decrypt and run with with: {decrypt_cmd} > [ARBITRARY IOC NAME]")
    printIoC(cipherext_file, "encrypted")
    print("Have a nice day!")

if __name__ == "__main__":
    main()
