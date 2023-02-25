# Secrets decryptor

Secrets decryptor is currently a draft for offline decryption of PassSecurium
users' secrets (in case Zero Knowledge will be implemented).

## Building

Dependencies:
- make
- gcc
- OpenSSL

## Usage
1. Put mnemonic words separated with spaces corresponding to the password into
the *priv* file inside project root directory.
1. Put secrets one per line into the *secrets* file inside project root
directory.
1. run `$ make clean run`.

Decrypted secrets will be in the *decryptedSecrets* file inside project root
directory.
