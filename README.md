# Postquantum encryption with subset sum (Third project for [INF568 Advanced Cryptology](https://moodle.polytechnique.fr/course/view.php?id=2655) @ Ecole polytechnique)

Python implementation of the cryptosystem introducted in *[this paper](https://eprint.iacr.org/2009/576)*.

## File structure

* **lps.py** contains all the code.  
* **test** contains a public/private key pair along with a plaintext, the corresponding ciphertext, and the decryption of the ciphertext which matches the original plaintext.  

## Methods

After creating an LPS object you can call the following methods:
* **key_gen:** Generates a private/public key pair from parameters are described in the [original paper](https://eprint.iacr.org/2009/576).
* **enc:** Encrypt an input message.
* **dec:** Decrypt an input ciphertext.
* **encf:** Encrypt a message from a file.
* **decf:** Decrypt a ciphertext from a file.
* **enc_to_file:** Encrypt a message from a file or from an input and save the ciphertext to a file.
* **dec_to_file:** Decrypt a ciphertext from a file or from an input and save the result to a file.
* **export_private:** Export the current private key to a file.
* **import_private:** Replace the current private key with one stored in a specified file.
* **export_public:** Export the current public key to a file.
* **import_public:** Replace the current public key with one stored in a specified file.

## Usage examples

Generating a key pair, exporting it and computing encrypt and decrypt.  
```python
python3
>>> import lps
>>> scheme = lps.LPS()
>>> scheme.key_gen(200,100001,64)
>>> scheme.export_private('test/custom-200-64-100001.priv')
>>> scheme.export_public('test/custom-200-64-100001.pub')
>>> scheme.enc_to_file('test/freedom.in','test/freedom.enc')
>>> scheme.dec_to_file('test/freedom.enc','test/freedom.dec')
```

Importing the key pair and decrypting the encrypted file  
```python
python3
>>> import lps
>>> scheme = lps.LPS()
>>> scheme.import_public("test/custom-200-64-100001.pub")
>>> scheme.import_private("test/custom-200-64-100001.priv")
>>> scheme.decf('test/freedom.enc')
'freedom\n'
```
