# DES Cipher

Basic implementation of the DES cipher encryption and decryption. Provide operation type, input text, and key to get back encrypted ciphertext. Input and output uses hexadecimal string format.


## Requirements

This project depends on `bitarray` library. You can either install it globally or in a virtual environment.

```
pip3 install -r requirements.txt
```

or 


```
python3 -m venv .venv
source .venv/bin/activate
pip3 install -r requirements.txt
```

## Usage

```
python3 ./run.py encrypt 02468aceeca86420 --key 0f1571c947d9e859
Output: da02ce3a89ecac3b

python3 ./run.py decrypt da02ce3a89ecac3b --key 0f1571c947d9e859
Output: 02468aceeca86420

python3 ./run.py encrypt 0123456789abcdef --key 133457799bbcdff1
Output: 85e813540f0ab405
```
