
import argparse

from bitarray.util import hex2ba, ba2hex

from des import DESCipher

def main():
    parser = argparse.ArgumentParser()

    parser.add_argument(
        "operation", 
        choices=['encrypt', 'decrypt'], 
        help="Keyword used to create playfair cipher matrix."
    )

    parser.add_argument(
        "input",
        help="Either plaintext when encrypting or ciphertext when decrypting."
    )

    parser.add_argument("--key", "-k", type=str, required=True, help="Key used for encryption or decryption.")

    args = parser.parse_args()

    try:
        input = hex2ba(args.input)
        key = hex2ba(args.key)
    except ValueError:
        raise ValueError("Input and key must be valid hexadecimal strings.")
    
    cipher = DESCipher()

    if args.operation == "encrypt":
        ciphertext = cipher.encrypt(input, key)
        print(f"\nCiphertext: {ba2hex(ciphertext)}")
    
    if args.operation == "decrypt":
        decrypted = cipher.decrypt(input, key)
        print(f"\nDecrypt: {ba2hex(decrypted)}")
    

    # input_data = hex2ba('02468aceeca86420')
    # input_key = hex2ba('0f1571c947d9e859')
    # output_data = hex2ba('da02ce3a89ecac3b')

if __name__ == "__main__":
    main()
