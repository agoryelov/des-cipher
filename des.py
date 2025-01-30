from typing import Literal
from bitarray import bitarray
from bitarray.util import int2ba, ba2int, ba2hex
from constants import *

class KeyScheduler:
    _key: bitarray

    _num_shifts = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]
    _keys: list[bitarray]

    def __init__(self, key: bitarray) -> None:
        super().__init__()
        if len(key) != 64:
            raise ValueError("Invalid key length. Key must be exactly 8 bytes.")
        
        self._raw_key = key
        self._keys = []

        self._derive_keys()

    def _derive_keys(self) -> None:
        permuted = _permute_bits(self._raw_key, PC_1)

        left = permuted[:28]
        right = permuted[28:]

        for i in range(16):
            num_shifts = self._num_shifts[i]

            left = _shift_bits(left, num_shifts)
            right = _shift_bits(right, num_shifts)

            permuted = _permute_bits(left + right, PC_2)
            self._keys.append(permuted)

    def key(self, index) -> bitarray:
        if index >= len(self._keys):
            raise ValueError(f"Error getting key[{index}]. Index out of range.")
        
        return self._keys[index]
    
class DESCipher:
    def __init__(self):
        super().__init__()
    
    @staticmethod
    def _apply_sbox(block: bitarray, iteration: int) -> bitarray:
        index = iteration * 6
        part = block[index:index+6]

        row = part[0:1] + part[5:6]
        col = part[1:5]

        row = ba2int(row)
        col = ba2int(col)

        result = S_BOXES[iteration][row][col]
        return int2ba(result, length=4)

    @staticmethod
    def _apply_f(block: bitarray, subkey: bitarray) -> bitarray:
        e = _permute_bits(block, E)
        xor = e ^ subkey

        output = bitarray()
        for i in range(8):
            sbox = DESCipher._apply_sbox(xor, i)
            output.extend(sbox)
        
        return _permute_bits(output, P)

    @staticmethod
    def _process_block(block, scheduler: KeyScheduler, type: Literal["decrypt", "encrypt"]):
        ip = _permute_bits(block, IP)

        left = ip[:32]
        right = ip[32:]

        for i in range(16):
            key_index = i if type == "encrypt" else 15 - i
            next_key = scheduler.key(key_index)

            next_left = right
            next_right = left ^ DESCipher._apply_f(right, next_key)

            left = next_left
            right = next_right

            print(f"Round: {(i+1):02d}: {ba2hex(left + right)}")
        
        combined = right + left
        return _permute_bits(combined, IP_UNDO)

    def encrypt(self, plaintext: bitarray, key: bitarray):
        if mod := len(plaintext) % 64:
            pad_len = 64 - mod
            plaintext.extend([0] * pad_len)
        
        scheduler = KeyScheduler(key)

        output = bitarray()
        for i in range(0, len(plaintext), 64):
            block = plaintext[i:i+64]
            encrypted = self._process_block(block, scheduler, 'encrypt')
            output += encrypted
        return output

    def decrypt(self, ciphertext: bitarray, key: bitarray):
        if (len(ciphertext) % 64) != 0:
            raise ValueError("Invalid ciphertext length. Must be a multiple 8 bytes.")
        
        scheduler = KeyScheduler(key)

        output = bitarray()
        for i in range(0, len(ciphertext), 64):
            block = ciphertext[i:i+64]
            decrypted = self._process_block(block, scheduler, 'decrypt')
            output += decrypted
        return output


    
def _shift_bits(input: bitarray, num: int):
    output = input.copy()
    for _ in range(num):
        first = output[0]
        output <<= 1
        output[-1] = first
    return output

def _permute_bits(input: bitarray, table: list):
    output = bitarray()
    for i in table:
        output.append(input[i - 1])
    return output
