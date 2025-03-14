from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from Crypto.Cipher import AES

def encrypt_message(plaintext, key):
    cipher = AES.new(key, AES.MODE_CBC)
    ciphertext = cipher.encrypt(pad(plaintext.encode(), AES.block_size))
    return cipher.iv, ciphertext

def decrypt_message(iv, ciphertext, key):
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
    return plaintext.decode()

def main():
    plaintext = input("Enter the plaintext message to encrypt: ")
    password = input("For encryption enter a password: ")

    key = pad(password.encode(), AES.block_size)[:32]

    iv, ciphertext = encrypt_message(plaintext, key)
    print("Encrypted message:", ciphertext.hex())
    print("Initialization vector:", iv.hex())

    decrypted_message = decrypt_message(iv, ciphertext, key)
    print("Decrypted message:", decrypted_message)

if __name__ == "__main__":
    main()
