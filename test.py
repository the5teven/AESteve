from AESteve import AES
aes = AES("54 68 61 74 73 20 6D 79 20 4B 75 6E 67 20 46 75")
msg = "Hello World!".encode()
print("Plain Text: ",msg)
en = aes.encrypt(msg)
print("Encrypt Base64: ",en)
de = aes.dencrypt(en)
print("Decrypted Text: ",de)
