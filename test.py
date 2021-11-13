from AESteve import AES
# First create an instance of the AES class. Remember to enter your key in hex!"
aes = AES(key="54 68 61 74 73 20 6D 79 20 4B 75 6E 67 20 46 75")
# Plain text must be in bytes. Use .encode() or use a byte string
msg = b"hello world"
#or
msg = "Hello World! 🌎".encode() # hey its unicode!
print("Plain Text: ",msg)
en = aes.encrypt(msg)
print("Encrypt Base64: ",en)
de = aes.decrypt(en)
print("Decrypted Text: ",de)
print("Decoded Decrypted Text: ",de.decode()) #remember to decode if your original text was encoded!
