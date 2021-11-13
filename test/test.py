from AESteve import AES
#must check if _name__ == '__main__'
if __name__ == '__main__':
    # First create an instance of the AES. Remember to enter your key in hex!"
    aes = AES(key="54 68 61 74 73 20 6D 79 20 4B 75 6E 67 20 46 75")
    #Playing text must be in bytes. Use .encode() or use a byte string
    msg = b"hello world"
    #or
    msg = "Hello World! 🌎".encode() # hey its unicode!
    print("Plain Text: ",msg)
    en = aes.encrypt(msg)
    print("Encrypt Base64: ",en)
    de = aes.decrypt(en)
    print("Decrypted Text: ",de)
    print("Decoded Decrypted Text: ",de.decode()) #remember to decode if your original text was encoded!

    #Encrypt File
    with open('test/files/testfile.png','rb') as plain_file:
        en = aes.encrypt(plain_file.read())
        with open('test/files/testfile.cry','wb') as encrypted_file:
            encrypted_file.write(en)

    # Decrypt File
    with open('test/files/testfile.cry','rb') as encrypted_file:
        de = aes.decrypt(encrypted_file.read())
        with open('test/files/testfile_decrypted.png','wb') as decrypted_file:
            decrypted_file.write(de)