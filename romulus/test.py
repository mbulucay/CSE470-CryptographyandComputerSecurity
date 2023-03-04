import modes as crpyt
import random

key1 = [random.randint(0, 255) for _ in range(64)]
key2 = [random.randint(0, 255) for _ in range(64)]


plaintext1 = "dummy text of the printing and typesetting industry. Lorem Ipsum has been the industry's standard dummy text".encode()
plaintext2 = "It was popularised in the 1960s with the release of Letraset sheets containing".encode()


def test_cbc():
    print("++++++++ CBC MODE +++++++")

    print("=========== EXAMPLE 1 ===========")
    print(" Plain text:", plaintext1.decode(), "\n")
    encrypted = crpyt.crpyto_cbc(plaintext1,key1)
    print(" Encrypted text : ",encrypted)
    decrypted = crpyt.decrpyto_cbc(encrypted,key1)
    print("Decrpyted text: ",decrypted, "\n")

    print("=========== EXAMPLE 2 ===========")
    print(" Plain text:", plaintext1.decode(), "\n")
    encrypted = crpyt.crpyto_cbc(plaintext1,key2)
    print(" Encrypted text : ",encrypted)
    decrypted = crpyt.decrpyto_cbc(encrypted,key2)
    print("Decrpyted text: ",decrypted, "\n")

    print("=========== EXAMPLE 3 ===========")
    print(" Plain text:", plaintext2.decode(), "\n")
    encrypted = crpyt.crpyto_cbc(plaintext2,key1)
    print(" Encrypted text : ",encrypted)
    decrypted = crpyt.decrpyto_cbc(encrypted,key1)
    print("Decrpyted text: ",decrypted, "\n")

    print("=========== EXAMPLE 4 ===========")
    print(" Plain text:", plaintext2.decode(), "\n")
    encrypted = crpyt.crpyto_cbc(plaintext2,key2)
    print(" Encrypted text : ",encrypted)
    decrypted = crpyt.decrpyto_cbc(encrypted,key2)
    print("Decrpyted text: ",decrypted, "\n")


def test_ofb():
    print("++++++++ OFB MODE +++++++")
    
    print("=========== EXAMPLE 1 ===========")
    print(" Plain text:", plaintext1.decode(), "\n")
    encrypted = crpyt.encrypt_ofb(plaintext1,key1)
    print(" Encrypted text : ",encrypted)
    decrypted = crpyt.decrypt_ofb(encrypted,key1)
    print("Decrpyted text: ",decrypted, "\n")

    print("=========== EXAMPLE 2 ===========")
    print(" Plain text:", plaintext1.decode(), "\n")
    encrypted = crpyt.encrypt_ofb(plaintext1,key2)
    print(" Encrypted text : ",encrypted)
    decrypted = crpyt.decrypt_ofb(encrypted,key2)
    print("Decrpyted text: ",decrypted, "\n")

    print("=========== EXAMPLE 3 ===========")
    print(" Plain text:", plaintext2.decode(), "\n")
    encrypted = crpyt.encrypt_ofb(plaintext2,key1)
    print(" Encrypted text : ",encrypted)
    decrypted = crpyt.decrypt_ofb(encrypted,key1)
    print("Decrpyted text: ",decrypted, "\n")

    print("=========== EXAMPLE 4 ===========")
    print(" Plain text:", plaintext2.decode(), "\n")
    encrypted = crpyt.encrypt_ofb(plaintext2,key2)
    print(" Encrypted text : ",encrypted)
    decrypted = crpyt.decrypt_ofb(encrypted,key2)
    print("Decrpyted text: ",decrypted, "\n")

if __name__ == "__main__":
    test_cbc()
    test_ofb()
