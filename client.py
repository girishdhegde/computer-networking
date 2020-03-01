import socket
from SPN import spn
from DH import dh

if __name__ == '__main__':


    #Assymetric key exchange using Diffie–Hellman
    base = 13131
    mod  = 8431
    key  = 467

    client1 = dh(base, mod, key)
    c1_pub_key = client1.generate_pub_key()

    msg = str(c1_pub_key)
    bytemsg = str.encode(msg)
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect(("127.0.0.1", 8080))
    client.send(bytemsg)
    
    data = client.recv(4096)
    c2_pub_key = int(data.decode())
    print("client2 public key:", c2_pub_key)

    client.close()
    
    common_key = client1.generate_common_key(c2_pub_key)
    
    print("\nsecret key is:", common_key)
    print('\nclient1 info:', client1)


    #Encryption/Decryption using Substitution and Permutation Networks
    client1_spn = spn(common_key)
  
    while True:
        msg = input(">")
        if msg == 'esc':
            break
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.connect(("127.0.0.1", 8080))
        
        ct = client1_spn.encrypt(msg)
        bytemsg = str.encode(ct)
        client.send(bytemsg)

        from_server = client.recv(4096)
        data = (from_server.decode())
        print("\nRecieved ciphertext from server:", data)
        data = client1_spn.decrypt(data)
        print("Decrypted message from server:", data, '\n')

    
        client.close()
