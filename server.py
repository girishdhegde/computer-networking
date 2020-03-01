import socket
from SPN import spn
from DH import dh

if __name__ == '__main__':

    #Assymetric key exchange using Diffie–Hellman
    base = 13131
    mod  = 8431
    key  = 741

    client2 = dh(base, mod, key)
    c2_pub_key = client2.generate_pub_key()

    msg = str(c2_pub_key)
    bytemsg = str.encode(msg)

    flag = False
    serv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    serv.bind(("127.0.0.1", 8080))
    serv.listen(5)
    while True:
        conn, addr = serv.accept()
        while True:
            data = conn.recv(4096)
            if not data: break
            data = (data.decode())
            print('client1 public key:', data)
            if data: 
                conn.send(bytemsg)
                flag = True
                break    
        if flag:
            break      
        conn.close()


    c1_pub_key = int(data)   
    common_key = client2.generate_common_key(c1_pub_key)
    
    print("\nsecret key is:", common_key)
    print('\nclient2 info:', client2)

    client2_spn = spn(common_key)

    serv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    serv.bind(("127.0.0.1", 8080))
    serv.listen(5)
    data = 'xyz'
    while True:
        conn, addr = serv.accept()
        while True:
            data = conn.recv(4096)
            if not data: break
            data = (data.decode())
            print("\nRecieved ciphertext:", data)
            data = client2_spn.decrypt(data)
            print("Decrypted message:", data)

            if 'ESC' in data.split() :
                break   

            ct = client2_spn.encrypt('Message received as ' + data)
            bytemsg = str.encode(ct)
            conn.send(bytemsg)
        if 'ESC' in data.split() :
            break      
        conn.close()
