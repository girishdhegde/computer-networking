class dh:
    def __init__(self, public_base, public_mod, private_key):
        self.base = public_base
        self.mod  = public_mod
        self.private_key = private_key
        self.public_key = None
        self.common_key = None

    def generate_pub_key(self):
        self.public_key = (self.base ** self.private_key) % self.mod
        return self.public_key

    def generate_common_key(self, pub_key):
        self.common_key = (pub_key ** self.private_key) % self.mod
        return self.common_key

    def __str__(self):
        return 'object of class Diffie–Hellman' +  '\nattributes: ' + ( 
                ', '.join(['{key} = {value}'.format(key=key, value=self.__dict__.get(key)) for key in self.__dict__]))





#####################################################################################################################################################################################################

if  __name__ == '__main__':

    alice = dh(5, 23, 4)
    ap_key = alice.generate_pub_key()

    bob = dh(5, 23, 3)
    bp_key = bob.generate_pub_key()

    s1 = alice.generate_common_key(bp_key)
    s2 = bob.generate_common_key(ap_key)

    print("\nsecret key is:", s1 if s1==s2 else 'not generated')
    print('\nbob info:', bob)
    print('\nalice info:', alice)

    # eve = dh(5, 23, 7)
    # ep_key = eve.generate_pub_key()
    # s3 = alice.generate_common_key(ep_key)
    # s4 = eve.generate_common_key(ap_key)
