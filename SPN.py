class spn:
     
      def  __init__(self, key):

            self.S_Box  = [14,  4, 13,  1,  2, 15, 11,  8,  3, 10,  6, 12,  5,  9,  0,  7]
            self.P_Box  = [ 0,  4,  8, 12,  1,  5,  9, 13,  2,  6, 10, 14,  3,  7, 11, 15]
            self.RS_Box = [self.S_Box.index(i) for i in range(16)]
            self.RP_Box = [self.P_Box.index(i) for i in range(16)]

            self.master_key = key
            self.subkeys    = None

      @staticmethod
      def generate_subkeys(K, n):
          sk = []
          for i in range(n, 0, -1):
              ki = K % (2 ** 16)
              sk.insert(0, ki)
              K = K >> 4
          return sk

      @staticmethod
      def xor(msg, key):
            n = ((ord(msg[0]) << 8) | ord(msg[1])) ^ key
            return chr((n & 0xff00) >> 8) + chr(n & 0x00ff)

      def substitute(self, msg):
            out = ''
            for c in msg:
                  h = ord(c)
                  l, r = (h & 0xf0) >> 4, h & 0x0f
                  hx   = (self.S_Box[l] << 4) | self.S_Box[r]
                  out += chr(hx)
            return out

      def reverse_substitute(self, msg):
            out = ''
            for c in msg:
                  h = ord(c)
                  l, r = (h & 0xf0) >> 4, h & 0x0f
                  hx   = (self.RS_Box[l] << 4) | self.RS_Box[r]
                  out += chr(hx)
            return out

      def permutation(self, msg):
            out = 0
            h = (ord(msg[0]) << 8) | (ord(msg[1]))
            for i in range(16):
                  l_bit = h % 2
                  h >>= 1
                  out |= l_bit << (self.P_Box[i])
            return chr((out & 0xff00) >> 8) + chr(out & 0x00ff)

      def reverse_permutation(self, msg):
            out = 0
            h = (ord(msg[0]) << 8) | (ord(msg[1]))
            for i in range(16):
                  l_bit = h % 2
                  h >>= 1
                  out |= l_bit << (self.RP_Box[i])
            return chr((out & 0xff00) >> 8) + chr(out & 0x00ff)

      def encrypt(self, msg, iterations=5):
            ciphertext = msg + ' ' if len(msg) %  2 else msg 
            subkeys = self.generate_subkeys(self.master_key, iterations)

            for itr in range(iterations):
                  msg = ciphertext
                  ciphertext = ''
                  for i in range(0, len(msg), 2):
                        xr = self.xor(msg[i: i+2], subkeys[itr])
                        sb = self.substitute(xr)
                        pm = self.permutation(sb)
                        ciphertext += pm

            return ciphertext


      def decrypt(self, msg, iterations=5):
            deciphertext = msg
            subkeys = self.generate_subkeys(self.master_key, iterations)

            for itr in range(iterations):
                  msg = deciphertext
                  deciphertext = ''
                  for i in range(0, len(msg), 2):
                        pm = self.reverse_permutation(msg[i: i+2])
                        sb = self.reverse_substitute(pm)
                        xr = self.xor(sb, subkeys[-(itr + 1)])
                        deciphertext += xr

            return deciphertext









####################################################################################################################################################################################################################

if __name__ == '__main__':
      sn = spn(0xfff4f8131)
      ct = sn.encrypt('SP_network')
      print("cipher text:", ct)
      # print("hex:", ':'.join(hex(ord(x))[2:] for x in ct))
      dt = sn.decrypt(ct)
      print("original text:", dt)


      # sub = (sn.substitute('ab'))
      # print(sub)

      # ori = (sn.reverse_substitute(sub))
      # print(ori)

      # p = sn.permutation('fr')
      # print(p)
      # rp = sn.reverse_permutation(p)
      # print(rp)

      # xr = (sn.xor('5y', 24955))
      # rx = (sn.xor(xr, 24955))
      # print(xr, rx)

