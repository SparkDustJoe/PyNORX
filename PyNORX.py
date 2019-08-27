__doc__ = """
    A Python3 implementation of the NORX AEAD encryption scheme (v3.0) 
    As released per the CAESAR competition (Round 3, which is as far as NORX progressed)
    Original design by Jean-Philippe Aumasson, Philipp Jovanovic, Samuel Neves (contact@norx.io)
    Original Python2 implementation by Philipp Jovanovic <philipp@jovanovic.io>, 2014-2015 (spec v2.0)
        (CC0, see LICENSE for more details on https://github.com/norx/norx or https://github.com/Daeinar/norx-py)
    This implementation by Dustin J. Sparks (SparkDustJoe@gmail.com, https://github.com/sparkdustjoe)
    Copyright (c) 2019 under a CC0 License
    """

__all__ = [
    "__title__", "__summary__", "__uri__", "__version__", "__author__",
    "__email__", "__license__", "__copyright__",
]
__title__ = "PyNORX";
__summary__ = "A Python3 library implementation of the NORX AEAD encryption scheme (v3.0)";
__version__ = "0.1";
__uri__ = "https://github.com/sparkdustjoe"
__author__ = "Dustin J. Sparks (Philipp Jovanovic on original Python2 code for spec v2.0)";
__email__ = "SparkDustJoe@gmail.com (see repository in GitHub.com/sparkdustjoe for submitting bugs/issues)";
__license__ = "CC0";
__copyright__ = "(c) 2019 Dustin J. Sparks (CC0 License)";

#import array;
#import sys;

class PyNORX(object):
    """
    A Python3 implementation of the NORX AEAD encryption scheme (v3.0) 
    As released per the CAESAR competition (Round 3, which is as far as NORX progressed)
    Original design by Jean-Philippe Aumasson, Philipp Jovanovic, Samuel Neves (contact@norx.io)
    Original Python2 implementation by Philipp Jovanovic <philipp@jovanovic.io>, 2014-2015 (spec v2.0)
        (CC0, see LICENSE for more details on https://github.com/norx/norx or https://github.com/Daeinar/norx-py)
    This implementation by Dustin J. Sparks (SparkDustJoe@gmail.com, https://github.com/sparkdustjoe)
    Copyright (c) 2019 under a CC0 License
    """

    def __init__(self, *, Word_Size_Bits=64, Rounds=4, Lanes=1, Tag_Size_Bits=256):
        """
        Create a new Norx object (not initialized; see seperate 'init' step for supplying the Key and Nonce)
        Allowed values: 
            32 or 64 Word_Size_Bits, Default = 64,
            1-63 Rounds (inclusive), Default = 4,
            1 to 255 parallel Lanes (inclusive), Default = 1
            0-128 (32-bit-words) or 0-256 (64-bit-words) (inclusive), Default = 256
        """
        assert Word_Size_Bits in [32, 64]
        assert 63 >= Rounds >= 1
        assert 255 >= Lanes >= 1 # inifinite parallelism (P=0) not supported
        assert 4 * Word_Size_Bits >= Tag_Size_Bits >= 0
        assert Tag_Size_Bits % 8 == 0 # byte-aligned tags only
        self.NORX_W_BITS = Word_Size_Bits
        self.NORX_R = Rounds
        self.NORX_P = Lanes
        self.NORX_T_BITS = Tag_Size_Bits;
        self.BYTES_WORD = Word_Size_Bits // 8; # integer division
        self.WORDS_NONCE = 4; # per spec 3.0 "4w"
        self.BYTES_NONCE = self.BYTES_WORD * self.WORDS_NONCE;
        self.WORDS_KEY = 4; # per spec 3.0 "4w"
        self.BYTES_KEY = self.BYTES_WORD * self.WORDS_KEY;
        self.BITS_STATE = Word_Size_Bits * 16; # per spec, state is 16w
        self.BYTES_STATE = self.BITS_STATE // 8; # integer division
        self.WORDS_CAPACITY = 4; # per spec 3.0 "4w"
        self.BYTES_CAPACITY = self.BYTES_WORD * self.WORDS_CAPACITY;
        self.BITS_CAPACITY = self.BYTES_CAPACITY * 8;
        self.BYTES_TAG = self.NORX_T_BITS // 8; # integer division
        self.BYTES_RATE = self.BYTES_STATE - self.BYTES_CAPACITY; 
        self.WORDS_RATE = self.BYTES_RATE // self.BYTES_WORD; # integer division
        self.DOMAIN_HEAD_TAG = 1 << 0;
        self.DOMAIN_PYLD_TAG = 1 << 1;
        self.DOMAIN_TRAIL_TAG = 1 << 2;
        self.DOMAIN_FIN_TAG = 1 << 3;
        self.DOMAIN_BR_TAG = 1 << 4;
        self.DOMAIN_MRG_TAG = 1 << 5;

        if Word_Size_Bits == 32:
            self.__ROT_CONST__ = (8, 11, 16, 31);
            self.__INIT_CONST__ = (
                0xA3D8D930, 0x3FA8B72C, 0xED84EB49, 0xEDCA4787, 
                0x335463EB, 0xF994220B, 0xBE0BF5C9, 0xD7C49104)
            self.__WORD_BITS_MASK__ = 0xffffffff
        elif Word_Size_Bits == 64:
            self.__ROT_CONST__ = (8, 19, 40, 63)
            self.__INIT_CONST__ = (
                0xB15E641748DE5E6B, 0xAA95E955E10F8410, 0x28D1034441A9DD40, 0x7F31BBF964E93BF5,
                0xB5E9E22493DFFB96, 0xB980C852479FAFBD, 0xDA24516BF55EAFD4, 0x86026AE8536F1501)
            self.__WORD_BITS_MASK__ = 0xffffffffffffffff

    def __load__(self, x):
        return int.from_bytes(x, byteorder = 'little', signed = False);

    def __load_from__(self, buffer, index, word_size_bytes):
        return self.__load__(buffer[index:index+word_size_bytes]);

    def __store__(self, x):
        return x.to_bytes(length = self.BYTES_WORD, byteorder = 'little');

    def __rot_r__(self, a, n):
        return ((a >> n) | (a << (self.NORX_W_BITS - n))) & self.__WORD_BITS_MASK__

    def __h_funct__(self, a, b):
        return ((a ^ b) ^ ((a & b) << 1)) & self.__WORD_BITS_MASK__

    def __g_funct__(self, S, a, b, c, d): 
        # take advantage of passing State contents by Object Ref
        ROT = self.__rot_r__;
        RC = self.__ROT_CONST__;
        H = self.__h_funct__;
        S[a] = H(S[a], S[b])
        S[d] = ROT(S[a] ^ S[d], RC[0])
        S[c] = H(S[c], S[d])
        S[b] = ROT(S[b] ^ S[c], RC[1])
        S[a] = H(S[a], S[b])
        S[d] = ROT(S[a] ^ S[d], RC[2])
        S[c] = H(S[c], S[d])
        S[b] = ROT(S[b] ^ S[c], RC[3])
        return;

    def __f_funct__(self, S, r):
        G = self.__g_funct__;
        for i in range(0, r):
            # Column step
            G(S, 0, 4, 8, 12)
            G(S, 1, 5, 9, 13)
            G(S, 2, 6, 10, 14)
            G(S, 3, 7, 11, 15)
            # Diagonal step
            G(S, 0, 5, 10, 15)
            G(S, 1, 6, 11, 12)
            G(S, 2, 7, 8, 13)
            G(S, 3, 4, 9, 14)
        return;

    def __pad__(self, x):
        y = bytearray(self.BYTES_RATE)
        y[:len(x)] = x
        y[len(x)] ^= 0x01;
        y[-1] ^= 0x80;
        return y;

    def init(self, n, k):
        b = self.BYTES_WORD

        K = [self.__load_from__(k, 0, b),
             self.__load_from__(k, b, b),
             self.__load_from__(k, 2*b, b),
             self.__load_from__(k, 3*b, b)];
        N = [self.__load_from__(n, 0, b),
             self.__load_from__(n, b, b),
             self.__load_from__(n, 2*b, b),
             self.__load_from__(n, 3*b, b)];

        U = self.__INIT_CONST__
        S = [
            N[0], N[1], N[2], N[3], K[0], K[1], K[2], K[3],
            U[0], U[1], U[2], U[3], U[4], U[5], U[6], U[7]
            ];
        S[12] ^= self.NORX_W_BITS # mix in session parameters
        S[13] ^= self.NORX_R
        S[14] ^= self.NORX_P
        S[15] ^= self.NORX_T_BITS
        self.__f_funct__(S, self.NORX_R) # permute
        S[12] ^= K[0] # added in V3.0, mix Key into State Capacity 
        S[13] ^= K[1] #  again after initialization
        S[14] ^= K[2]
        S[15] ^= K[3]
        return S;

    def __absorb__(self, S, x, tag):
        inlen = len(x)
        if inlen > 0:
            i, n = 0, self.BYTES_RATE
            while inlen >= n:
                self.__absorb_block__(S, x[n*i:n*(i+1)], tag)
                inlen -= n
                i += 1
            self.__absorb_last__(S, x[n*i:n*i+inlen], tag)

    def __absorb_block__(self, S, x, tag):
        b = self.BYTES_WORD
        S[15] ^= tag
        self.__f_funct__(S, self.NORX_R)
        for i in range(0, self.WORDS_RATE):
            y = b*i;
            S[i] ^= self.__load_from__(x, y, b);

    def __absorb_last__(self, S, x, tag):
        y = self.__pad__(x)
        self.__absorb_block__(S, y, tag)

    def __merge_lane__(self, S, L):
        L[15] ^= self.DOMAIN_MRG_TAG;
        self.__f_funct__(L, self.NORX_R);
        for i in range(0, 16):
            S[i] ^= L[i];
            L[i] |= self.__WORD_BITS_MASK__; # destroy contents of old state
        return S;

    def __encryptP1__(self, S, x):
        b = self.BYTES_RATE;
        c = bytearray()
        inlen = len(x)
        if inlen > 0:
            i = 0;
            while inlen >= b:
                y = b*i;
                c += self.__enc_block__(S, x[y:y+b])
                inlen -= self.BYTES_RATE
                i += 1
            c += self.__enc_last__(S, x[self.BYTES_RATE*i:])
        return c

    def __encryptP2__(self, SL, x):
        b = self.BYTES_RATE;
        c = bytearray();
        inlen = len(x);
        lane_ptr = 0
        if inlen > 0:
            i = 0
            while inlen >= b:
                y = b*i;
                c += self.__enc_block__(SL[lane_ptr], x[y:y+b]);
                inlen -= b;
                i += 1
                lane_ptr = (lane_ptr + 1) % self.NORX_P
            c += self.__enc_last__(SL[lane_ptr], x[b*i:])
        return c

    def __enc_block__(self, S, x):
        c = bytearray()
        b = self.BYTES_WORD
        S[15] ^= self.DOMAIN_PYLD_TAG
        self.__f_funct__(S, self.NORX_R)
        for i in range(0, self.WORDS_RATE):
            y = b*i;
            S[i] ^= self.__load_from__(x, y, b);
            c += self.__store__(S[i])
        return c;

    def __enc_last__(self, S, x):
        y = self.__pad__(x)
        c = self.__enc_block__(S, y)
        return c[:len(x)]

    def __decryptP1__(self, S, x):
        b = self.BYTES_RATE;
        m = bytearray()
        inlen = len(x)
        if inlen > 0:
            i = 0
            while inlen >= b:
                y = b*i;
                m += self.__dec_block__(S, x[y:y+b]);
                inlen -= b;
                i += 1
            m += self.__dec_last__(S, x[b*i:])
        return m
    
    def __decryptP2__(self, SL, x):
        b = self.BYTES_RATE;
        m = bytearray()
        inlen = len(x)
        lane_ptr = 0
        if inlen > 0:
            i = 0
            while inlen >= b:
                y = b*i;
                m += self.__dec_block__(SL[lane_ptr], x[y:y+b]);
                inlen -= b;
                i += 1
                lane_ptr = (lane_ptr + 1) % self.NORX_P;
            m += self.__dec_last__(SL[lane_ptr], x[b*i:])
        return m

    def __dec_block__(self, S, x):
        m = bytearray()
        b = self.BYTES_WORD
        S[15] ^= self.DOMAIN_PYLD_TAG
        self.__f_funct__(S, self.NORX_R)
        for i in range(0, self.WORDS_RATE):
            y = b*i;
            c = self.__load_from__(x, y, b);
            m += self.__store__(S[i] ^ c)
            S[i] = c
        return m;

    def __dec_last__(self, S, x):
        m = bytearray()
        buffer = bytearray()
        b = self.BYTES_WORD
        S[15] ^= self.DOMAIN_PYLD_TAG
        self.__f_funct__(S, self.NORX_R)
        for i in range(0, self.WORDS_RATE):
            buffer += self.__store__(S[i]);
        buffer[:len(x)] = x; # replace the buffer with actual data (x)
        buffer[len(x)] ^= 0x01; # apply padding bits at length and last byte
        buffer[-1] ^= 0x80;
        for i in range(0, self.WORDS_RATE):
            y = b*i;
            c = self.__load_from__(buffer, y, b);
            m += self.__store__(S[i] ^ c)
            S[i] = c
        return m[:len(x)]

    def __gen_tag__(self, S, k):
        b = self.BYTES_WORD
        K = [self.__load_from__(k, 0, b), # prep the key again for mixing into the State
             self.__load_from__(k, b, b),
             self.__load_from__(k, 2*b, b),
             self.__load_from__(k, 3*b, b)];
        t = bytearray();
        S[15] ^= self.DOMAIN_FIN_TAG;
        self.__f_funct__(S, self.NORX_R);
        S[12] ^= K[0]; # added in v3.0, mix key into Capacity of State
        S[13] ^= K[1]; #   during post-processing / tag generation
        S[14] ^= K[2];
        S[15] ^= K[3];
        self.__f_funct__(S, self.NORX_R);
        S[12] ^= K[0]; # added in v3.0, mix key into Capacity of State
        S[13] ^= K[1]; #   during post-processing / tag generation
        S[14] ^= K[2];
        S[15] ^= K[3];
        for i in range(0, self.WORDS_CAPACITY):
            t += self.__store__(S[i + self.WORDS_RATE]);
        for i in range(0, 16): S[i] = 0; # burn state, no longer needed
        del S;
        return t[:self.NORX_T_BITS // 8]; # integer division

    def aead_encrypt(self, h, m, t, n, k):
        """
        Encrypt and tag message (returns bytearray(ciphertext if any + tag of Tag_Size_Bits size))
        """
        assert len(k) == self.BYTES_KEY;
        assert len(n) == self.BYTES_NONCE;
        c = bytearray();
        S = self.init(n, k);
        self.__absorb__(S, h, self.DOMAIN_HEAD_TAG);
        if (self.NORX_P == 1):
            c += self.__encryptP1__(S, m);
        elif (self.NORX_P > 1):
            #raise Exception("Parallelism (P>1) not supported.");
            S[15] ^= self.DOMAIN_BR_TAG;
            self.__f_funct__(S, self.NORX_R);
            SL = {};
            SL[0] = S[:]; # skip lane 0 for the next step (XOR 0 has no effect)
            for i in range(1, self.NORX_P):
                SL[i] = S[:]; #make a copy
                for j in range(0, self.WORDS_RATE): # per spec, only the RATE words of the STATE are affected 
                    SL[i][j] ^= i # tag the lane number into every RATE word of the states
            c += self.__encryptP2__(SL, m);
            for i in range(0, len(S)): S[i] = 0; # burn the state
            for i in range(0, self.NORX_P):
                S = self.__merge_lane__(S, SL[i]); # merge the lane back into the main state, 
                del SL[i]; # then destroy the lane (contents cleared to all 1's in the function itself)
        else: # p == 0
            raise Exception("Inifite parallelism (P=0) not supported.");
        self.__absorb__(S, t, self.DOMAIN_TRAIL_TAG);
        c += self.__gen_tag__(S, k);
        return bytes(c);

    def aead_decrypt(self, h, c, t, n, k):
        """
        Decrypt and validate ciphertext (returns tuple(True/False, bytearray of plaintext if any))
        """
        assert len(k) == self.BYTES_KEY;
        assert len(n) == self.BYTES_NONCE;
        assert len(c) >= self.NORX_T_BITS // 8; # integer division
        m = bytearray()
        #c = bytearray(c)
        d = len(c)-self.BYTES_TAG;
        c, t0 = c[:d], c[d:];
        S = self.init(n, k);
        self.__absorb__(S, h, self.DOMAIN_HEAD_TAG);
        if (self.NORX_P == 1):
            m += self.__decryptP1__(S, c);
        elif (self.NORX_P > 1):
            S[15] ^= self.DOMAIN_BR_TAG;
            self.__f_funct__(S, self.NORX_R);
            SL = {};
            SL[0] = S[:]; # skip lane 0 for the next step (XOR 0 has no effect)
            for i in range(1, self.NORX_P): 
                SL[i] = S[:]; # make a copy
                for j in range(0, self.WORDS_RATE): # per spec, only the RATE words of the STATE are affected 
                    SL[i][j] ^= i # tag the lane number into every RATE word of the states
            m += self.__decryptP2__(SL, c); 
            for i in range(0, len(S)): S[i] = 0; # burn the state
            for i in range(0, self.NORX_P):
                S = self.__merge_lane__(S, SL[i]); # merge the lane back into the main state, 
                del SL[i]; # then destroy the lane (contents cleared to all 1's in the function itself)
        else:
            raise Exception("Inifite parallelism (P=0) not supported.");
        self.__absorb__(S, t, self.DOMAIN_TRAIL_TAG);
        t1 = self.__gen_tag__(S, k);
        acc = 0 # verify tag
        for i in range(0, self.BYTES_TAG):
            acc |= t0[i] ^ t1[i]; # any bit set to '1' (a difference between the two values) will stick
        if acc != 0: # and any '1' bit != 0, meaning something is different
            del m;
            return (False, None); # validation failed, return nothing
            #if (m): #DEBUGGING ONLY!!!
            #    return (False, m); #DEBUGGING ONLY!!! 
            #else: #DEBUGGING ONLY!!!
            #    return (False, None); #DEBUGGING ONLY!!!
        else:
            if (m):
                return (True, m); 
            else:
                return (True, None); # don't return an empty array (validation still passes)

if (__name__ == "__main__"):
    import PyNORXTESTS;
    import PyNORXTESTCASES;
    PyNORXTESTS.RUN_TESTS();
