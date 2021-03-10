"""
Python implementation of PKCS-1.5 RSA encryption
https://tools.ietf.org/html/rfc2313
"""
from os import urandom
from math import log
from Cryptodome.Util import number
import sys

# To support recursion in egcd
sys.setrecursionlimit(1500)


def egcd(a, b):
    """
    Use Euclid's algorithm to find gcd of a and b
    """
    if a == 0:
        return b, 0, 1
    else:
        g, y, x = egcd(b % a, a)
        return g, x - (b // a) * y, y


def modinv(a, m):
    """
    Compute modular inverse of a over m
    """
    g, x, y = egcd(a, m)
    if g != 1:
        raise Exception('modular inverse does not exist')
    else:
        return x % m


def key_gen(n_length):
    """
    Generate RSA key
    :param n_length: length of modulus
    :return: k, e, N, p, q
    """ 
    if n_length % 8:
        raise Exception("n_length must be divisible by 8")
    k = 512
    e = 65537
    N = 529803473496650627334934380236450455032538356845867691553491639849020589682964569661806668914786691748501223909440437806130300519171586828298121962268772685197715268730599506418427305951668095998130510352088559571822485928424720534612361375852356497302008510795686311570027534324871998131804048048067158391219215834397374614550753080054975740380869344333723986639666726972408351961774595737723510103755897591478782064006433024404674824926915257049065823510895853114117051465791267005214570022565207676946975540919079202803285927930435482863237576476716358046126588244842814128846392765505501229886184424798214719183792612309978074438681049484774595062073242781083130584929367924976241241201949848133354904362186863123979207466314983883935150333821513090384995597450801056275162422595097811002576880023033035473507073665579641395471193307206838723201843100817327381312504465400823105279532849974491693124969639764845868404257704504231343823767219590993648642969980972190983908916050857323732031758745594761101938270879446770619871509546586230494277929415316936030998684752438194647869303216150795519644351385751444674729311984019577596274148528982629765298105137796561742168846498641332037014461096613205081415760217327808411909512047
    p = 29940916181823255768723002402474640761740952397604501778009902918984097049933646769487018741501070211773265218193626320482789226320990637575110133100521115398830393590744456310134428444839693553546623035212981991963648774152139781354550126330621691263754359751466190031615906344009167987915034874337015203232456887546496989414909485110159174129380735224098615902655638463424921127481041988531466148158732441901237020506800428870560387695045645947153859460513288840654882405332238352764525463674141443183302164613536674735639346338441535868209752199435606199238962705383570640595396322522316106796557653957879221134721
    q = 17694965320342718374934712795560082845724579075073189037488526073221142586103685746654807748243531145942441319566583577202750819293565449189215862545184847901623541647788356676995486251185728496418472711305760023206225127020026744250964664091335118176840421124477530234206885939401433572297413741017471864821684509654933459688032561542870197836350185114666963733756469614506801425529711221163822728994144102864842314382495456141074001135314850488157434047967801440315677322989738218521876487092403180374188328981368317648470315575602580880306848943747045194497012637888568908575947279451665960904507607288775923489007
    
    return k,e,N,p,q
    
    
    
    e = 2 ** 16 + 1

    while True:
        p = number.getPrime(int(n_length / 2), urandom)
        q = number.getPrime(int(n_length / 2), urandom)
        g, x, y = egcd(e, (p - 1) * (q - 1))
        if p != q and g == 1:
            break

    k = int(n_length / 8)
    N = p * q

    return k, e, N, p, q


class RSA(object):
    def __init__(self, k, e, N, p=None, q=None, var=False):
        self.k = k
        self.e = e
        self.N = N
        self.p = p
        self.q = q
        self.var = var
        if self.var:
            print('init vars:', k, N)
        if (p is not None) and (q is not None):
            self.phin = (p - 1) * (q - 1)
            self.d = modinv(self.e, self.phin) # should be e^-1 so that we will be able to decrypt
            self.test()
        else:
            self.d = None
        if self.var: 
            print(log(N, 2), N)
            if self.d is not None:
                print(hex(self.d))

    def encrypt(self, M):
        return pow(M, self.e, self.N)

    def decrypt(self, C):
        if self.d is None:
            raise Exception('Private key not set')
        return pow(C, self.d, self.N)

    def test(self):
        M = 0x205
        if self.decrypt(self.encrypt(M)) != M:
            raise Exception('Error in RSA decrypt encrypt test')
        if self.var:
            print('RSA decrypt encrypt test success')

    def getN(self):
        return self.N

    def getpqd(self):
        return self.p, self.q, self.d

    def gete(self):
        return self.e


class RSA_PKCS_1(RSA):
    def __init__(self, bt, *args):
        self.bt = bt #Block type
        super(RSA_PKCS_1, self).__init__(*args)

    min_pad_size = 11

    def enc_PKCS_1(self, d, ps=None):
        """
        RSA encryption
        """
        if len(d) > self.k - RSA_PKCS_1.min_pad_size:
            raise Exception("byte list too long")

        if self.bt == 0 and d[0] == 0:
            raise Exception("first byte must be nonzero 0 if bt=0")

        if ps is None: #padding string
            ps = self.pad(self.k-3-len(d)) #???
        
        eb = bytes([0]) + bytes([self.bt]) + ps + bytes([0]) + d   # Encryption Block ????

        x = int.from_bytes(eb, byteorder='big')  # Conversion to integer

        y = self.encrypt(x)

        ed = y.to_bytes(self.k, byteorder='big')
        return ed

    def dec_PKCS_1(self, ed):
        """
        RSA decryption
        """
        if len(ed) != self.k:
            raise Exception("length of ed must be k")

        y = int.from_bytes(ed, byteorder='big')
        if y < 0 or y >= self.N:
            raise Exception("y out of bounds")

        x = self.decrypt(y)

        eb = x.to_bytes(self.k, byteorder='big')

        return self.parse(eb)

    def pad(self, l):
        """
        Generate padding string
        :param l: length of padding string
        :return: padding string
        """
        if self.bt == 0:
            ps = bytes(l)
        elif self.bt == 1:
            ps = l * bytes([0xff])
        elif self.bt == 2:
            added = 0
            ps = b''
            while added < l:
                rand_byte = urandom(1)
                if rand_byte != b'\x00':
                    ps += rand_byte
                    added += 1
        else:
            raise Exception("incompatible block type")
        return ps

    def parse(self, eb):
        """
        Parse encryption block
        :param eb: encryption block
        :return: parsed data
        """
        return 12 #?



if __name__ == "__main__":

    n_length = 4096
    data = b'secret message'
    bt = 2

    keys = key_gen(n_length)
    print(keys)

    pkcs = RSA_PKCS_1(bt, *keys)

    ed = pkcs.enc_PKCS_1(data)
    print(ed)

    d = pkcs.dec_PKCS_1(ed)
    print(d)