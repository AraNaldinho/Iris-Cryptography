import socket             
import argparse
import copy
import math
import pickle
import random
from itertools import combinations
import cv
import numpy as np
from matplotlib import pyplot as plt
from PIL import Image
im = Image.open("1.jpg") #Can be many different formats.
rgb_im = im.convert('RGB')
pix = im.load()
def gcd(a, b):
    """returns the Greatest Common Divisor of a and b"""
    a = abs(a)
    b = abs(b)
    if a < b:
        a, b = b, a
    while b != 0:
        a, b = b, a % b
    return a


def coPrime(l):
    """returns 'True' if the values in the list L are all co-prime
       otherwise, it returns 'False'. """
    for i, j in combinations(l, 2):
        if gcd(i, j) != 1:
            return False
    return True


def gcd1(a, b):#extended euclidean algo
    """return  x, y and z, such that x is
    the GCD of a and b (i.e)x = y * a + z * b"""
    if a == 0:
        return b, 0, 1
    else:
        g, y, x = gcd1(b % a, a)
        return g, x - (b // a) * y, y


def modInv(a, m):
    """ m as +ve value between zero and m-1"""
	#only woks if its co prime no
    if coPrime([a, m]):
        linearCombination = gcd1(a, m)
        return linearCombination[1] % m
    else:
        return 0


def extractTwos(m):#func to return a tuple i.e array of int m=2 to the power of s the whole * d(i.e 1) 
    assert m >= 0
    i = 0
    while m & (2 ** i) == 0:
        i += 1
    return i, m >> i


def int2baseTwo(x):
    """base 2 conversion & stored reverse"""
    assert x >= 0
    bitInverse = []
    while x != 0:
        bitInverse.append(x & 1)
        x >>= 1#bit shift
    return bitInverse


def modExp(a, d, n):
    #returns a ** d (mod n)
    assert d >= 0#hceck wehther it is >=0
    assert n >= 0
    base2D = int2baseTwo(d)
    base2DLength = len(base2D)
    modArray = []
    result = 1
    for i in range(1, base2DLength + 1):
        if i == 1:
            modArray.append(a % n)
        else:
            modArray.append((modArray[i - 2] ** 2) % n)
    for i in range(0, base2DLength):
        if base2D[i] == 1:
            result *= base2D[i] * modArray[i]
    return result % n


def testingco(n, k):
    """
    Miller algorithm  pseudo-prime test
    return True means if it is a prime
    return False means definitely a composite
    """
    assert n >= 1 #checking for n is grter than 1
    assert k > 0 # ensure k is a +ve int

    if n == 2:
        return True #if n=2 returns true

    if n % 2 == 0:
        return False# return False for all they even no bigger than 2

    extract2 = extractTwos(n - 1)
    s = extract2[0]
    d = extract2[1]
    assert 2 ** s * d == n - 1

    def tryComposite(a):#to cross check whether its is a composite
 
        x = modExp(a, d, n) 
        if x == 1 or x == n - 1:
            return None
        else:
            for j in range(1, s):
                x = modExp(x, 2, n)
                if x == 1:
                    return False
                elif x == n - 1:
                    return None
            return False

    for i in range(0, k):
        a = random.randint(2, n - 2)
        if tryComposite(a) == False:
            return False
    return True


def primeSieve(k):#return a list of with 1,o,-1

    def isPrime(n):
        """return True is given num n is absolutely prime"""
        for i in range(2, int(n ** 0.5) + 1):
            if n % i == 0:
                return False
        return True
    result = [-1] * (k + 1)
    for i in range(2, int(k + 1)):
        if isPrime(i):
            result[i] = 1
        else:
            result[i] = 0
    return result


def findAPrime(a, b, k):
    """Return a pseudo prime no  btn a and b """
    x = random.randint(a, b)
    for i in range(0, int(10 * math.log(x) + 3)):
        if testingco(x, k):
            return x
        else:
            x += 1
    raise ValueError


def newKey(a, b, k):
    """ Try to find two large pseudo primes roughly between a and b.
    Generate public and private keys for RSA encryption.
    Raises ValueError if it fails to find one"""
    try:
        p = findAPrime(a, b, k)
        while True:
            q = findAPrime(a, b, k)
            if q != p:
                break
    except:
        raise ValueError

    n = p * q
    m = (p - 1) * (q - 1)

    while True:
        e = random.randint(1, m)
        if coPrime([e, m]):
            break

    d = modInv(e, m)
    return (n, e, d)


def string2numList(strn):
    #string to intt converion with help of ASCII value
    return [ ord(chars) for chars in pickle.dumps(strn) ]


def numList2string(l):
    #Converts a list of integers to a string based on ASCII values
    return pickle.loads(''.join(map(chr, l)))


def numList2blocks(l, n):
    """Take a list of integers(each between 0 and 127), and combines them
    into block size n using base 256. If len(L) % n != 0, use some random
    junk to fill L to make it."""
    # Note that ASCII printable characters range is 0x20 - 0x7E
    returnList = []
    toProcess = copy.copy(l)
    if len(toProcess) % n != 0:
        for i in range(0, n - len(toProcess) % n):
            toProcess.append(random.randint(32, 126))
    for i in range(0, len(toProcess), n):
        block = 0
        for j in range(0, n):
            block += toProcess[i + j] << (8 * (n - j - 1))
        returnList.append(block)
    return returnList


def blocks2numList(blocks, n):
    """inverse function of numList2blocks."""
    toProcess = copy.copy(blocks)
    returnList = []
    for numBlock in toProcess:
        inner = []
        for i in range(0, n):
            inner.append(numBlock % 256)
            numBlock >>= 8
        inner.reverse()
        returnList.extend(inner)
    return returnList


def encrypt(message, modN, e, blockSize):
    """given a string message, public keys and blockSize, encrypt using
    RSA algorithms."""
    numList = string2numList(message)
    numBlocks = numList2blocks(numList, blockSize)
    return [modExp(blocks, e, modN) for blocks in numBlocks]


def decrypt(secret, modN, d, blockSize):
    """reverse function of encrypt"""
    numBlocks = [modExp(blocks, d, modN) for blocks in secret]
    numList = blocks2numList(numBlocks, blockSize)
    return numList2string(numList)

def block_size(val):
    try:
        v = int(val)
        assert(v >= 10 and v <= 1000)
    except:
        raise argparse.ArgumentTypeError("{} is not a valid block size".format(val))
    return val

"""def start():
    parser = argparse.ArgumentParser()

    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-m", "--message", help="Text message to encrypt")
    group.add_argument("-f", "--file", type=file, help="Text file to encrypt")

    parser.add_argument("-b", "--block-size", type=block_size, default=15,
        help="Block size to break message info smaller trunks")
    args = parser.parse_args()



    n, e, d = newKey(10 ** 100, 10 ** 101, 50)
    print n
    print "-"*80
    print e
    print "-"*80
    print d
    print "-"*80
    if args.message is not None:
        message = args.message
    else:
        print args.file
        try:
            message = args.file.read()
        finally:
             args.file.close()

    print "original message is {}".format(message)
    print "-"*80
    cipher = encrypt(message, n, e, 15)
    print "cipher text is {}".format(cipher)
    print "-"*80
    deciphered = decrypt(cipher, n, d, 15)	
    print "decrypted message is {}".format(deciphered)"""
 
def iris():
	

    WAITKEY_DELAY_MS = 10
    STOP_KEY = 'q'

    cv.NamedWindow("image - press 'q' to quit", cv.CV_WINDOW_AUTOSIZE);
    cv.NamedWindow("post-process", cv.CV_WINDOW_AUTOSIZE);

    

      # grab image
    orig = cv.LoadImage('1.jpg')

    # create tmp images
    grey_scale = cv.CreateImage(cv.GetSize(orig), 8, 1)
    processed = cv.CreateImage(cv.GetSize(orig), 8, 1)


    cv.Smooth(orig, orig, cv.CV_GAUSSIAN, 5, 5)

    cv.CvtColor(orig, grey_scale, cv.CV_RGB2GRAY)

    # do some processing on the grey scale image
    cv.Erode(grey_scale, processed, None, 10)
    cv.Dilate(processed, processed, None, 10)
    cv.Canny(processed, processed, 5, 70, 3)
    cv.Smooth(processed, processed, cv.CV_GAUSSIAN, 15, 15)

    storage = cv.CreateMat(orig.width, 1, cv.CV_32FC3)

    # these parameters need to be adjusted for every single image
    HIGH =70
    LOW = 140

    try: 
        # extract circles
        cv.HoughCircles(processed, storage, cv.CV_HOUGH_GRADIENT, 2, 32.0, HIGH, LOW)

        for i in range(0, len(np.asarray(storage))):
          # print "circle #%d" %i
            Radius = int(np.asarray(storage)[i][0][2])
            x = int(np.asarray(storage)[i][0][0])
            y = int(np.asarray(storage)[i][0][1])
            center = (x, y)
	   
            # green dot on center and red circle around
            cv.Circle(orig, center, 1, cv.CV_RGB(0, 255, 0), -1, 8, 0)
            cv.Circle(orig, center, Radius, cv.CV_RGB(255, 0, 0), 3, 8, 0)

            cv.Circle(processed, center, 1, cv.CV_RGB(0, 255, 0), -1, 8, 0)
            cv.Circle(processed, center, Radius, cv.CV_RGB(255, 0, 0), 3, 8, 0)

    except:
        print "nothing found"
        pass
     
    return(x,y,Radius)
if __name__=='__main__':	
    #message="kaviyabharathi"
    s = socket.socket()         # Create a socket object
    host = socket.gethostname() # Get local machine name
    port = 12372	               # Reserve a port for your service .
    s.connect((host, port))
    while True:
	a,b,c=iris()
	for i in range(1,c):
	
             r, g, b1 = rgb_im.getpixel((a+i,b))
             sum1=r+g+b1
        for i in range(1,c):
	     r, g, b1 = rgb_im.getpixel((a,b+i))
             sum2=r+g+b1
	n, e, d = newKey(sum1**10,sum2**11,15)
	#print n,e,d
	s.send(str(e))
	print "send ee"
	s.send(str(n))
        print "send"
	cipher_buffer = s.recv(9000)
        cipher = pickle.loads(cipher_buffer)
	#cipher = encrypt(message, n, e, 15)
        print cipher
	deciphered = decrypt(cipher, n, d, 15)
	print deciphered
    s.close                    

