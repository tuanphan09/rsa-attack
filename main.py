from oracle import Oracle
from sys import stdout
import time


def os2ip(octets: bytes) -> int:
    """
    Octet-String-to-Integer primitive
    PKCS #1 Version 1.5 (RFC2313)
    """
    return int.from_bytes(octets, 'big')


def i2osp(i: int, k: int) -> bytes:
    """
    Integer-to-Octet-String primitive
    PKCS #1 Version 1.5 (RFC2313)
    """
    return i.to_bytes(k, byteorder='big')

def interval(a: int, b: int) -> range:
    return range(a, b + 1)

def ceildiv(a: int, b: int) -> int:
    return -(-a // b)

def floordiv(a: int, b: int) -> int:
    return a // b




def bleichenbacher(oracle: Oracle):
    
    k, n, e = oracle.get_k(), oracle.get_n(), oracle.get_e()
    
    B = pow(2, 8 * (k - 2))
    B2 = 2 * B
    B3 = B2 + B

    print("---------------")
    print("k = ", k)
    print("n = ", n)
    print("B2 = ", B2)
    print("B3 = ", B3)
    print("---------------")


    # get ciphertext
    cipher = os2ip(oracle.get_ciphertext())
    
    def pkcs_conformant(c_param: int, s_param: int) -> bool:
        """
        Check for PKCS conformance.
        """
        pkcs_conformant.counter += 1
        return oracle.check_pkcs_format(i2osp(c_param * pow(s_param, e, n) % n, k))
    
    pkcs_conformant.counter = 0

    """
    Step 1: Blinding.
    Can be skipped if c is already PKCS conforming.
    In that case, we set s_0 = 1.
    """
    print("Starting Step 1")

    assert(pkcs_conformant(cipher, 1))
    
    # while(True):
    #     s_0 = 

    s_0 = 1
    c_0 = cipher * pow(s_0, e, n) % n
    """
    Step 2: Init an interval containing m
    """
    set_m_old = {(B2, B3 - 1)}
    print("Step 2: Init an interval containing m: ",set_m_old)

    i = 1
    s_old = s_0
    total_time= 0 
    while True:
        start_time = int(round(time.time() * 1000))
        
        print("LOOP:", i)
        """
        Step 3: Start searching new PKCS conforming ciphertext.
        """
        if i == 1:
            print("Starting Step 3: Start searching new PKCS conforming ciphertext")
            nb_check = 0
            s_new = ceildiv(n, B3)
            while not pkcs_conformant(c_0, s_new):
                s_new += 1
                nb_check += 1

            print("\tFound s_new after {} calls to the oracle".format(nb_check))


        elif i > 1 and len(set_m_old) >= 2:
            
            print("Starting Step 4.a: more than 1 interval")
            nb_check = 0
            s_new = s_old + 1
            while not pkcs_conformant(c_0, s_new):
                s_new += 1
                nb_check += 1

            print("\tFound s_new after {} calls to the oracle".format(nb_check))

        elif len(set_m_old) == 1:
            print("Starting Step 4.b: Only 1 interval")

            a, b = next(iter(set_m_old))
            found = False
            r = ceildiv(2 * (b * s_old - B2), n)
            nb_check = 0
            while not found:
                for s in interval(ceildiv(B2 + r*n, b), floordiv(B3 - 1 + r*n, a)):
                    nb_check += 1
                    if pkcs_conformant(c_0, s):
                        found = True
                        s_new = s
                        break
                r += 1

            print("\tFound s_new after {} calls to the oracle".format(nb_check))


        """
        Step 5: Narrowing the set of solutions with s_new
        """
        print("Starting Step 5: Narrowing the set of solutions with s_new ")

        
        nb_inter = 0
        nb_new_inter = 0
        range_plaintext = 0

        set_m_new = set()
        for a, b in set_m_old:
            nb_inter += 1
            r_min = ceildiv(a * s_new - B3 + 1, n)
            r_max = floordiv(b * s_new - B2, n)

            print("\tInterval {}: range value of r = {}".format(nb_inter, r_max - r_min + 1))

            for r in interval(r_min, r_max):
                new_lb = max(a, ceildiv(B2 + r*n, s_new))
                new_ub = min(b, floordiv(B3 - 1 + r*n, s_new))
                if new_lb <= new_ub:  # intersection must be non-empty
                    set_m_new |= {(new_lb, new_ub)}
                    nb_new_inter += 1
                    range_plaintext += new_ub - new_lb + 1

        print("\tNumber of new interval: {}".format(nb_new_inter))

        """
        Step 6: Computing the solution.
        """

        print("Starting with Step 6: Computing the solution")
        print("\tNumber of possible value of plaintext = {}".format(range_plaintext))
        if len(set_m_new) == 1:
            a, b = next(iter(set_m_new))
            if a == b:
                print("\tSolution found!!!!!!!\n\n")
                print("Calculated: ", i2osp(a, k))
                print("Success after {} calls to the oracle.".format(pkcs_conformant.counter))
                print("Toatl time = {}ms".format(total_time))

                return a

        print("\tHaven't found solution yet, back to step 4 !!!")
        i += 1
        s_old = s_new
        set_m_old = set_m_new
        
        end_time = int(round(time.time() * 1000))
        total_time += end_time - start_time
        print("Time = {}ms".format(end_time - start_time))
        print("--------------------------------------------------------")

if __name__ == "__main__":
    oracle = Oracle()
    bleichenbacher(oracle)