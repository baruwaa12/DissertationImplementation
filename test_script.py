# test_kyber.py
from kyber_py.kyber import Kyber512

def main():
    # Generate a key pair
    pk, sk = Kyber512.keygen()
    print("Kyber512 Public Key Length:", len(pk))
    print("Kyber512 Secret Key Length:", len(sk))
    
    # Encapsulate a shared key
    key, c = Kyber512.encaps(pk)
    print("Ciphertext Length:", len(c))
    print("Shared Key Length:", len(key))
    
    # Decapsulate to recover the shared key
    _key = Kyber512.decaps(sk, c)
    if key == _key:
        print("Shared keys match.")
    else:
        print("Error: Shared keys do not match.")

if __name__ == '__main__':
    main()
