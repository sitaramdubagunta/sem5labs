def mod_inverse(a, m):
    for x in range(1, m):
        if (a * x) % m == 1: return x
    raise ValueError("no inv")


def additive(text, key, decrypt=False):
    k = -key if decrypt else key
    return "".join(
        [chr((ord(c) - 65 + k) % 26 + 65) if c.isupper() else chr((ord(c) - 97 + k) % 26 + 97) if c.islower() else c for
         c in text.replace(" ", "")])


def mult(text, key, decrypt=False):
    k = mod_inverse(key, 26) if decrypt else key
    return "".join(
        [chr(((ord(c) - 65) * k) % 26 + 65) if c.isupper() else chr(((ord(c) - 97) * k) % 26 + 97) if c.islower() else c
         for c in text.replace(" ", "")])


def affine(text, a, b, decrypt=False):
    if decrypt:
        ia = mod_inverse(a, 26)
        return "".join([chr((ia * (ord(c) - 65 - b)) % 26 + 65) if c.isupper() else chr(
            (ia * (ord(c) - 97 - b)) % 26 + 97) if c.islower() else c for c in text.replace(" ", "")])
    return "".join([chr(((ord(c) - 65) * a + b) % 26 + 65) if c.isupper() else chr(
        ((ord(c) - 97) * a + b) % 26 + 97) if c.islower() else c for c in text.replace(" ", "")])


while True:
    print("\n CIPHeR MENU ")
    print("1.additive Cipher")
    print("2.Multiplicatve Cipher")
    print("3.Affine Ciphre")
    print("4.Exit")

    ch = input("Choose opton: ")
    if ch == '4': break

    act = input("Encrypt or Decrypt (e/d): ").lower()
    txt = input("Enter text: ")

    try:
        if ch == '1':
            k = int(input("Enter key: "))
            print("Out:", additive(txt, k, act == 'd'))
        elif ch == '2':
            k = int(input("Enter key: "))
            print("Out:", mult(txt, k, act == 'd'))
        elif ch == '3':
            ka = int(input("Enter key A: "))
            kb = int(input("Enter key B: "))
            print("Out:", affine(txt, ka, kb, act == 'd'))
    except Exception as e:
        print("Err:", e)