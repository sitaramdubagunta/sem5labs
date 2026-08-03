def vigenere_cipher(key: str, plaintext: str, encrypt=False) -> str:
    plaintext = plaintext.replace(" ", "")
    key = key.replace(" ", "").upper()

    ans = []
    for i, c in enumerate(plaintext):
        shift = ord(key[i % len(key)]) - ord('A')

        if not encrypt:
            shift = -1 * shift

        caseofch = ord('A') if c.isupper() else ord('a')

        if c.isalpha():
            ans.append(chr((ord(c) - caseofch + shift) % 26 + caseofch))
        else:
            ans.append(c)
    return ''.join(ans)


def autokey(key: str, plaintext: str, encrypt=False) -> str:
    plaintext = plaintext.replace(" ", "")
    key = key.replace(" ", "").upper()
    keystream = ""

    if len(key) > len(plaintext):
        keystream = "".join(key[:len(plaintext)])
    else:
        keystream = key + plaintext[:len(plaintext) - len(key)]

    ans = []

    for i, c in enumerate(plaintext):

        shift = ord(keystream[i]) - ord('A')

        if not encrypt:
            shift = -1 * shift
        caseofch = ord('A') if c.isupper() else ord('a')
        if c.isalpha():
            ans.append(chr((ord(c) - caseofch + shift) % 26 + caseofch))
        else:
            ans.append(c)
    return ''.join(ans)


def main():
    while True:
        print("\n1. Vigenere")
        print("2. Autokey")
        print("3. Exit")

        choice = input("> ").strip()

        if choice == '1':
            key = input("Key: ").strip()
            text = input("Text: ").strip()
            mode = input("Encrypt (y/n)? ").strip().lower() == 'y'
            print("Result:", vigenere_cipher(key, text, encrypt=mode))

        elif choice == '2':
            key = input("Key: ").strip()
            text = input("Text: ").strip()
            mode = input("Encrypt (y/n)? ").strip().lower() == 'y'
            print("Result:", autokey(key, text, encrypt=mode))

        elif choice == '3':
            break


if __name__ == "__main__":
    main()