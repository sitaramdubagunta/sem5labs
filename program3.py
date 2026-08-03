def playfaircipher(plaintext: str, key: str , encrypt: bool = True) -> str:
    matrix = [["" for _ in range(5)] for _ in range(5)]
    seen = set()

    key = key.upper().replace(" ", "").replace("J", "I")
    alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'

    keystream = ""
    for char in key + alphabet:
        if char not in seen and char.isalpha():
            seen.add(char)
            keystream += char

    idx = 0
    for row in range(5):
        for col in range(5):
            matrix[row][col] = keystream[idx]
            idx += 1

    plaintext = "".join([c.upper() if c.upper() != 'J' else 'I' for c in plaintext if c.isalpha()])

    pairs = []
    i = 0
    while i < len(plaintext):
        if i + 1 == len(plaintext) or plaintext[i] == plaintext[i + 1]:
            pairs.append(plaintext[i] + 'X')
            i += 1
        else:
            pairs.append(plaintext[i] + plaintext[i + 1])
            i += 2

    def find_pos(letter):
        for r in range(5):
            for c in range(5):
                if matrix[r][c] == letter:
                    return r, c
        return None

    direction = 1 if encrypt else -1
    result = []

    for pair in pairs:
        r1, c1 = find_pos(pair[0])
        r2, c2 = find_pos(pair[1])

        if r1 == r2:
            result.append(matrix[r1][(c1 + direction) % 5])
            result.append(matrix[r2][(c2 + direction) % 5])
        elif c1 == c2:
            result.append(matrix[(r1 + direction) % 5][c1])
            result.append(matrix[(r2 + direction) % 5][c2])
        else:
            result.append(matrix[r1][c2])
            result.append(matrix[r2][c1])

    return "".join(result)


if __name__ == "__main__":
    user_plaintext = input("Enter the plaintext: ")
    user_key = input("Enter the secret key: ")
    encrypt = input("Encrypt or Decrypt (e/d): ").lower()
    ciphertext = playfaircipher(user_plaintext, user_key, encrypt=(encrypt != 'd'))
    print(f"\nEncrypted Ciphertext: {ciphertext}")