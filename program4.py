def matrix_multiply(matrix, vector):
    result = [0, 0]
    result[0] = (matrix[0][0] * vector[0] + matrix[0][1] * vector[1]) % 26
    result[1] = (matrix[1][0] * vector[0] + matrix[1][1] * vector[1]) % 26
    return result


def hill_cipher(plaintext: str, key_matrix: list) -> str:
    plaintext = "".join([c.upper() for c in plaintext if c.isalpha()])

    if len(plaintext) % 2 != 0:
        plaintext += 'X'

    ciphertext_chars = []

    for i in range(0, len(plaintext), 2):
        vector = [ord(plaintext[i]) - ord('A'), ord(plaintext[i + 1]) - ord('A')]
        encrypted_vector = matrix_multiply(key_matrix, vector)
        ciphertext_chars.append(chr(encrypted_vector[0] + ord('A')))
        ciphertext_chars.append(chr(encrypted_vector[1] + ord('A')))

    return "".join(ciphertext_chars)


if __name__ == "__main__":
    key = [
        [3, 3],
        [2, 5]
    ]

    user_plaintext = input("Enter the plaintext: ")
    ciphertext = hill_cipher(user_plaintext, key)
    print(f"\nEncrypted Ciphertext: {ciphertext}")