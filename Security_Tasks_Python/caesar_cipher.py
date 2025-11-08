
def caesar_cipher(text, shift, mode):
    """
    Encrypts or decrypts a message using the Caesar Cipher algorithm.
    :param text: The input string (message).
    :param shift: The integer shift value.
    :param mode: 'encrypt' or 'decrypt'.
    :return: The processed string.
    """
    result = ""
    if mode == 'decrypt':
        shift = -shift
    for char in text:
        if 'a' <= char <= 'z':
            shifted_char_code = ord('a') + (ord(char) - ord('a') + shift) % 26
            result += chr(shifted_char_code)
        elif 'A' <= char <= 'Z':
            shifted_char_code = ord('A') + (ord(char) - ord('A') + shift) % 26
            result += chr(shifted_char_code)
        else:
            result += char
    return result

def main():
    print("Welcome to the Caesar Cipher Tool!")
    while True:
        try:
            mode = input("Do you want to (e)ncrypt or (d)ecrypt? ").lower()
            if mode not in ['e', 'd']:
                print("Invalid choice. Please enter 'e' or 'd'.")
                continue
            message = input("Enter the message: ")
            shift = int(input("Enter the shift value (a number): "))
            if mode == 'e':
                print(f"Encrypted message: {caesar_cipher(message, shift, 'encrypt')}")
            else:
                print(f"Decrypted message: {caesar_cipher(message, shift, 'decrypt')}")
            if input("Do you want to continue? (yes/no): ").lower() != 'yes':
                break
        except ValueError:
            print("Invalid input for shift. Please enter a number.")

if __name__ == "__main__":
    main()
