
from PIL import Image

def encrypt_image(image_path, output_path, key):
    try:
        img = Image.open(image_path)
        img_data = list(img.getdata())
        encrypted_pixels = [img_data[(i + key) % len(img_data)] for i in range(len(img_data))]
        encrypted_img = Image.new(img.mode, img.size)
        encrypted_img.putdata(encrypted_pixels)
        encrypted_img.save(output_path)
        print(f"Image encrypted successfully and saved to {output_path}")
    except FileNotFoundError:
        print(f"Error: The file at {image_path} was not found.")
    except Exception as e:
        print(f"An error occurred: {e}")

def decrypt_image(image_path, output_path, key):
    encrypt_image(image_path, output_path, -key)
    print(f"Image decrypted successfully and saved to {output_path}")

def main():
    print("Welcome to the Pixel Manipulation Image Encryption Tool!")
    while True:
        choice = input("Do you want to (e)ncrypt or (d)ecrypt an image? ").lower()
        if choice not in ['e', 'd']:
            print("Invalid choice. Please enter 'e' or 'd'.")
            continue
        input_path = input("Enter the path to the image file: ")
        output_path = input("Enter the path to save the output file: ")
        try:
            key = int(input("Enter the encryption/decryption key (an integer): "))
        except ValueError:
            print("Invalid key. Please enter an integer.")
            continue
        if choice == 'e':
            encrypt_image(input_path, output_path, key)
        else:
            decrypt_image(input_path, output_path, key)
        if input("Do you want to process another image? (yes/no): ").lower() != 'yes':
            break

if __name__ == "__main__":
    main()
