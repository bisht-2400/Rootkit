import random
import string

from PIL import Image


def write_file(data, extension, size):
    with open(f'decoded_img/extracted_{size//8}bytes_file.{extension}', 'wb') as f:
        print(f"[FILE CREATED] File created and saved")
        f.write(data)


def open_image(filename: str):
    """
    Open the Image file and return it.
    :param: filename: destination of the image file.
    :return: the Image object file.
    """
    try:
        image = Image.open(filename, 'r')
        return image
    except IOError as e:
        print(f"Error with the image file.\n{e}")


def get_random_char():
    letters = string.ascii_letters
    return bytes(random.choice(letters), 'ascii')


def read_file(filename: str):
    """
    Reads the file and returns the data as byte string.
    :param: filename: Destination and name to the file.
    :return: a string with the file.
    """
    with open(f'{filename}', 'rb') as f:
        data = f.read()
    return data


def xor_encrypt_decrypt(bits_data, key):
    """
    Performs XOR encryption on a string of bits using a single-byte key.
    :param bits_data: The string of bits to encrypt.
    :param key: The single-byte encryption key (8 bits).
    :return: The encrypted string of bits.
    """
    if len(key) != 8:
        raise ValueError("Key must be a single byte (8 bits)")
    key = key * (len(bits_data) // 8) + key[:len(bits_data) % 8]
    encrypted_bits = [str(int(bits_data[i]) ^ int(key[i])) for i in range(len(bits_data))]
    encrypted_data = ''.join(encrypted_bits)
    return encrypted_data


def string_to_bytes(input_string):
    encoded_bytes = []
    for char in input_string:
        ascii_value = ord(char)
        binary_string = format(ascii_value, '08b')
        encoded_bytes.append(binary_string)
    encoded_data = ''.join(encoded_bytes).encode()
    return encoded_data


def bytes_to_string(encoded_data):
    binary_string = ''.join(format(byte, '08b') for byte in encoded_data)
    binary_chunks = [binary_string[i:i + 8] for i in range(0, len(binary_string), 8)]
    decoded_string = ''.join(chr(int(chunk, 2)) for chunk in binary_chunks)
    return decoded_string


def bytes_to_bits(byte_data):
    """
    Converts byte data to a string of bits.
    :param: byte_data: Byte data to convert.
    :return: A string of bits.
    """
    bits_list = [format(byte, '08b') for byte in byte_data]
    bits_string = ''.join(bits_list)
    return bits_string


def bits_to_string(bits):
    if len(bits) % 8 != 0:
        raise ValueError("Input string length must be a multiple of 8")
    byte_chunks = [bits[i:i + 8] for i in range(0, len(bits), 8)]
    characters = [chr(int(chunk, 2)) for chunk in byte_chunks]
    return ''.join(characters)


def bit_string_to_bytes(bit_string):
    if len(bit_string) % 8 != 0:
        raise ValueError("Input string length must be a multiple of 8")
    byte_array = bytearray()
    for i in range(0, len(bit_string), 8):
        byte = int(bit_string[i:i + 8], 2)
        byte_array.append(byte)
    return bytes(byte_array)
