import streamlit as st
import string
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.serialization import load_pem_private_key

# ================== Cifra de César ==================
def cifra_cesar(mensagem, deslocamento):
    resultado = ""
    for char in mensagem:
        if char.isupper():
            resultado += chr((ord(char) + deslocamento - 65) % 26 + 65)
        elif char.islower():
            resultado += chr((ord(char) + deslocamento - 97) % 26 + 97)
        else:
            resultado += char
    return resultado

# ================== Vigenère ==================
def vigenere_encrypt(message, key):
    encrypted_message = []
    key = key.upper()
    key_length = len(key)
    key_as_int = [ord(i) for i in key]
    message_int = [ord(i) for i in message.upper()]

    for i in range(len(message_int)):
        if message[i].isalpha():
            value = (message_int[i] + key_as_int[i % key_length]) % 26
            encrypted_message.append(chr(value + 65))
        else:
            encrypted_message.append(message[i])
    return ''.join(encrypted_message)

def vigenere_decrypt(ciphertext, key):
    decrypted_message = []
    key = key.upper()
    key_length = len(key)
    key_as_int = [ord(i) for i in key]
    ciphertext_int = [ord(i) for i in ciphertext.upper()]

    for i in range(len(ciphertext_int)):
        if ciphertext[i].isalpha():
            value = (ciphertext_int[i] - key_as_int[i % key_length]) % 26
            decrypted_message.append(chr(value + 65))
        else:
            decrypted_message.append(ciphertext[i])
    return ''.join(decrypted_message)

# ================== RSA ==================
def generate_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key

def encrypt_message(public_key, message):
    return public_key.encrypt(
        message.encode('utf-8'),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

def decrypt_message(private_key, encrypted_message):
    return private_key.decrypt(
        encrypted_message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    ).decode('utf-8')

# ================== Enigma ==================
ALPHABET = string.ascii_uppercase
ROTOR_I = "EKMFLGDQVZNTOWYHXUSPAIBRCJ"
ROTOR_II = "AJDKSIRUXBLHWTMCQGZNPYFVOE"
ROTOR_III = "BDFHJLCPRTXVZNYEIWGAKMUSQO"
REFLECTOR = "YRUHQSLDPXNGOKMIEBFZCWVJAT"
ROTORS = [ROTOR_I, ROTOR_II, ROTOR_III]

def create_plugboard(pairs):
    plugboard = {c: c for c in ALPHABET}
    for a, b in pairs:
        plugboard[a] = b
        plugboard[b] = a
    return plugboard

def rotate(rotor):
    return rotor[1:] + rotor[0]

def substitute(rotor, c, reverse=False):
    if reverse:
        return ALPHABET[rotor.index(c)]
    else:
        return rotor[ALPHABET.index(c)]

def enigma(message, plugboard_pairs):
    plugboard = create_plugboard(plugboard_pairs)
    encrypted_message = []
    for char in message.upper():
        if char not in ALPHABET:
            encrypted_message.append(char)
            continue
        char = plugboard[char]
        for i, rotor in enumerate(ROTORS):
            char = substitute(rotor, char)
            if i == 0 or (i == 1 and len(encrypted_message) % 26 == 0):
                ROTORS[i] = rotate(rotor)
        char = substitute(REFLECTOR, char)
        for rotor in reversed(ROTORS):
            char = substitute(rotor, char, reverse=True)
        char = plugboard[char]
        encrypted_message.append(char)
    return ''.join(encrypted_message)

# ================== Streamlit Interface ==================
st.title("🔐 Crypto Playground")

option = st.sidebar.selectbox(
    "Escolha o algoritmo:",
    ["Cifra de César", "Vigenère", "RSA", "Enigma"]
)

if option == "Cifra de César":
    text = st.text_input("Mensagem:")
    shift = st.number_input("Deslocamento:", value=3)
    if st.button("Criptografar"):
        st.write(cifra_cesar(text, shift))

elif option == "Vigenère":
    text = st.text_input("Mensagem:")
    key = st.text_input("Chave:")
    mode = st.radio("Modo:", ["Criptografar", "Decriptografar"])
    if st.button("Executar") and key:
        if mode == "Criptografar":
            st.write(vigenere_encrypt(text, key))
        else:
            st.write(vigenere_decrypt(text, key))

elif option == "RSA":
    text = st.text_input("Mensagem:")
    if st.button("Gerar Chaves e Criptografar"):
        priv, pub = generate_keys()
        enc = encrypt_message(pub, text)
        st.text_area("Mensagem Criptografada:", enc.hex())
        dec = decrypt_message(priv, enc)
        st.text_area("Mensagem Decriptografada:", dec)

elif option == "Enigma":
    text = st.text_input("Mensagem:")
    pairs = st.text_input("Plugboard (ex: AB,CD):")
    plugboard_pairs = [(p[0], p[1]) for p in pairs.split(",") if len(p) == 2]
    if st.button("Criptografar"):
        st.write(enigma(text, plugboard_pairs))
