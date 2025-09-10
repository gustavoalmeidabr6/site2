# Início de célula
! pip install cryptography


# Início de célula
def cifra_cesar(mensagem, deslocamento):
    resultado = ""

    # Itera sobre cada caractere da mensagem
    for char in mensagem:
        # Cifra letras maiúsculas
        if char.isupper():
            resultado += chr((ord(char) + deslocamento - 65) % 26 + 65)
        # Cifra letras minúsculas
        elif char.islower():
            resultado += chr((ord(char) + deslocamento - 97) % 26 + 97)
        # Mantém caracteres não alfabéticos inalterados
        else:
            resultado += char

    return resultado

# Exemplo de uso
mensagem = "chavear"
deslocamento = 17
mensagem_cifrada = cifra_cesar(mensagem, deslocamento)
print("Mensagem original:", mensagem)
print("Mensagem cifrada:", mensagem_cifrada)


# Início de célula
def cifra_cesar(mensagem, deslocamento):
    resultado = ""

    print(f"Deslocamento aplicado: {deslocamento}")
    print("Caracter Original -> Caracter Cifrado")

    # Itera sobre cada caractere da mensagem
    for char in mensagem:
        # Cifra letras maiúsculas
        if char.isupper():
            novo_char = chr((ord(char) + deslocamento - 65) % 26 + 65)
            #print(f"{char} -> {novo_char} (Deslocado em {deslocamento})")
            resultado += novo_char
        # Cifra letras minúsculas
        elif char.islower():
            novo_char = chr((ord(char) + deslocamento - 97) % 26 + 97)
            #print(f"{char} -> {novo_char} (Deslocado em {deslocamento})")
            resultado += novo_char
        # Mantém caracteres não alfabéticos inalterados
        else:
            print(f"{char} -> {char} (Sem deslocamento)")
            resultado += char

    return resultado

# Exemplo de uso
mensagem = "Estamos na aula de SCS"
deslocamento = 9
mensagem_cifrada = cifra_cesar(mensagem, deslocamento)
print("\nMensagem original:", mensagem)
print("Mensagem cifrada:", mensagem_cifrada)


# Início de célula
# Função para criptografar usando a Cifra de Vigenère
def vigenere_encrypt(message, key):
    encrypted_message = []
    key = key.upper()  # Transformar a chave em maiúsculas
    key_length = len(key)
    key_as_int = [ord(i) for i in key]  # Convertendo as letras da chave para valores numéricos
    message_int = [ord(i) for i in message.upper()]  # Convertendo a mensagem para valores numéricos

    for i in range(len(message_int)):
        if message[i].isalpha():  # Apenas letras serão criptografadas
            value = (message_int[i] + key_as_int[i % key_length]) % 26
            encrypted_message.append(chr(value + 65))  # Convertendo de volta para caractere
        else:
            encrypted_message.append(message[i])  # Mantém caracteres não-alfabéticos

    return ''.join(encrypted_message)

# Função para decriptografar usando a Cifra de Vigenère
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

# Função principal
def main():
    # Solicitar a mensagem e a chave do usuário
    message = input("Digite a mensagem: ")
    key = input("Digite a chave (palavra): ")

    # Criptografar a mensagem
    encrypted_message = vigenere_encrypt(message, key)
    print(f"Mensagem criptografada: {encrypted_message}")

    # Decriptografar a mensagem
    decrypted_message = vigenere_decrypt(encrypted_message, key)
    print(f"Mensagem decriptografada: {decrypted_message}")

if __name__ == "__main__":
    main()


# Início de célula
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization

# Função para gerar as chaves RSA (pública e privada)
def generate_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key

# Função para criptografar a mensagem usando a chave pública
def encrypt_message(public_key, message):
    encrypted_message = public_key.encrypt(
        message.encode('utf-8'),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return encrypted_message

# Função para decriptografar a mensagem usando a chave privada
def decrypt_message(private_key, encrypted_message):
    decrypted_message = private_key.decrypt(
        encrypted_message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return decrypted_message.decode('utf-8')

# Função para serializar a chave privada e pública (opcional: salvar as chaves em arquivos)
def serialize_keys(private_key, public_key):
    pem_private_key = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )

    pem_public_key = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    return pem_private_key, pem_public_key

# Função principal
def main():
    # Gerar chaves
    private_key, public_key = generate_keys()

    # Exibir as chaves (opcional)
    pem_private_key, pem_public_key = serialize_keys(private_key, public_key)
    print("Chave privada:\n", pem_private_key.decode())
    print("Chave pública:\n", pem_public_key.decode())

    # Solicitar a mensagem do usuário
    message = input("Digite a mensagem que deseja criptografar: ")

    # Criptografar a mensagem
    encrypted_message = encrypt_message(public_key, message)
    print(f"\nMensagem criptografada: {encrypted_message}")

    # Decriptografar a mensagem
    decrypted_message = decrypt_message(private_key, encrypted_message)
    print(f"\nMensagem decriptografada: {decrypted_message}")

# Executar o programa
if __name__ == "__main__":
    main()


# Início de célula
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.exceptions import InvalidSignature

# Função para gerar as chaves RSA (pública e privada)
def generate_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key

# Função para criptografar a mensagem usando a chave pública
def encrypt_message(public_key, message):
    encrypted_message = public_key.encrypt(
        message.encode('utf-8'),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return encrypted_message

# Função para decriptografar a mensagem usando a chave privada
def decrypt_message(private_key, encrypted_message):
    try:
        decrypted_message = private_key.decrypt(
            encrypted_message,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return decrypted_message.decode('utf-8')
    except ValueError as e:
        print("Falha ao decriptografar a mensagem: chave privada incorreta.")
        return None

# Função para serializar a chave privada e pública
def serialize_keys(private_key, public_key):
    pem_private_key = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )

    pem_public_key = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    return pem_private_key, pem_public_key

# Função para modificar um caractere na chave privada
def alter_private_key(pem_private_key):
    altered_key = pem_private_key[:36] + b'g' + pem_private_key[37:]  # substitui o 5º caractere por 'g'
    print("Chave privada alterada:\n", altered_key.decode())
    return altered_key

# Função principal
def main():
    # Gerar as chaves
    private_key, public_key = generate_keys()

    # Serializar as chaves
    pem_private_key, pem_public_key = serialize_keys(private_key, public_key)
    print("Chave privada original:\n", pem_private_key.decode())
    print("Chave pública:\n", pem_public_key.decode())

    # Solicitar a mensagem do usuário
    message = input("Digite a mensagem que deseja criptografar: ")

    # Criptografar a mensagem
    encrypted_message = encrypt_message(public_key, message)
    print(f"\nMensagem criptografada: {encrypted_message}")

    # Decriptografar a mensagem com a chave original
    decrypted_message = decrypt_message(private_key, encrypted_message)
    print(f"\nMensagem decriptografada (chave original): {decrypted_message}")

    # Alterar a chave privada e tentar decriptografar novamente
    altered_pem_private_key = alter_private_key(pem_private_key)
    try:
        altered_private_key = load_pem_private_key(altered_pem_private_key, password=None, backend=default_backend())
        altered_decrypted_message = decrypt_message(altered_private_key, encrypted_message)
        print(f"\nMensagem decriptografada (chave alterada): {altered_decrypted_message}")
    except Exception as e:
        print("Erro ao carregar chave alterada:", e)

# Executar o programa
if __name__ == "__main__":
    main()


# Início de célula
import string

# Definindo o alfabeto e os rotores
ALPHABET = string.ascii_uppercase
ROTOR_I = "EKMFLGDQVZNTOWYHXUSPAIBRCJ"
ROTOR_II = "AJDKSIRUXBLHWTMCQGZNPYFVOE"
ROTOR_III = "BDFHJLCPRTXVZNYEIWGAKMUSQO"
REFLECTOR = "YRUHQSLDPXNGOKMIEBFZCWVJAT"

# Inicialização da configuração inicial dos rotores
ROTORS = [ROTOR_I, ROTOR_II, ROTOR_III]

# Função para criar o plugboard (painel de conectores)
def create_plugboard(pairs):
    plugboard = {c: c for c in ALPHABET}  # Mapeamento inicial sem alteração
    for a, b in pairs:
        plugboard[a] = b
        plugboard[b] = a
    return plugboard

# Função para girar o rotor
def rotate(rotor):
    return rotor[1:] + rotor[0]

# Função de substituição de um único caractere pelo rotor
def substitute(rotor, c, reverse=False):
    if reverse:
        return ALPHABET[rotor.index(c)]
    else:
        return rotor[ALPHABET.index(c)]

# Função principal para encriptar uma mensagem
def enigma(message, plugboard_pairs):
    plugboard = create_plugboard(plugboard_pairs)
    encrypted_message = []

    # Para cada caractere na mensagem
    for char in message.upper():
        if char not in ALPHABET:
            encrypted_message.append(char)
            continue

        # Passo 1: Plugboard
        char = plugboard[char]

        # Passo 2: Passar pelos rotores da direita para a esquerda
        for i, rotor in enumerate(ROTORS):
            char = substitute(rotor, char)
            # Rodar o rotor I a cada letra, o II a cada 26 letras
            if i == 0 or (i == 1 and len(encrypted_message) % 26 == 0):
                ROTORS[i] = rotate(rotor)

        # Passo 3: Refletor
        char = substitute(REFLECTOR, char)

        # Passo 4: Voltar pelos rotores da esquerda para a direita
        for rotor in reversed(ROTORS):
            char = substitute(rotor, char, reverse=True)

        # Passo 5: Plugboard
        char = plugboard[char]

        encrypted_message.append(char)

    return ''.join(encrypted_message)

# Teste da máquina Enigma
message = "UMA MENSAGEM QUE PRECISAMOS PRESERVAR A QUALQUER CUSTO POIS TEM SEGREDOS QUE PRECISAM SER MANTIDOS A QUALQUER CUSTO"
message = "CUSTO MUITO ALTO"
plugboard_pairs = [('A', 'B'), ('C', 'D')]  # Configuração do painel de conectores
encrypted_message = enigma(message, plugboard_pairs)

print("Mensagem Original: ", message)
print("Mensagem Encriptada: ", encrypted_message)


