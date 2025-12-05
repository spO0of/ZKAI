from base64 import b64decode
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes


challenge_b64 = input("challenge in base64 >")
challenge = b64decode(challenge_b64)

private_key_name = input("private key filename (default id_rsa) >") or "id_rsa"
private_key_data = open(private_key_name, 'rb').read()
private_key = serialization.load_pem_private_key(private_key_data, None)

decrypted = private_key.decrypt(
    challenge,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
).decode('utf-8')

print(decrypted)
