import ast
import base64
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding

KEYS_NAME = input("KEYS_NAME (default : id_rsa) >") or 'id_rsa'
private_key = serialization.load_pem_private_key(open(KEYS_NAME, "rb").read(), None)
priv_nums = private_key.private_numbers()
d = priv_nums.d
n = priv_nums.public_numbers.n

dataset = ast.literal_eval(open(input("DATASET_NAME (default : id_rsa.dataset.json)> ") or "id_rsa.dataset.json").read())

plaintexts = {}
for key, value in dataset.items():
    if key != "pub":
        value_decode = base64.b64decode(value)
        value_decrypt = private_key.decrypt(
            value_decode,
            padding.OAEP(
                mgf=padding.MGF1(hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        plaintexts[key] = value_decrypt

# encrypt with private key
encrypted = {}
for k, pt in plaintexts.items():
    m = int.from_bytes(pt, "big")
    c = pow(m, d, n)
    encrypted[k] = base64.b64encode(
        c.to_bytes((c.bit_length()+7)//8, "big")
    ).decode()

print("Encrypted:", encrypted)
