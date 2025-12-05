from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes


def generate_dataset(DATASET_DATA, KEYS_NAME):
    public_key_data = open(KEYS_NAME+'.pub', 'rb').read()
    public_key = serialization.load_pem_public_key(public_key_data)

    for args in DATASET_DATA:
        encrypted = public_key.encrypt(
            DATASET_DATA[args].encode(),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        DATASET_DATA[args] = encrypted

    DATASET_DATA['pub'] = public_key_data.decode()

    open(KEYS_NAME+'.dataset.json', "w").write(str(DATASET_DATA))
