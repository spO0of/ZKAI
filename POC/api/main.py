from fastapi import FastAPI
from pydantic import BaseModel

from tinydb import TinyDB, Query

import base64
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes


db = TinyDB('db.json')

id_challenges_cache_memory = {}

class User(BaseModel):
    name: str
    email: str
    pub: str

class Id(BaseModel):
    id: int

class CryptoChallengeClear(BaseModel):
    crypto_challenge_clear: str

class UserJwt(BaseModel):
    name: str
    email: str


app = FastAPI()


@app.post("/register")
async def input_request(user: User):
    user_id = db.insert(user.dict())
    return {"id": user_id}


@app.post("/login_get_crypto_challenge")
async def input_request(id: Id):
    user_data = db.get(doc_id=id.id)

    public_key_str = user_data['pub']
    public_key_data = public_key_str.encode('utf-8')
    public_key = serialization.load_pem_public_key(public_key_data)

    challenge_clear = b"toto"
    encrypted_challenge = public_key.encrypt(
        challenge_clear,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    encrypted_challenge_b64 = base64.b64encode(encrypted_challenge).decode('utf-8')
    id_challenges_cache_memory[id.id] = challenge_clear
    print(id_challenges_cache_memory)
    return {"challenge": encrypted_challenge_b64}

@app.post("/login_resolve_crypto_challenge_and_send_jwt")
async def input_request(id: Id, crypto_challenge_clear: CryptoChallengeClear, user_jwt : UserJwt):
    if id_challenges_cache_memory[id.id].decode() == crypto_challenge_clear.crypto_challenge_clear:

        user_data = db.get(doc_id=id.id)
        public_key_str = user_data['pub']
        public_key_data = public_key_str.encode('utf-8')
        public_key = serialization.load_pem_public_key(public_key_data)
        pub_nums = public_key.public_numbers()
        e = pub_nums.e
        n = pub_nums.n

        decrypted_jwt = {}

        for key, value in user_jwt:
            value = int.from_bytes(base64.b64decode(value), "big")
            m = pow(value, e, n)
            pt = m.to_bytes((m.bit_length()+7)//8, "big")
            decrypted_jwt[key] = base64.b64encode(pt).decode()

        encrypted_jwt = {}

        for key, value in decrypted_jwt.items():
            encrypted_data = public_key.encrypt(
                value.encode("utf-8"),
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            encrypted_jwt[key] = base64.b64encode(encrypted_data)
        print(encrypted_jwt)
        """
        là le problème c'est que ça donne pas le même résultat parce que le chiffrement est pas déterministe pour des raisons de sécurité.
        je peu pas non plus faire un hahs des données reçu lors du register parce que les données sont jamais reçu en clair avant maintenant...
        là je suis bloqué
        """
    else:
        print("nok")
