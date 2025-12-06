from fastapi import FastAPI
from pydantic import BaseModel

from tinydb import TinyDB, Query

import jwt
import base64
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
import hashlib

SECRET_KEY = "lxxxxesqzzzlzodds45454fzeds5azx2sdfdsfxa8s5f9e5"

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
    public_key_str = user.pub
    public_key_data = public_key_str.encode('utf-8')
    public_key = serialization.load_pem_public_key(public_key_data)

    encrypted_name = public_key.encrypt(
        user.name.encode('utf-8'),
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(),label=None)
    )

    encrypted_email = public_key.encrypt(
        user.email.encode('utf-8'),
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(),label=None)
    )

    user_data_to_store = {
        'pub': user.pub,
        'name': base64.b64encode(encrypted_name).decode('utf-8'),
        'email': base64.b64encode(encrypted_email).decode('utf-8'),
        'name_hash': hashlib.sha256(user.name.encode('utf-8')).hexdigest(),
        'email_hash': hashlib.sha256(user.email.encode('utf-8')).hexdigest()
    }

    user_id = db.insert(user_data_to_store)
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

        for key, value in user_jwt:
            if user_data[key+"_hash"] != hashlib.sha256(value.encode('utf-8')).hexdigest():
                return "JWT tampered"

        token = jwt.encode(user_data, SECRET_KEY, algorithm="HS256")
        return token
    else:
        return "Challenge failed :("
