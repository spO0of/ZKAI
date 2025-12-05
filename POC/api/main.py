from fastapi import FastAPI
from pydantic import BaseModel
from tinydb import TinyDB, Query


db = TinyDB('db.json')


class User(BaseModel):
    name: str
    email: str
    pub: str


app = FastAPI()


@app.post("/register")
async def input_request(user: User):
    user_id = db.insert(user.dict())
    return {"id": user_id}
