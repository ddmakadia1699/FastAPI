from fastapi import FastAPI, HTTPException, Depends, Header, Query, Path, status
from pydantic import BaseModel
from typing import Dict, List
from datetime import datetime, timedelta
import uuid
import cachetools

app = FastAPI()

db_users = {}
db_posts = {}

cache = cachetools.TTLCache(maxsize=100, ttl=300)

class UserSignup(BaseModel):
    email: str
    password: str

class UserLogin(BaseModel):
    email: str
    password: str

class PostCreate(BaseModel):
    text: str

class Post(BaseModel):
    post_id: str
    text: str
    created_at: datetime

class ErrorResponse(BaseModel):
    detail: str

def verify_token(token: str = Header(None)) -> str:
    if token is None or token not in db_users:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or missing token")
    return token

@app.post("/signup", response_model=str)
def signup(user_data: UserSignup):
    if user_data.email in db_users:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="User already exists")
    token = str(uuid.uuid4())
    db_users[user_data.email] = token
    return token

@app.post("/login", response_model=str)
def login(user_data: UserLogin):
    if user_data.email not in db_users or db_users[user_data.email] != user_data.password:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")
    token = str(uuid.uuid4())
    db_users[user_data.email] = token
    return token

def get_token(token: str = Depends(verify_token)):
    return token

@app.post("/addPost", response_model=str)
def add_post(post_data: PostCreate, token: str = Depends(get_token)):
    if len(post_data.text) > 1024:
        raise HTTPException(status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                            detail="Payload size exceeds the limit")

    post_id = str(uuid.uuid4())

    db_posts[post_id] = {
        "text": post_data.text,
        "created_at": datetime.now(),
        "user_token": token,
    }

    return post_id

@app.get("/getPosts", response_model=List[Post])
def get_posts(token: str = Depends(get_token)):
    if token in cache:
        return cache[token]

    user_posts = [
        {"post_id": post_id, **post_data}
        for post_id, post_data in db_posts.items()
        if post_data["user_token"] == token
    ]

    cache[token] = user_posts

    return user_posts

@app.delete("/deletePost/{post_id}", response_model=str)
def delete_post(
    post_id: str,
    token: str = Depends(get_token),
):
    if post_id not in db_posts:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Post not found")

    post_data = db_posts[post_id]

    if post_data["user_token"] != token:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Unauthorized to delete this post")

    del db_posts[post_id]

    if token in cache:
        cache.pop(token)

    return "Post deleted successfully"