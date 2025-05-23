from datetime import datetime, timedelta
from typing import Optional
import jwt
from fastapi import HTTPException, status, Request
from pydantic import BaseModel
import redis
import redis.client
from .models import TokenData

# Well, we all have a good understanding that these constants must be hidden in real project.
SECRET_KEY = "12345"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

redis_client = redis.Redis(host="redis", port=6379, db=0)

class TokenData(BaseModel):
    username : str
    role : str

def create_jwt_token(data:  dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp" : expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def add_to_whitelist(token : str, ip : str, expires : int):
    redis_client.setex(f"whitelist:{token}", expires, ip)

def revoke_token(token: str):
    if redis_client.delete(f"whitelist{token}"):
        redis_client.setex(f"blacklist:{token}", 3600, "revoked")

def verify_token(token: str, request : Request):
    if redis_client.exists(f"blacklist:{token}"):
        raise HTTPException(status_code=403, detail="Token revoked")
    
    if not redis_client.exists(f"whitelist:{token}"):
        raise HTTPException(status_code=403, detail="Token invalid")
    
    stored_ip = redis_client.get(f"whitelist:{token}")
    current_ip = request.client.host
    if stored_ip and stored_ip.decode() != current_ip:
        revoke_token(token)
        raise HTTPException(status_code=403, detail="IP mismatch - token revoked")

    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return TokenData(username=payload["sub"], role=payload["role"])
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except Exception:
        raise HTTPException(status_code=403, detail="Invalid token")