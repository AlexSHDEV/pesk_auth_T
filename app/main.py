from fastapi import FastAPI, Depends, HTTPException, Request, Response
from .auth import create_jwt_token, add_to_whitelist, revoke_token, verify_token, ACCESS_TOKEN_EXPIRE_MINUTES
from .dependencies import get_current_user, check_role
from datetime import datetime, timedelta
from .models import TokenData

from fastapi.security import HTTPBearer 

app = FastAPI()
security = HTTPBearer()

COOKIE_NAME = "auth_token"
HTTPS_ONLY = True # For prod only

fake_users = {
    "user1" : {"password" : "pass1", "role" : "role1"},
    "user2" : {"password" : "pass2", "role" : "role2"},
}

@app.post("/login")
async def login(response: Response, request : Request, username: str, password: str):
    user = fake_users.get(username)

    if not user or user["password"] != password: # HAVE INTENTION ON REPLACE THIS CHECK BY ADVANCED CHECK
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    access_token = create_jwt_token(
        {"sub": username, "role" : user["role"]},
        expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    )

    add_to_whitelist(access_token, request.client.host, ACCESS_TOKEN_EXPIRE_MINUTES * 60) # bond with IP

    # Set secure cookie
    response.set_cookie(
        key=COOKIE_NAME,
        value=access_token,
        httponly=True,
        secure=HTTPS_ONLY,
        samesite="strict",
        max_age=ACCESS_TOKEN_EXPIRE_MINUTES*60
    )
    return {"access_token" : access_token, "response" : response}

@app.post("/logout")
async def logout(token: str = Depends(get_current_user)):
    revoke_token(token)
    return {"message" : "Logged out"}

@app.get("/content")
async def get_content(request: Request, user : TokenData = Depends(get_current_user)):

    token = request.cookies.get(COOKIE_NAME)
    if not token:
        raise HTTPException(status_code=401, detail="Not authenticated")
    
    payload = verify_token(token, request)

    common_content = "Share content"
    role_content = {
        "role1" : "Role 1 content",
        "role2" : "Role 2 content"
    }
    return {
        "common" : common_content,
        "role_specific" : role_content.get(user.role, "No access")
    }