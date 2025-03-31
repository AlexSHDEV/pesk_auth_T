from fastapi import FastAPI, Depends, HTTPException
from .auth import create_jwt_token, add_to_whitelist, revoke_token, TokenData
from .dependencies import get_current_user, check_role

app = FastAPI()

# Пример "базы данных" пользователей (для демонстрации)
fake_users = {
    "user1": {"password": "pass1", "role": "role1"},
    "user2": {"password": "pass2", "role": "role2"},
}

@app.post("/login")
async def login(username: str, password: str):
    user = fake_users.get(username)
    if not user or user["password"] != password:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    access_token = create_jwt_token(
        {"sub": username, "role": user["role"]},
        expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    )
    add_to_whitelist(access_token, ACCESS_TOKEN_EXPIRE_MINUTES * 60)
    return {"access_token": access_token}

@app.post("/logout")
async def logout(token: str = Depends(get_current_user)):
    revoke_token(token)
    return {"message": "Logged out"}

@app.get("/content")
async def get_content(user: TokenData = Depends(get_current_user)):
    common_content = "Общий контент"
    role_content = {
        "role1": "Контент для роли 1",
        "role2": "Контент для роли 2"
    }
    return {
        "common": common_content,
        "role_specific": role_content.get(user.role, "Нет доступа")
    }