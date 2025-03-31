from fastapi import Depends, HTTPException
from .auth import verify_token

def get_current_user(token: str):
    return verify_token(token)

def check_role(required_role: str):
    def role_checker(user: TokenData = Depends(get_current_user)):
        if user.role != required_role:
            raise HTTPException(status_code=403, detail="Access denied")
        return user
    return role_checker