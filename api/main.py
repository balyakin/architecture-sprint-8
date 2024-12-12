from fastapi import FastAPI, Depends, HTTPException
from fastapi.security import OAuth2PasswordBearer
from jose import jwt, JWTError
from typing import Dict
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI()


app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Keycloak public key
KEYCLOAK_PUBLIC_KEY = """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0djHTSGmhjvmbmbxi6RF
DxqKIJDdRkSQGhUgy2xO+Lg9ZbKKPKjElFI9w0xxRA9p7sDSVNo0KYfQmKbahues
ry4+LfdKDf+pn4dBBpZMGDFHP7Z6uNnqNRsKx2UEFjD+FHQo6sqimpcb3G49it/I
5Nro7fQqEwaVr1SVCoASanDPYSmgmTlfOZdbz0hDmFIjixnAS8HrgUVP70jznTW8
lPwj0sSYzoAlLCTQabTA+HT5oZ4GCSeUletYEWMd+52BMOm5eyzf8OMBhp203SB7
cKFUcWnKWiTdSuCqgEPoLPNvzr9vWycO0lZOUytdbehSKa8em9FRATyYfGAKpaSb
OQIDAQAB
-----END PUBLIC KEY-----"""
ALGORITHM = "RS256"
ROLE_REQUIRED = "prothetic_user"

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

def decode_jwt(token: str) -> Dict:
    """
    Decode JWT token using the public key and verify the signature.

    Args:
        token (str): JWT token.

    Returns:
        Dict: Decoded token payload.

    Raises:
        HTTPException: If token is invalid.
    """
    try:
        payload = jwt.decode(token, KEYCLOAK_PUBLIC_KEY, algorithms=[ALGORITHM])
        return payload
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

def validate_user_role(token: str = Depends(oauth2_scheme)):
    """
    Validate user role in the decoded JWT token.

    Args:
        token (str): JWT token.

    Raises:
        HTTPException: If the role is not valid.
    """
    payload = decode_jwt(token)
    roles = payload.get("realm_access", {}).get("roles", [])
    if ROLE_REQUIRED not in roles:
        raise HTTPException(status_code=403, detail="Insufficient role")

@app.get("/reports")
def get_report(validate: None = Depends(validate_user_role)):
    """
    Return a sample report for authorized users.

    Returns:
        Dict: Sample report data.
    """
    return {"report": "This is a very important report"}