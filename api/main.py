import os
import logging
from typing import Dict

import requests
from fastapi import FastAPI, Depends, HTTPException
from fastapi.security import OAuth2PasswordBearer
from fastapi.middleware.cors import CORSMiddleware
from jose import jwt, JWTError
from jose.utils import base64url_decode
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

# Configure logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# FastAPI app instance
app = FastAPI()

# CORS Middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Keycloak configuration
KEYCLOAK_URL = os.getenv("KEYCLOAK_URL", "http://localhost:8080")
REALM_NAME = os.getenv("KEYCLOAK_REALM", "reports-realm")
ALGORITHM = "RS256"
ROLE_REQUIRED = "prothetic_user"
CLIENT_ID = os.getenv("CLIENT_ID", "reports-api")

KEYCLOAK_PUBLIC_KEYS = {}

# OAuth2 scheme
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")


def jwks_to_pem(jwks_key: Dict) -> str:
    """
    Convert JWKS format key to PEM format.

    Args:
        jwks_key (Dict): JWKS key in dictionary format.

    Returns:
        str: PEM-formatted public key.
    """
    try:
        logger.debug(f"Converting JWKS key: {jwks_key}")
        modulus = int.from_bytes(base64url_decode(jwks_key['n'].encode()), 'big')
        exponent = int.from_bytes(base64url_decode(jwks_key['e'].encode()), 'big')

        public_key = rsa.RSAPublicNumbers(exponent, modulus).public_key()
        pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        logger.debug("Successfully converted JWKS to PEM.")
        return pem.decode('utf-8')
    except Exception as e:
        logger.error(f"Error converting JWKS to PEM: {e}")
        raise RuntimeError(f"Error converting JWKS to PEM: {e}")


def fetch_keycloak_public_keys() -> Dict[str, str]:
    """
    Fetch the public keys from the Keycloak JWKS endpoint.

    Returns:
        Dict[str, str]: A dictionary of key IDs (kid) and their corresponding PEM-formatted public keys.
    """
    try:
        jwks_url = f"{KEYCLOAK_URL}/realms/{REALM_NAME}/protocol/openid-connect/certs"
        logger.info(f"Fetching JWKS from {jwks_url}")
        response = requests.get(jwks_url, timeout=10)
        response.raise_for_status()
        jwks = response.json()
        logger.debug(f"JWKS response: {jwks}")

        keys = {}
        for key in jwks.get("keys", []):
            if key.get("use") == "sig":  # Only use signing keys
                keys[key["kid"]] = jwks_to_pem(key)
        if not keys:
            raise RuntimeError("No signing keys ('use': 'sig') found in JWKS endpoint")
        logger.info(f"Fetched {len(keys)} signing keys.")
        return keys
    except Exception as e:
        logger.error(f"Failed to fetch public keys from Keycloak: {e}")
        raise RuntimeError(f"Failed to fetch public keys from Keycloak: {e}")


@app.on_event("startup")
def load_keycloak_public_keys():
    """
    Load the public keys from Keycloak during application startup.
    """
    global KEYCLOAK_PUBLIC_KEYS
    try:
        KEYCLOAK_PUBLIC_KEYS = fetch_keycloak_public_keys()
        logger.info("Public keys loaded successfully.")
    except RuntimeError as e:
        logger.error(f"Error during Keycloak public key loading: {e}")
        raise


def decode_jwt(token: str) -> Dict:
    """
    Decode and validate a JWT token using the Keycloak public key.

    Args:
        token (str): JWT token.

    Returns:
        Dict: Decoded token payload.

    Raises:
        HTTPException: If the token is invalid.
    """
    try:
        logger.debug(f"Decoding token: {token}")
        header = jwt.get_unverified_header(token)
        kid = header.get("kid")
        logger.info(f"Token header: {header}")

        if not kid or kid not in KEYCLOAK_PUBLIC_KEYS:
            logger.error(f"Key ID {kid} not found in loaded keys.")
            raise HTTPException(status_code=401, detail="Invalid token: Unknown Key ID")

        public_key = KEYCLOAK_PUBLIC_KEYS[kid]
        logger.info(f"Using public key with kid: {kid}")

        payload = jwt.decode(
            token,
            public_key,
            algorithms=[ALGORITHM],
            audience=CLIENT_ID
        )
        logger.info(f"Token decoded successfully: {payload}")
        return payload
    except JWTError as e:
        logger.error(f"JWT decoding error: {e}")
        raise HTTPException(status_code=401, detail=f"Invalid token: {e}")


def validate_user_role(token: str = Depends(oauth2_scheme)):
    """
    Validate the user role in the decoded JWT token.

    Args:
        token (str): JWT token.

    Raises:
        HTTPException: If the user lacks the required role.
    """
    logger.info("Validating user role.")
    payload = decode_jwt(token)
    roles = payload.get("realm_access", {}).get("roles", [])
    logger.debug(f"User roles: {roles}")
    if not roles or ROLE_REQUIRED not in roles:
        logger.warning("User does not have the required role.")
        raise HTTPException(status_code=403, detail="Insufficient role")


@app.get("/reports")
def get_report(validate: None = Depends(validate_user_role)):
    """
    Return a sample report for authorized users.

    Returns:
        Dict: Sample report data.
    """
    logger.info("Authorized user requesting report.")
    return {"report": "This is a very important report"}
