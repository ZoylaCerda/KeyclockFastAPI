from fastapi import FastAPI, Depends, HTTPException, Security
from fastapi.security import OAuth2AuthorizationCodeBearer
from jose import JWTError
from keycloak import KeycloakAdmin, KeycloakOpenID
import requests
import jwt
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography import x509
import base64
from pydantic import BaseModel


app = FastAPI()

KEYCLOAK_SERVER_URL = "http://localhost:8080/"
REALM_NAME = "2FA"
CLIENT_ID = "dosfa"
CLIENT_SECRET = "t05TquRQyA8YOjjkCh1TV7c3cqcOpbJu"

keycloak_openid = KeycloakOpenID(
    server_url=KEYCLOAK_SERVER_URL,
    client_id=CLIENT_ID,
    realm_name=REALM_NAME,
    client_secret_key=CLIENT_SECRET
)

oauth2_scheme = OAuth2AuthorizationCodeBearer(
    authorizationUrl=f"{KEYCLOAK_SERVER_URL}realms/{REALM_NAME}/protocol/openid-connect/auth",
    tokenUrl=f"{KEYCLOAK_SERVER_URL}realms/{REALM_NAME}/protocol/openid-connect/token"
)

keycloak_admin = KeycloakAdmin( 
    server_url=KEYCLOAK_SERVER_URL, 
    username='marvin', 
    password='123', 
    realm_name="master", 
    client_id='admin-cli', 
    verify=True 
) 

def get_keycloak_public_key():
    """Retrieve the public key from Keycloak's OpenID configuration"""
    openid_config_url = f"{KEYCLOAK_SERVER_URL}realms/{REALM_NAME}/.well-known/openid-configuration"
    response = requests.get(openid_config_url)

    if response.status_code == 200:
        jwks_uri = response.json()["jwks_uri"]
        jwks_response = requests.get(jwks_uri)
        if jwks_response.status_code == 200:
            jwks = jwks_response.json()
            cert_b64 = jwks['keys'][0]['x5c'][0]
            cert_der = base64.b64decode(cert_b64)
            cert = x509.load_der_x509_certificate(cert_der, default_backend())
            public_key = cert.public_key()
            return public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
    raise Exception("Failed to retrieve public key from Keycloak")

# Verificar el token
async def verify_token(token: str = Depends(oauth2_scheme)):
    try:
        public_key = get_keycloak_public_key() 
        payload = jwt.decode(token, public_key, algorithms=['RS256'], audience="account", issuer=f"{KEYCLOAK_SERVER_URL}realms/{REALM_NAME}")
        return payload
        
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")
    except Exception as e:
        raise HTTPException(status_code=401, detail=str(e))

# Ruta protegida
@app.get("/protected-endpoint")
async def protected_route(user_info: dict = Depends(verify_token)):
    return {"message": "Access granted", "user": user_info}



# Registrar usuario
class UserRegister(BaseModel):
    email: str
    password: str

def get_role_id(role_name: str):
    roles = keycloak_admin.get_realm_roles()
    for role in roles:
        if role['name'] == role_name:
            return role
    raise HTTPException(status_code=404, detail=f"Role '{role_name}' not found")
    
@app.post("/register")
async def register_user(user: UserRegister):
    try:
        keycloak_admin.create_user({
            "email": user.email,
            "username": user.email,
            "enabled": True,
            "credentials": [{"type": "password", "value": user.password, "temporary": False}]
        })

        user_id = keycloak_admin.get_user_id(user.email)

        role = get_role_id("user")

        keycloak_admin.assign_realm_roles(user_id=user_id, roles=[role])

        return {"message": "User created and role assigned successfully"}  
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    
# Resetear contraseña
class resetPassword(BaseModel): 
    email: str 
 
@app.post("/reset-password") 
async def reset_password(resetPassword: resetPassword): 
    try: 
        user_id = keycloak_admin.get_user_id(resetPassword.email) 
        if user_id: 
            keycloak_admin.set_user_password(user_id, "nueva_contraseña_temporal", temporary = True) 
            return {"message": f"user password reset  {resetPassword.email}"} 
        else: 
            raise HTTPException(status_code=404, detail="Usuario not found") 
    except Exception as e: 
        raise HTTPException(status_code=500, detail=str(e))
    
# Get all users
@app.get("/users")
async def get_users():
    try:
        users = keycloak_admin.get_users()
        return users
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))