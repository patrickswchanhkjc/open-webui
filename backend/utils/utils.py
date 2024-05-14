from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi import HTTPException, status, Depends

from apps.web.models.users import Users

from pydantic import BaseModel
from typing import Union, Optional
from constants import ERROR_MESSAGES
from passlib.context import CryptContext
from datetime import datetime, timedelta
import requests
import jwt
import uuid
import logging
import config
from ldap3 import Server, Connection, ALL, SUBTREE
import os

logging.getLogger("passlib").setLevel(logging.ERROR)


SESSION_SECRET = config.WEBUI_SECRET_KEY
ALGORITHM = "HS256"

##############
# Auth Utils
##############

bearer_security = HTTPBearer()
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def verify_ldap_user(usermail, password):
    server_url = config.LDAP_SERVER_ADDRESS
    server_port =  config.LDAP_SERVER_PORT
    bind_dn = config.BIND_DN
    bind_pw = config.BIND_PW
    user_search_base = config.USER_SERACH_BASE
    user_search_filter = config.USER_SEARCH_FILTER
    group_search_filter = config.GROUP_SEARCH_FILTER
    account_attribute = config.ACCOUNT_ATTRIBUTE

    print(f'verify_ldap_user: connecting to ldap://{server_url}:{server_port}')

    server = Server(f'ldap://{server_url}:{server_port}',  get_info=ALL)
    connection = Connection(server, bind_dn, bind_pw, auto_bind=True)

    try:

        if connection.bind():
            search_filter = "(&" + user_search_filter + "" +  group_search_filter + ")"
            search_filter = search_filter.replace('%s', usermail)
            # check if an user exists
            print(f'searching user with user_search_base={user_search_base}, search_filter={search_filter}, username_attribute= {account_attribute}')
            connection.search(user_search_base,  search_filter, SUBTREE, attributes=[account_attribute])
            # Check if the search was successful
            domain_user = connection.entries[0][account_attribute].value 

            connection = Connection(server, domain_user, password, auto_bind=True)
            if connection.bind():
                return True
            else:
                return False
        else:
            return False

    except Exception as e:
        print('Invalid credentials.')
    finally:
        # Always unbind the connection
        connection.unbind()

def get_group_by_ldap_user(usermail):
    
    is_admin = False
    is_user = False
    
    server_url = config.LDAP_SERVER_ADDRESS
    server_port =  config.LDAP_SERVER_PORT
    bind_dn = config.BIND_DN
    bind_pw = config.BIND_PW
    user_search_base = config.USER_SERACH_BASE
    user_search_filter = config.USER_SEARCH_FILTER
    group_search_filter = config.GROUP_SEARCH_FILTER
    admin_search_filter = config.ADMIN_SEARCH_FILTER
    username_attribute = config.USERNAME_ATTRIBUTE
    account_attribute = config.ACCOUNT_ATTRIBUTE

    print(f'get_group_by_ldap_user: connecting to ldap://{server_url}:{server_port}')
    print(f'using the following values')
    print(f'bind_dn={bind_dn}')
    print(f'bind_pw={bind_pw}')
    print(f'user_search_base={user_search_base}')
    print(f'user_search_filter={user_search_filter}')
    print(f'group_search_filter={group_search_filter}')
    print(f'username_attribute={username_attribute}')
    print(f'account_attribute={account_attribute}')

    # Create a temporary connection to try binding with the user's credentials
    server = Server(f'ldap://{server_url}:{server_port}',  get_info=ALL)
    connection = Connection(server, bind_dn, bind_pw, auto_bind=True)
    

    try:
        # Try to bind with the user's credentials
        if connection.bind():
            search_filter = "(&" + user_search_filter + "" +  group_search_filter + ")"
            search_filter = search_filter.replace('%s', usermail)
            # check if an user exists
            print(f'searching user with user_search_base={user_search_base}, search_filter={search_filter}, username_attribute= {username_attribute}')
            connection.search(user_search_base,  search_filter, SUBTREE, attributes=[username_attribute])
            if connection.entries:
                is_user = True
            search_filter = "(&" + user_search_filter + "" +  admin_search_filter + ")"
            search_filter = search_filter.replace('%s', usermail)
            print(f'searching admin with user_search_base={user_search_base}, search_filter={search_filter}, username_attribute= {username_attribute}')
            connection.search(user_search_base,  search_filter, SUBTREE, attributes=[username_attribute])
            if connection.entries:
                is_admin = True
        else:
            print('Password is incorrect.')
            
    except Exception as e:
        print('Invalid credentials.')
    finally:
        # Always unbind the connection
        connection.unbind()

    if is_admin:
        return "admin"
    elif is_user:
        return "user"
    else:
        return None

def get_ldap_user(usermail):

    server_url = config.LDAP_SERVER_ADDRESS
    server_port =  config.LDAP_SERVER_PORT
    bind_dn = config.BIND_DN
    bind_pw = config.BIND_PW
    user_search_base = config.USER_SERACH_BASE
    user_search_filter = config.USER_SEARCH_FILTER
    group_search_filter = config.GROUP_SEARCH_FILTER
    username_attribute = config.USERNAME_ATTRIBUTE
    account_attribute = config.ACCOUNT_ATTRIBUTE
    print(f'get_ldap_user: connecting to ldap://{server_url}:{server_port}')
    print(f'using the following values')
    print(f'bind_dn={bind_dn}')
    print(f'bind_pw={bind_pw}')
    print(f'user_search_base={user_search_base}')
    print(f'user_search_filter={user_search_filter}')
    print(f'group_search_filter={group_search_filter}')
    print(f'username_attribute={username_attribute}')
    print(f'account_attribute={account_attribute}')

    # Create a temporary connection to try binding with the user's credentials
    server = Server(f'ldap://{server_url}:{server_port}',  get_info=ALL)
    connection = Connection(server, bind_dn, bind_pw, auto_bind=True)
    

    try:
        # Try to bind with the user's credentials
        if connection.bind():
            search_filter = "(&" + user_search_filter + "" +  group_search_filter + ")"
            search_filter = search_filter.replace('%s', usermail)
            # check if an user exists
            print(f'searching with user_search_base={user_search_base}, search_filter={search_filter}, username_attribute= {username_attribute}')
            connection.search(user_search_base,  search_filter, SUBTREE, attributes=[username_attribute])

            if connection.entries:
                print(f'usermail {usermail} is authenticated')
                for entry in connection.entries:
                    username = entry[username_attribute].value
                    print(f'username {username}')
                    return username
            else: 
                print("No entries found")
                return None
        else:
            print('Password is incorrect.')
            
    except  Exception as e:
        print('Invalid credentials.')
    finally:
        # Always unbind the connection
        connection.unbind()

def verify_password(plain_password, hashed_password):
    return (
        pwd_context.verify(plain_password, hashed_password) if hashed_password else None
    )


def get_password_hash(password):
    return pwd_context.hash(password)


def create_token(data: dict, expires_delta: Union[timedelta, None] = None) -> str:
    payload = data.copy()

    if expires_delta:
        expire = datetime.utcnow() + expires_delta
        payload.update({"exp": expire})

    encoded_jwt = jwt.encode(payload, SESSION_SECRET, algorithm=ALGORITHM)
    return encoded_jwt


def decode_token(token: str) -> Optional[dict]:
    try:
        decoded = jwt.decode(token, SESSION_SECRET, algorithms=[ALGORITHM])
        return decoded
    except Exception as e:
        return None


def extract_token_from_auth_header(auth_header: str):
    return auth_header[len("Bearer ") :]


def create_api_key():
    key = str(uuid.uuid4()).replace("-", "")
    return f"sk-{key}"


def get_http_authorization_cred(auth_header: str):
    try:
        scheme, credentials = auth_header.split(" ")
        return HTTPAuthorizationCredentials(scheme=scheme, credentials=credentials)
    except:
        raise ValueError(ERROR_MESSAGES.INVALID_TOKEN)


def get_current_user(
    auth_token: HTTPAuthorizationCredentials = Depends(bearer_security),
):
    # auth by api key
    if auth_token.credentials.startswith("sk-"):
        return get_current_user_by_api_key(auth_token.credentials)
    # auth by jwt token
    data = decode_token(auth_token.credentials)
    if data != None and "id" in data:
        user = Users.get_user_by_id(data["id"])
        if user is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=ERROR_MESSAGES.INVALID_TOKEN,
            )
        else:
            Users.update_user_last_active_by_id(user.id)
        return user
    else:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=ERROR_MESSAGES.UNAUTHORIZED,
        )


def get_current_user_by_api_key(api_key: str):
    user = Users.get_user_by_api_key(api_key)

    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=ERROR_MESSAGES.INVALID_TOKEN,
        )
    else:
        Users.update_user_last_active_by_id(user.id)

    return user


def get_verified_user(user=Depends(get_current_user)):
    if user.role not in {"user", "admin"}:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=ERROR_MESSAGES.ACCESS_PROHIBITED,
        )
    return user


def get_admin_user(user=Depends(get_current_user)):
    if user.role != "admin":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=ERROR_MESSAGES.ACCESS_PROHIBITED,
        )
    return user
