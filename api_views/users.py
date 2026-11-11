import re
import threading
import time
import jsonschema
import jwt

from config import db, vuln_app
from api_views.json_schemas import *
from flask import jsonify, Response, request, json
from models.user_model import User
from app import vuln


def error_message_helper(msg):
    if isinstance(msg, dict):
        return '{ "status": "fail", "message": "' + msg['error'] + '"}'
    else:
        return '{ "status": "fail", "message": "' + msg + '"}'


def get_all_users():
    return_value = jsonify({'users': User.get_all_users()})
    return return_value


def debug():
    # never expose passwords or admin flags: only the public user fields are returned
    return_value = jsonify({'users': User.get_all_users()})
    return return_value

def me():
    resp = token_validator(request.headers.get('Authorization'))
    if "error" in resp:
        return Response(error_message_helper(resp), 401, mimetype="application/json")
    else:
        user = User.query.filter_by(username=resp['sub']).first()
        responseObject = {
            'status': 'success',
            'data': {
                'username': user.username,
                'email': user.email,
                'admin': user.admin
            }
        }
        return Response(json.dumps(responseObject), 200, mimetype="application/json")
        

def get_by_username(username):
    if User.get_user(username):
        return Response(str(User.get_user(username)), 200, mimetype="application/json")
    else:
        return Response(error_message_helper("User not found"), 404, mimetype="application/json")


def register_user():
    request_data = request.get_json()
    # check if user already exists
    user = User.query.filter_by(username=request_data.get('username')).first()
    if not user:
        try:
            # validate the data are in the correct form
            jsonschema.validate(request_data, register_user_schema)
            # a client-supplied 'admin' flag is ignored: self-registered users are never admins
            user = User(username=request_data['username'], password=request_data['password'],
                        email=request_data['email'])
            db.session.add(user)
            db.session.commit()

            responseObject = {
                'status': 'success',
                'message': 'Successfully registered. Login to receive an auth token.'
            }

            return Response(json.dumps(responseObject), 200, mimetype="application/json")
        except jsonschema.exceptions.ValidationError as exc:
            return Response(error_message_helper(exc.message), 400, mimetype="application/json")
    else:
        return Response(error_message_helper("User already exists. Please Log in."), 200, mimetype="application/json")


# Brute-force protection: failed login attempts are counted per username in a sliding window.
# Once the limit is exceeded further FAILED attempts get HTTP 429. A correct password is never
# blocked, and the throttled response carries the same generic message so it cannot be used
# to enumerate users.
LOGIN_FAILURE_LIMIT = 5
LOGIN_FAILURE_WINDOW_SECONDS = 60
GENERIC_LOGIN_ERROR = "Username or Password Incorrect!"
_failed_logins = {}
_failed_logins_lock = threading.Lock()


def _register_failed_login(username):
    """Records a failed attempt and returns True when the caller is over the limit."""
    now = time.time()
    key = str(username).lower()
    with _failed_logins_lock:
        recent = [t for t in _failed_logins.get(key, []) if now - t < LOGIN_FAILURE_WINDOW_SECONDS]
        recent.append(now)
        _failed_logins[key] = recent
        return len(recent) > LOGIN_FAILURE_LIMIT


def login_user():
    request_data = request.get_json()

    try:
        # validate the data are in the correct form
        jsonschema.validate(request_data, login_user_schema)
        # fetching user data if the user exists
        user = User.query.filter_by(username=request_data.get('username')).first()
        if user and request_data.get('password') == user.password:
            auth_token = user.encode_auth_token(user.username)
            responseObject = {
                'status': 'success',
                'message': 'Successfully logged in.',
                'auth_token': auth_token
            }
            return Response(json.dumps(responseObject), 200, mimetype="application/json")
        # unknown user and wrong password get the exact same generic answer (no enumeration)
        if _register_failed_login(request_data.get('username')):
            return Response(error_message_helper(GENERIC_LOGIN_ERROR), 429, mimetype="application/json")
        return Response(error_message_helper(GENERIC_LOGIN_ERROR), 200, mimetype="application/json")
    except jsonschema.exceptions.ValidationError as exc:
        return Response(error_message_helper(exc.message), 400, mimetype="application/json")
    except:
        return Response(error_message_helper("An error occurred!"), 200, mimetype="application/json")


def token_validator(auth_header):
    if auth_header:
        try:
            auth_token = auth_header.split(" ")[1]
        except:
            auth_token = ""
    else:
        auth_token = ""
    if auth_token:
        # if auth_token is valid we get back the username of the user
        return User.decode_auth_token(auth_token)
    else:
        return {'error': 'Invalid token. Please log in again.'}


def update_email(username):
    request_data = request.get_json()
    try:
        jsonschema.validate(request_data, update_email_schema)
    except:
        return Response(error_message_helper("Please provide a proper JSON body."), 400, mimetype="application/json")
    resp = token_validator(request.headers.get('Authorization'))
    if "error" in resp:
        return Response(error_message_helper(resp), 401, mimetype="application/json")
    else:
        user = User.query.filter_by(username=resp['sub']).first()
        email = str(request_data.get('email'))
        # linear-time email check: bounded length and no nested quantifiers (no catastrophic backtracking)
        if len(email) <= 254 and re.fullmatch(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,24}", email):
            user.email = email
            db.session.commit()
            responseObject = {
                'status': 'success',
                'data': {
                    'username': user.username,
                    'email': user.email
                }
            }
            return Response(json.dumps(responseObject), 204, mimetype="application/json")
        else:
            return Response(error_message_helper("Please Provide a valid email address."), 400,
                            mimetype="application/json")


def update_password(username):
    request_data = request.get_json()
    resp = token_validator(request.headers.get('Authorization'))
    if "error" in resp:
        return Response(error_message_helper(resp), 401, mimetype="application/json")
    else:
        if request_data.get('password'):
            # a user may only change their OWN password; a request for anyone else is refused
            # (and nothing is changed, not even the caller's own password)
            if username != resp['sub']:
                return Response(error_message_helper("You can only change your own password."), 403,
                                mimetype="application/json")
            user = User.query.filter_by(username=resp['sub']).first()
            if not user:
                return Response(error_message_helper("User Not Found"), 400, mimetype="application/json")
            user.password = request_data.get('password')
            db.session.commit()
            responseObject = {
                'status': 'success',
                'Password': 'Updated.'
            }
            return Response(json.dumps(responseObject), 204, mimetype="application/json")
        else:
            return Response(error_message_helper("Malformed Data"), 400, mimetype="application/json")


def delete_user(username):
    resp = token_validator(request.headers.get('Authorization'))
    if "error" in resp:
        return Response(error_message_helper(resp), 401, mimetype="application/json")
    else:
        user = User.query.filter_by(username=resp['sub']).first()
        if user.admin:
            if bool(User.delete_user(username)):
                responseObject = {
                    'status': 'success',
                    'message': 'User deleted.'
                }
                return Response(json.dumps(responseObject), 200, mimetype="application/json")
            else:
                return Response(error_message_helper("User not found!"), 404, mimetype="application/json")
        else:
            return Response(error_message_helper("Only Admins may delete users!"), 401, mimetype="application/json")
