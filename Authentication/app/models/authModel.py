import jwt

from bson import ObjectId
from werkzeug.local import LocalProxy
from settings.db import get_db

from app.auth.authPayload import authPayload
from app.auth.authResponse import authResponse

db = LocalProxy(get_db)

AUTHSECRET = "authenticationMicroserviceTest"


def authenticate(clientId, clientSecret):
    try:
        client = db.clients.find_one(
            {'clientId': clientId, 'clientSecret': clientSecret})

        if client:
            payload = authPayload(
                str(client.get('_id')),
                client.get('clientId'),
                client.get('isAdmin')
            )

            encoded_jwt = jwt.encode(
                payload.__dict__, AUTHSECRET, algorithm='HS256')
            response = authResponse(encoded_jwt, 3000, client.get('isAdmin'), str(client.get('_id')))
            return response.__dict__
        else:
            return False

    except (Exception) as error:
        print(error)
        return False


def verify(token):
    try:
        is_blacklisted = check_blacklist(token)
        if is_blacklisted == True:
            return {"success": False}
        else:
            decoded = jwt.decode(token, AUTHSECRET, algorithms=['HS256'])
            return decoded
    
    except (Exception) as error:
        print(error)
        return {"success": False}


def create(clientId, clientSecret, isAdmin, mongo_client_id):
    try:
        db.clients.insert_one({
            '_id': ObjectId(mongo_client_id),
            'clientId': clientId,
            'clientSecret': clientSecret,
            'isAdmin': isAdmin
        })

        return True

    except (Exception) as error:
        print(error)
        return False


def blacklist(token):
    try:
        db.blacklist.insert_one({"token": token})
        return True

    except (Exception) as error:
        print(error)
        return False


def check_blacklist(token):
    try:
        blocked_token = db.blacklist.find_one({"token": token})

        if blocked_token:
            return True
        else:
            return False

    except (Exception) as error:
        print(error)
        return True
