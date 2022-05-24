import os
import json
import hashlib
import configparser

from werkzeug.local import LocalProxy
from flask import Flask, request, session

from settings.db import get_db
from app.models import authModel

app = Flask(__name__)

db = LocalProxy(get_db)

config = configparser.ConfigParser()
config.read(os.path.abspath(os.path.join(".ini")))

@app.route("/auth", methods=["POST"])
def auth():    
    client_id = request.form.get("client_id")
    client_secret_input = request.form.get("client_secret")

    hash_object = hashlib.sha1(bytes(client_secret_input, 'utf-8'))
    hashed_client_secret = hash_object.hexdigest()

    authentication = authModel.authenticate(client_id, hashed_client_secret)
    if authentication == False:
        return {'success': False}
    else: 
        return json.dumps(authentication)

@app.route("/verify", methods=["POST"])
def verify():
    authorizationHeader = request.headers.get('authorization')    
    token = authorizationHeader.replace("Bearer ","")
    verification = authModel.verify(token)
    return verification

@app.route("/logout", methods=["POST"])
def logout():
    token = request.form.get("token")
    status = authModel.blacklist(token)
    return {'success': status}

@app.route("/client", methods=["POST","DELETE"])
def client():
    if request.method == 'POST':
        client_id = request.form.get("client_id")
        client_secret_input = request.form.get("client_secret")
        mongo_client_id = request.form.get("mongo_client_id")

        is_admin = request.form.get("is_admin", False)        

        hash_object = hashlib.sha1(bytes(client_secret_input, 'utf-8'))
        hashed_client_secret = hash_object.hexdigest()

        createResponse = authModel.create(client_id, hashed_client_secret, is_admin, mongo_client_id)
        return {'success': createResponse}

    elif request.method == 'DELETE':
        # Not implemented yet
        return {'success': False}
    else:        
        return {'success': False}


if __name__ == "__main__":
    app.config['DEBUG'] = True
    app.config['MONGO_URI'] = "mongodb+srv://admin:admin@authentication.24al5.mongodb.net/test"
    app.config['SECRET_KEY'] = "authenticationMicroserviceTest"

    app.run()