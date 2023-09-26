from flask import Flask, request, jsonify
from flask_bcrypt import Bcrypt
import datetime
import jwt
# import secrets

app = Flask(__name__)
app.config['SECRET_KEY'] = ''
bcrypt = Bcrypt(app)

# Store user data securely (hashed passwords)
users = {
    'john': bcrypt.generate_password_hash('gun').decode('utf-8'),
    'grace': bcrypt.generate_password_hash('pig').decode('utf-8')
}

def create_access_token(username):
    payload = {
        'user': username,
        'exp': datetime.datetime.now() + datetime.timedelta(hours=1)
    }
    token = jwt.encode(payload, app.config['SECRET_KEY'], algorithm='HS256')
    # print(token)
    return token

@app.route('/')
def home():
    return 'Hello'

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    if username in users and bcrypt.check_password_hash(users[username], password):
        access_token = create_access_token(username)
        return jsonify(message="Login succeeded!", access_token=access_token), 200
    else:
        return jsonify(message='Authentication failed, invalid login credential'), 401

@app.route('/user', methods=['GET'])
def get_user():
    token = request.headers.get('Authorization').split(" ")[1]
    if not token:
        return jsonify(message='Token is missing'), 401
    try:
        payload = jwt.decode(token, app.config['SECRET_KEY'], algorithm='HS256')
        print(payload)
        user = payload['user']
        return jsonify(message='Authorization is successful', user=user), 200
    except jwt.ExpiredSignatureError:
        return jsonify(message='Expired token'), 401
    except jwt.DecodeError:
        return jsonify(message='Invalid token'), 401

@app.route('/create', methods=['POST'])
def create_data():
    token = request.headers.get('Authorization')
    if not token:
        return jsonify(message='Token is missing'), 401
    try:
        payload = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        username = request.json.get('username')
        password = request.json.get('password')

        if username in users:
            return jsonify(message='Username already exists'), 400

        # Hash the password before storing it
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        users[username] = hashed_password
        return jsonify(message='Data created successfully'), 201
    except jwt.ExpiredSignatureError:
        return jsonify(message='Token has expired'), 401
    except jwt.DecodeError:
        return jsonify(message='Invalid token'), 401

if __name__ == '__main__':
    app.run(debug=True, port=8000)
