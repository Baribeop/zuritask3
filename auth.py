# Import necessary libraries
from flask import Flask, request, jsonify
import jwt
import datetime
import secrets

# Initialize Flask app
app = Flask(__name__)

# Secret key for JWT encoding/decoding (keep this secret)
SECRET_KEY = 'b0b208372dc5a496fb631b73f1522974'


# secrets = secrets.token_hex(16)
# print(secrets)

# Temporary storage for user data (should be a database in a real system)
users = {'mary': 'obi', 'joe': 'apple'}

# Endpoint to obtain a token (authentication)
@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data['username']
    password = data['password']

    # Check if the provided username and password match the stored data
    if username in users and users[username] == password:
        # Generate a JWT token with user information
        token = jwt.encode({'username': username, 'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=1)},
                           SECRET_KEY, algorithm='HS256')
        return jsonify({'token': token.decode('UTF-8')})

    return jsonify({'message': 'Authentication failed'}), 401

# Protected GET endpoint
@app.route('/data', methods=['GET'])
def get_data():
    try:
        # Get the token from the request header
        token = request.headers.get('Authorization').split(" ")[1]
        # Decode the token using the secret key
        decoded_token = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
        username = decoded_token['username']

        # For example, you can retrieve user-specific data
        return jsonify({'message': f'Hello, {username}! This is your protected data.'})

    except Exception as e:
        return jsonify({'message': 'Authentication failed'}), 401

# Run the application
if __name__ == '__main__':
    app.run(debug=True)





