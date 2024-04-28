from flask import Flask, jsonify, request
from pymongo import MongoClient
from flask_cors import CORS 
import bcrypt
from flask_jwt_extended import JWTManager, create_access_token

app = Flask(__name__)
CORS(app) 
app.config['JWT_SECRET_KEY'] = 'super-secret'  # Change this to a secure, long, random string in production
jwt = JWTManager(app)

# MongoDB configuration
app.config['MONGO_URI'] = 'mongodb+srv://dhwanigohil108:RT8PfkeOkkwt57kF@weshare.2kloapv.mongodb.net/WeShare?retryWrites=true&w=majority&appName=WeShare'
# Initialize MongoDB client
mongo = MongoClient(app.config['MONGO_URI'])
db = mongo.get_database()

@app.route('/', methods=['GET'])
def index():
    return jsonify({'message': 'Welcome to WeShare!'}), 200

@app.route('/register', methods=['POST'])
def register():
    data = request.json
    name = data.get('name')
    email = data.get('email')
    phone = data.get('phone')
    password = data.get('password')

    # Check if all parameters are provided
    if not name or not email or not phone or not password:
        return jsonify({'message': 'Name, email, phone number, and password are required'}), 400

    # Check if the email is already registered
    if db.users.find_one({'email': email}):
        return jsonify({'message': 'Email already exists'}), 400

    # Hash the password
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

    new_user = {
        'name': name,
        'email': email,
        'phone': phone,
        'password': hashed_password.decode('utf-8')  # Convert bytes to string for MongoDB
    }

    # Insert the new user into the database
    result = db.users.insert_one(new_user)

    return jsonify({'message': 'User registered successfully'}), 201

@app.route('/login', methods=['POST'])
def login():
    data = request.json
    email = data.get('email')
    password = data.get('password')

    # Check if the email and password are provided
    if not email or not password:
        return jsonify({'message': 'Email and password are required'}), 400

    # Check if the user exists
    user = db.users.find_one({'email': email})
    if not user:
        return jsonify({'message': 'Invalid email or password'}), 401

    # Verify the password hash
    if not bcrypt.checkpw(password.encode('utf-8'), user['password'].encode('utf-8')):
        return jsonify({'message': 'Invalid email or password'}), 401

    # Create an access token for the user
    access_token = create_access_token(identity=str(user['_id']))

    return jsonify({'message': 'Login successful', 'access_token': access_token}), 200

if __name__ == '__main__':
    app.run(debug=True, port=5000, host='0.0.0.0')
