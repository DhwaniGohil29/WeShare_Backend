from flask import Flask, jsonify, request
from pymongo import MongoClient
from bson import ObjectId
import bcrypt
from flask_jwt_extended import JWTManager, create_access_token

app = Flask(__name__)
app.config['JWT_SECRET_KEY'] = 'super-secret'  # Change this to a secure, long, random string in production
jwt = JWTManager(app)

# MongoDB configuration
app.config['MONGO_URI'] = 'mongodb+srv://dhwanigohil108:RT8PfkeOkkwt57kF@weshare.2kloapv.mongodb.net/WeShare?retryWrites=true&w=majority&appName=WeShare'
# Initialize MongoDB client
mongo = MongoClient(app.config['MONGO_URI'])
db = mongo.get_database()

@app.route('/register', methods=['POST'])
def register():
    data = request.json
    name = data.get('name')
    email = data.get('email')
    phone = data.get('phone')
    password = data.get('password')

    # Check if all parameters are provided
    if not name or not email or not phone or not password:
        return jsonify({'error': 'Name, email, phone number, and password are required'}), 400

    # Check if the email is already registered
    if db.users.find_one({'email': email}):
        return jsonify({'error': 'Email already exists'}), 400

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
        return jsonify({'error': 'Email and password are required'}), 400

    # Check if the user exists
    user = db.users.find_one({'email': email})
    if not user:
        return jsonify({'error': 'Invalid email or password'}), 401

    # Verify the password hash
    if not bcrypt.checkpw(password.encode('utf-8'), user['password'].encode('utf-8')):
        return jsonify({'error': 'Invalid email or password'}), 401

    # Create an access token for the user
    access_token = create_access_token(identity=str(user['_id']))

    return jsonify({'message': 'Login successful', 'access_token': access_token}), 200

ride_requests = []

@app.route('/request', methods=['POST'])
def request_ride():
    data = request.json
    start_location = data.get('start_location')
    end_location = data.get('end_location')

    # Check if both start and end locations are provided
    if not start_location or not end_location:
        return jsonify({'error': 'Both start and end locations are required'}), 400

    # Store the ride request in the list (for demonstration purposes)
    ride_request = {
        'start_location': start_location,
        'end_location': end_location
    }
    db.ride_requests.insert_one(ride_request)

    return jsonify({'message': 'Ride request received successfully'}), 201


if __name__ == '__main__':
    app.run(debug=True)

if __name__ == '__main__':
    app.run(debug=True)
