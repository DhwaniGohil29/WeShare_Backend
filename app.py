from flask import Flask, jsonify, request
from pymongo import MongoClient
from flask_cors import CORS 
import bcrypt
from flask_jwt_extended import JWTManager, create_access_token
from datetime import datetime

app = Flask(__name__)
CORS(app) 
app.config['JWT_SECRET_KEY'] = 'sdfregr_56ergq4t242v#345g'  
jwt = JWTManager(app)


app.config['MONGO_URI'] = 'mongodb+srv://dhwanigohil108:RT8PfkeOkkwt57kF@weshare.2kloapv.mongodb.net/WeShare?retryWrites=true&w=majority&appName=WeShare'

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

    if not name or not email or not phone or not password:
        return jsonify({'message': 'Name, email, phone number, and password are required'}), 400


    if db.users.find_one({'email': email}):
        return jsonify({'message': 'Email already exists'}), 400

    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

    new_user = {
        'name': name,
        'email': email,
        'phone': phone,
        'password': hashed_password.decode('utf-8') 
    }


    result = db.users.insert_one(new_user)

    return jsonify({'message': 'User registered successfully'}), 201

@app.route('/login', methods=['POST'])
def login():
    data = request.json
    email = data.get('email')
    password = data.get('password')

    if not email or not password:
        return jsonify({'message': 'Email and password are required'}), 400

    user = db.users.find_one({'email': email})
    if not user:
        return jsonify({'message': 'Invalid email or password'}), 401

    if not bcrypt.checkpw(password.encode('utf-8'), user['password'].encode('utf-8')):
        return jsonify({'message': 'Invalid email or password'}), 401

    access_token = create_access_token(identity=str(user['_id']))

    return jsonify({'message': 'Login successful', 'access_token': access_token}), 200

@app.route('/preferences', methods=['POST'])
def set_preferences():

    data = request.get_json()
    email = data.get('email')
    branch = data.get('branch')
    role = data.get('role')
    year = data.get('year')
    gender = data.get('gender') 

    user = db.users.find_one({'email': email})
    if not user:
        return jsonify({'message': 'User not found'}), 404

    preferences = {'branch': branch, 'role': role, 'year': year, 'gender': gender}
    db.users.update_one({'email': email}, {'$set': {'preferences': preferences}}) 

    existing_preferences = db.preferences.find_one({'email': email})
    if existing_preferences:
        db.preferences.update_one({'email': email}, {'$set': {'branch': branch, 'role': role, 'year': year, 'gender': gender}})
    else:
        preference = {'email': email, 'branch': branch, 'role': role, 'year': year, 'gender': gender}
        db.preferences.insert_one(preference)

    return jsonify({'message': 'Preferences saved successfully'}), 201

@app.route('/ride-request', methods=['POST'])
def save_ride_request():
    data = request.get_json()
    email = data.get('email')
    from_latitude = data.get('fromlatitude')
    from_longitude = data.get('fromlongitude')
    to_latitude = data.get('tolatitude')
    to_longitude = data.get('tolongitude')
    current_time = datetime.now()
    if not email or not from_latitude or not from_longitude or not to_latitude or not to_longitude:
        return jsonify({'message': 'Incomplete ride request data'}), 400

    user = db.users.find_one({'email': email})
    if not user:
        return jsonify({'message': 'User not found'}), 404

    preferences = db.preferences.find_one({'email': email})

    branch = preferences.get('branch')
    role = preferences.get('role')
    year = preferences.get('year')
    gender = preferences.get('gender')

    existing_ride_request = db.RideRequest.find_one({'email': email})

    if existing_ride_request:
        db.RideRequest.update_one(
            {'email': email},
            {
                '$set': {
                    'fromlatitude': from_latitude,
                    'fromlongitude': from_longitude,
                    'tolatitude': to_latitude,
                    'tolongitude': to_longitude,
                    'branch': branch,
                    'role': role,
                    'year': year,
                    'gender': gender,
                    'request_time': current_time
                }
            }
        )
        return jsonify({'message': 'Ride request updated successfully'}), 200
    else:
        ride_request_data = {
            'email': email,
            'fromlatitude': from_latitude,
            'fromlongitude': from_longitude,
            'tolatitude': to_latitude,
            'tolongitude': to_longitude,
            'branch': branch,
            'role': role,
            'year': year,
            'gender': gender,
            'request_time': current_time
        }
        db.RideRequest.insert_one(ride_request_data)
        return jsonify({'message': 'Ride request saved successfully'}), 201


@app.route('/remove-ride', methods=['POST'])
def remove_ride_request():
    data = request.get_json()
    email = data.get('email')

    if not email:
        return jsonify({'message': 'Email is required to remove ride request'}), 400

    result = db.RideRequest.delete_many({'email': email})

    if result.deleted_count > 0:
        return jsonify({'message': 'Ride request(s) removed successfully'}), 200
    else:
        return jsonify({'message': 'No ride requests found for the provided email'}), 404

if __name__ == '__main__':
    app.run(debug=True, port=5000, host='0.0.0.0')
