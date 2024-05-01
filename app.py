from flask import Flask, jsonify, request
from pymongo import MongoClient
from flask_cors import CORS 
import bcrypt
from flask_jwt_extended import JWTManager, create_access_token
from datetime import datetime
from geopy.distance import great_circle
from flask import jsonify
import uuid
from flask_socketio import SocketIO, emit

app = Flask(__name__)
CORS(app) 
socketio = SocketIO(app)
app.config['JWT_SECRET_KEY'] = 'sdfregr_56ergq4t242v#345g'  
jwt = JWTManager(app)


app.config['MONGO_URI'] = 'mongodb+srv://dhwanigohil108:RT8PfkeOkkwt57kF@weshare.2kloapv.mongodb.net/WeShare?retryWrites=true&w=majority&appName=WeShare'

mongo = MongoClient(app.config['MONGO_URI'])
db = mongo.get_database()



def find_closest_users(user_location, data):
    kmeans = data['kmeans']
    user_cluster = kmeans.predict([user_location])[0]

    # Filter users belonging to the same cluster
    cluster_users = data['users'][data['users']['Cluster'] == user_cluster].copy()

    # Calculate distances from user location to all other users in the same cluster
    cluster_users['Distance'] = cluster_users.apply(
        lambda row: great_circle((row['Latitude'], row['Longitude']), user_location).kilometers,
        axis=1
    )

    # Sort users by distance and return the top 7 nearest users
    closest_users = cluster_users.sort_values(by='Distance').iloc[:7]
    return closest_users[['Name', 'Latitude', 'Longitude']]



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


# @app.route('/remove-ride', methods=['POST'])
# def remove_ride_request():
#     data = request.get_json()
#     email = data.get('email')

#     if not email:
#         return jsonify({'message': 'Email is required to remove ride request'}), 400

#     result = db.RideRequest.delete_many({'email': email})

#     if result.deleted_count > 0:
#         return jsonify({'message': 'Ride request(s) removed successfully'}), 200
#     else:
#         return jsonify({'message': 'No ride requests found for the provided email'}), 404
def remove_ride_request():
    data = request.get_json()
    emails = data.get('emails')

    if not emails:
        return jsonify({'message': 'Emails are required to remove ride requests'}), 400

    result = db.RideRequest.delete_many({'email': {'$in': emails}})

    if result.deleted_count > 0:
        return jsonify({'message': 'Ride request(s) removed successfully'}), 200
    else:
        return jsonify({'message': 'No ride requests found for the provided emails'}), 404
    


def group_by_preferences(users):
    groups = []
    for user in users:
        preferences = (user['branch'], user['role'], user['year'], user['gender'])
        groups.append({'email': user['email'], 'preferences': preferences})
    return groups
def generate_unique_id():
    return str(uuid.uuid4())

@app.route('/find-matching-rides', methods=['POST'])
def find_matching_rides():
    data = request.get_json()
    email = data.get('email')
    from_latitude = data.get('from_latitude')
    from_longitude = data.get('from_longitude')
    to_latitude = data.get('to_latitude')
    to_longitude = data.get('to_longitude')

    if not email or not from_latitude or not from_longitude or not to_latitude or not to_longitude:
        return jsonify({'message': 'Incomplete data in request body'}), 400

    # Query the RideRequest collection to find ride requests with the same destination coordinates
    matching_rides = db.RideRequest.find({
        'tolatitude': to_latitude,
        'tolongitude': to_longitude
    })

    # Prepare list to store distances and user data
    users = []

    # Calculate distances and filter out the user's own ride request
    for ride in matching_rides:
        if ride['email'] != email:
            ride_location = (ride['fromlatitude'], ride['fromlongitude'])
            user_location = (from_latitude, from_longitude)
            distance = great_circle(user_location, ride_location).kilometers
            users.append({
                'email': ride['email'],
                'distance': distance,
                'branch': ride['branch'],
                'role': ride['role'],
                'year': ride['year'],
                'gender': ride['gender']
            })

    # Sort the rides by distance and get the top 6 closest matches
    closest_matches = sorted(users, key=lambda x: x['distance'])[:6]

    # Group the closest matches based on similar preferences
    grouped_matches = group_by_preferences(closest_matches)

    # Form groups of 2 users each
    groups = []
    for i in range(0, len(grouped_matches), 2):
        group = grouped_matches[i:i+2]
        groups.append({'group': len(groups) + 1,'group_id': generate_unique_id(), 'users': group})

    # Prepare response data
    return jsonify({'groups': groups}), 200


@app.route('/ride-requests/locations', methods=['GET'])
def get_ride_request_locations():
    ride_requests = db.RideRequest.find({}, {'_id': 0, 'fromlatitude': 1, 'fromlongitude': 1})

    locations = [{'fromlatitude': ride_request['fromlatitude'], 'fromlongitude': ride_request['fromlongitude']} 
                 for ride_request in ride_requests]

    return jsonify(locations)


@app.route('/create-group', methods=['POST'])
def create_group():
    data = request.get_json()
    group_id = data.get('group_id')
    users = data.get('users')

    if not group_id or not users:
        return jsonify({'message': 'Incomplete data in request body'}), 400

    group_data = {
        'group_id': group_id,
        'users': users
    }
    db.groupSelected.insert_one(group_data)

    return jsonify({'message': 'Group created successfully', 'group_id': group_id}), 200



@app.route('/update-status', methods=['POST'])
def update_status():
    data = request.get_json()
    group_id = data.get('group_id')
    updated_users = data.get('users')

    if not group_id or not updated_users:
        return jsonify({'message': 'Incomplete data in request body'}), 400

    db.groupSelected.update_one({'group_id': group_id}, {'$set': {'users': updated_users}})

    return jsonify({'message': 'Status updated successfully for group {}'.format(group_id)}), 200


@app.route('/delete-group', methods=['DELETE'])
def delete_group():
    group_id = request.args.get('group_id')

    if not group_id:
        return jsonify({'message': 'Group ID is required in the query parameters'}), 400

    group_data = db.groupSelected.find_one({'group_id': group_id})
    if not group_data:
        return jsonify({'message': 'Group not found'}), 404

    db.groupSelected.delete_one({'group_id': group_id})

    return jsonify({'message': 'Group deleted successfully', 'group_id': group_id}), 200


@app.route('/group-history', methods=['GET'])
def group_history():
    group_id = request.args.get('group_id')

    if not group_id:
        return jsonify({'message': 'Group ID is required in the query parameters'}), 400


    group_data = db.groupSelected.find_one({'group_id': group_id})

    if not group_data:
        return jsonify({'message': 'Group not found'}), 404
    
    all_approved = all(user.get('status') == 'approved' for user in group_data.get('users'))
    
    overall_status = 'approved' if all_approved else 'pending'
    if overall_status == 'approved':
        db.groupHistory.insert_one(group_data)

    # socketio.emit('group_history_updated', {'group_id': group_id, 'overall_status': overall_status})
    return jsonify({'group_id': group_id, 'overall_status': overall_status}), 200


# @socketio.on('connect')
# def handle_connect():
#     print('Client connected')
#     emit('connection_response', {'data': 'Connected to the server'})


# @socketio.on('disconnect')
# def handle_disconnect():
#     print('Client disconnected')


@app.route('/history', methods=['POST'])
def get_history():
    data = request.get_json()
    email = data.get('email')

    if not email:
        return jsonify({'message': 'Email is required in the request body'}), 400

    # Query groupHistory collection to find groups where the user's email is present
    user_groups = db.groupHistory.find({'users.email': email})

    # Prepare the response containing group details
    groups = []
    for group in user_groups:
        groups.append({
            '_id': str(group['_id']),
            'group_id': group['group_id'],
            'users': group['users']
        })

    return jsonify({'user_groups': groups}), 200

@app.route('/add-favorite-group', methods=['POST'])
def add_favorite_group():
    data = request.get_json()
    user = data.get('user')
    member1 = data.get('member1')
    member2 = data.get('member2')

    if not user or not member1 or not member2:
        return jsonify({'message': 'Incomplete data in request body'}), 400

    favorite_group = {
        'user': user,
        'members': [member1, member2]
    }

    db.favoriteGroups.insert_one(favorite_group)

    return jsonify({'message': 'Favorite group added successfully'}), 201

@app.route('/delete-favorite-group', methods=['POST'])
def delete_favorite_group():
    data = request.get_json()
    user = data.get('user')
    member1 = data.get('member1')
    member2 = data.get('member2')

    if not user or not member1 or not member2:
        return jsonify({'message': 'Incomplete data in request body'}), 400

    result = db.favoriteGroups.delete_one({'user': user, 'members': [member1, member2]})

    if result.deleted_count > 0:
        return jsonify({'message': 'Favorite group deleted successfully'}), 200
    else:
        return jsonify({'message': 'Favorite group not found'}), 404


@app.route('/get-favorite-groups', methods=['POST'])
def get_favorite_groups():
    data = request.get_json()
    user = data.get('user')

    if not user:
        return jsonify({'message': 'User is required in the request body'}), 400

    favorite_groups = list(db.favoriteGroups.find({'user': user}, {'_id': 0}))

    return jsonify({'favorite_groups': favorite_groups}), 200


@app.route('/get-user-details', methods=['POST'])
def get_user_details():
    data = request.get_json()
    email = data.get('email')

    if not email:
        return jsonify({'message': 'Email is required in the request body'}), 400

    user_details = db.users.find_one({'email': email}, {'_id': 0, 'name': 1, 'email': 1, 'phone': 1})

    if not user_details:
        return jsonify({'message': 'User not found'}), 404

    preferences = db.preferences.find_one({'email': email}, {'_id': 0, 'branch': 1, 'role': 1, 'year': 1, 'gender': 1})

    user_details.update(preferences)

    return jsonify({'user_details': user_details}), 200

if __name__ == '__main__':
    app.run(debug=True, port=5000, host='0.0.0.0')
