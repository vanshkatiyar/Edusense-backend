import os
from flask import Flask, jsonify, request
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from flask_bcrypt import Bcrypt
from flask_jwt_extended import create_access_token, jwt_required, get_jwt_identity, JWTManager
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from functools import wraps
from datetime import datetime, time

# --- SETUP, MODELS, DB CREATION, AUTH DECORATORS (All Unchanged) ---
# ... (This entire section of code remains exactly the same as before) ...
# --- 1. SETUP ---
app = Flask(__name__)
CORS(app, resources={r"/api/*": {"origins": "http://localhost:3000"}}, supports_credentials=True)
basedir = os.path.abspath(os.path.dirname(__file__))
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'rooms.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = 'a-super-secret-key-that-you-should-change-later'

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)

limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://",
)

# --- 2. DATABASE MODELS ---
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    phone = db.Column(db.String(20), unique=True, nullable=True)
    password_hash = db.Column(db.String(128), nullable=False)
    role = db.Column(db.String(80), nullable=False, default='student')
    def to_dict(self):
      return { 'id': self.id, 'email': self.email, 'phone': self.phone, 'role': self.role }

class Room(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), unique=True, nullable=False)
    branch = db.Column(db.String(120), nullable=False)
    occupancy = db.Column(db.Integer, default=0)
    lights_on = db.Column(db.Boolean, default=False)
    is_locked = db.Column(db.Boolean, default=True)
    batch_name = db.Column(db.String(100), nullable=True)
    start_time = db.Column(db.DateTime, nullable=True)
    end_time = db.Column(db.DateTime, nullable=True)

    def to_dict(self):
        timing_str = None
        if self.start_time and self.end_time:
            timing_str = f"{self.start_time.strftime('%I:%M %p')} - {self.end_time.strftime('%I:%M %p')}"
        return {
            'id': self.id, 'name': self.name, 'branch': self.branch, 'occupancy': self.occupancy,
            'lights_on': self.lights_on, 'is_locked': self.is_locked,
            'batch_name': self.batch_name, 'timing': timing_str,
        }

# --- 3. DATABASE CREATION ---
@app.cli.command('init-db')
def init_db_command():
    db.drop_all()
    db.create_all()
    hashed_password = bcrypt.generate_password_hash('admin123').decode('utf-8')
    admin_user = User(email='admin@edusense.com', password_hash=hashed_password, role='admin')
    teacher_pw = bcrypt.generate_password_hash('teacher123').decode('utf-8')
    teacher_user = User(email='teacher@example.com', phone='1234567890', password_hash=teacher_pw, role='teacher')
    student_pw = bcrypt.generate_password_hash('student123').decode('utf-8')
    student_user = User(email='student@example.com', password_hash=student_pw, role='student')
    db.session.add_all([admin_user, teacher_user, student_user])
    room1 = Room(name='AIRO101', branch='Artificial Intelligence', occupancy=15, lights_on=True, is_locked=False)
    room2 = Room(name='MECH203', branch='Mechanical', occupancy=0, lights_on=True, is_locked=True)
    db.session.add_all([room1, room2])
    db.session.commit()
    print('Initialized database with sample users and rooms.')

# --- 4. AUTHORIZATION DECORATORS ---
def roles_required(roles=[]):
    def decorator(fn):
        @wraps(fn)
        @jwt_required()
        def wrapper(*args, **kwargs):
            user_identity = get_jwt_identity()
            user = User.query.filter_by(email=user_identity).first()
            if not user or user.role not in roles:
                return jsonify(msg="Insufficient permissions!"), 403
            return fn(*args, **kwargs)
        return wrapper
    return decorator

def admin_required(fn):
    return roles_required(roles=['admin'])(fn)

# --- 5. API ENDPOINTS ---
@app.route('/api/login', methods=['POST'])
@limiter.limit("5 per minute")
def login():
    data = request.get_json()
    if not data: return jsonify({"msg": "Missing JSON"}), 400
    email, password = data.get('email'), data.get('password')
    if not email or not password: return jsonify({"msg": "Missing email or password"}), 400
    user = User.query.filter_by(email=email).first()
    if user and bcrypt.check_password_hash(user.password_hash, password):
        access_token = create_access_token(identity=user.email)
        return jsonify(access_token=access_token, user=user.to_dict())
    return jsonify({"msg": "Invalid credentials"}), 401

# --- CORRECTED: Combined GET and POST for /api/rooms ---
@app.route('/api/rooms', methods=['GET', 'POST'])
@jwt_required()
def handle_rooms():
    if request.method == 'POST':
        # Admin check for POST request
        user_identity = get_jwt_identity()
        user = User.query.filter_by(email=user_identity).first()
        if not user or user.role != 'admin':
            return jsonify(msg="Insufficient permissions!"), 403
        
        # Create room logic
        data = request.get_json()
        name = data.get('name')
        branch = data.get('branch')
        if not name or not branch:
            return jsonify({"msg": "Room name and branch are required."}), 400
        if Room.query.filter_by(name=name).first():
            return jsonify({"msg": f"A room with the name '{name}' already exists."}), 409
        new_room = Room(name=name, branch=branch)
        db.session.add(new_room)
        db.session.commit()
        return jsonify(new_room.to_dict()), 201

    else: # This handles the GET request
        now = datetime.now()
        rooms = Room.query.all()
        for room in rooms:
            if room.end_time and room.end_time < now:
                room.batch_name = None
                room.start_time = None
                room.end_time = None
        db.session.commit()
        return jsonify([r.to_dict() for r in rooms])

# --- CORRECTED: Combined PUT and DELETE for /api/rooms/<id> ---
@app.route('/api/rooms/<int:room_id>', methods=['PUT', 'DELETE'])
@admin_required
def handle_room_by_id(room_id):
    room = db.get_or_404(Room, room_id)
    
    if request.method == 'PUT':
        data = request.get_json()
        name = data.get('name')
        branch = data.get('branch')
        if not name or not branch:
            return jsonify({"msg": "Room name and branch are required."}), 400
        existing_room = Room.query.filter_by(name=name).first()
        if existing_room and existing_room.id != room_id:
            return jsonify({"msg": f"A room with the name '{name}' already exists."}), 409
        room.name = name
        room.branch = branch
        db.session.commit()
        return jsonify(room.to_dict())

    else: # This handles the DELETE request
        db.session.delete(room)
        db.session.commit()
        return jsonify({"msg": f"Room '{room.name}' has been deleted."})


# --- The rest of the endpoints are unchanged ---
@app.route('/api/analytics', methods=['GET'])
@jwt_required()
def get_analytics():
    all_rooms = Room.query.all()
    total_rooms = len(all_rooms)
    occupied_rooms = Room.query.filter(Room.occupancy > 0).count()
    vacant_rooms = total_rooms - occupied_rooms
    wasting_power_rooms = Room.query.filter(Room.occupancy == 0, Room.lights_on == True).count()
    branch_usage_chart = { "labels": ["Artificial Intelligence", "Mechanical"], "data": [85, 60] }
    return jsonify({ "live_stats": { "total_rooms": total_rooms, "occupied_rooms": occupied_rooms, "vacant_rooms": vacant_rooms, "wasting_power_rooms": wasting_power_rooms }, "branch_usage": branch_usage_chart })

@app.route('/api/rooms/<int:room_id>/schedule', methods=['POST'])
@admin_required
def set_schedule(room_id):
    room = db.get_or_404(Room, room_id)
    data = request.get_json()
    if not data or not data.get('batch_name'):
        room.batch_name = None
        room.start_time = None
        room.end_time = None
    else:
        try:
            start_t = time.fromisoformat(data['start_time'])
            end_t = time.fromisoformat(data['end_time'])
            today = datetime.now().date()
            room.start_time = datetime.combine(today, start_t)
            room.end_time = datetime.combine(today, end_t)
            room.batch_name = data['batch_name']
        except (ValueError, KeyError):
            return jsonify({"msg": "Invalid data format. Required: batch_name, start_time (HH:MM), end_time (HH:MM)"}), 400
    db.session.commit()
    return jsonify(room.to_dict())

@app.route('/api/rooms/<int:room_id>/toggle-light', methods=['POST'])
@roles_required(roles=['admin', 'teacher'])
def toggle_light(room_id):
    room = db.get_or_404(Room, room_id)
    room.lights_on = not room.lights_on
    db.session.commit()
    return jsonify(room.to_dict())

@app.route('/api/rooms/<int:room_id>/set-occupancy', methods=['POST'])
@roles_required(roles=['admin', 'teacher'])
def set_occupancy(room_id):
    room = db.get_or_404(Room, room_id)
    data = request.get_json()
    occupancy = data.get('occupancy')
    if occupancy is None or not isinstance(occupancy, int) or occupancy < 0:
        return jsonify({"error": "Invalid occupancy"}), 400
    room.occupancy = occupancy
    db.session.commit()
    return jsonify(room.to_dict())

# ... (User management endpoints remain the same) ...
@app.route('/api/users', methods=['GET'])
@admin_required
def get_users():
    users = User.query.all()
    return jsonify([user.to_dict() for user in users])

@app.route('/api/users', methods=['POST'])
@admin_required
def add_user():
    data = request.get_json()
    email, phone, password, role = data.get('email'), data.get('phone'), data.get('password'), data.get('role', 'student')
    if not email or not password: return jsonify({"msg": "Email and password are required"}), 400
    if User.query.filter_by(email=email).first(): return jsonify({"msg": "Email already exists"}), 409
    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
    new_user = User(email=email, phone=phone, password_hash=hashed_password, role=role)
    db.session.add(new_user)
    db.session.commit()
    return jsonify(new_user.to_dict()), 201

@app.route('/api/users/<int:user_id>/role', methods=['PUT'])
@admin_required
def update_user_role(user_id):
    user_to_update = db.get_or_404(User, user_id)
    data = request.get_json()
    new_role = data.get('role')
    if new_role not in ['admin', 'teacher', 'student']: return jsonify({"msg": "Invalid role"}), 400
    current_user_email = get_jwt_identity()
    current_user = User.query.filter_by(email=current_user_email).first()
    if current_user.id == user_to_update.id and new_role != 'admin': return jsonify({"msg": "Admin cannot demote themselves"}), 403
    user_to_update.role = new_role
    db.session.commit()
    return jsonify(user_to_update.to_dict())

@app.route('/api/users/<int:user_id>', methods=['DELETE'])
@admin_required
def delete_user(user_id):
    user_to_delete = db.get_or_404(User, user_id)
    current_user_email = get_jwt_identity()
    current_user = User.query.filter_by(email=current_user_email).first()
    if current_user.id == user_to_delete.id: return jsonify({"msg": "Cannot delete yourself"}), 403
    db.session.delete(user_to_delete)
    db.session.commit()
    return jsonify({"msg": f"User {user_to_delete.email} deleted"}), 200


if __name__ == '__main__':
    app.run(debug=True)