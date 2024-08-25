from flask import Flask, request, jsonify
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime

app = Flask(__name__)

# Configuration
app.config['SECRET_KEY'] = 'your_secret_key'  # Replace with a strong secret key
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['JWT_SECRET_KEY'] = 'your_jwt_secret_key'  # Replace with a strong JWT secret key

# Initialize extensions
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)

# Models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    tasks = db.relationship('Task', backref='user', lazy=True)

class Task(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(150), nullable=False)
    description = db.Column(db.Text, nullable=True)
    status = db.Column(db.String(50), nullable=False, default='Todo')
    priority = db.Column(db.String(50), nullable=False, default='Medium')
    due_date = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

# Create the database
with app.app_context():
    db.create_all()

# Routes for User Registration and Login
@app.route('/api/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    # Hash the password
    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

    # Create a new user
    new_user = User(username=username, password=hashed_password)
    
    # Save the user to the database
    db.session.add(new_user)
    db.session.commit()

    return jsonify({"message": "User registered successfully!"}), 201

@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    # Find the user by username
    user = User.query.filter_by(username=username).first()

    if user and bcrypt.check_password_hash(user.password, password):
        # Generate a JWT token
        access_token = create_access_token(identity=user.id)
        return jsonify({"access_token": access_token}), 200
    else:
        return jsonify({"message": "Invalid credentials"}), 401

# Routes for Task Management
@app.route('/api/tasks', methods=['POST'])
@jwt_required()
def create_task():
    data = request.get_json()
    current_user_id = get_jwt_identity()

    new_task = Task(
        title=data.get('title'),
        description=data.get('description'),
        status=data.get('status', 'Todo'),
        priority=data.get('priority', 'Medium'),
        due_date=datetime.strptime(data.get('due_date'), '%Y-%m-%d') if data.get('due_date') else None,
        user_id=current_user_id
    )

    db.session.add(new_task)
    db.session.commit()

    return jsonify({"message": "Task created successfully!"}), 201

@app.route('/api/tasks', methods=['GET'])
@jwt_required()
def get_tasks():
    current_user_id = get_jwt_identity()
    tasks = Task.query.filter_by(user_id=current_user_id).all()

    tasks_list = [
        {
            "id": task.id,
            "title": task.title,
            "description": task.description,
            "status": task.status,
            "priority": task.priority,
            "due_date": task.due_date.strftime('%Y-%m-%d') if task.due_date else None,
            "created_at": task.created_at.strftime('%Y-%m-%d %H:%M:%S'),
            "updated_at": task.updated_at.strftime('%Y-%m-%d %H:%M:%S')
        }
        for task in tasks
    ]

    return jsonify({"tasks": tasks_list}), 200

@app.route('/api/tasks/<int:task_id>', methods=['PUT'])
@jwt_required()
def update_task(task_id):
    data = request.get_json()
    current_user_id = get_jwt_identity()

    task = Task.query.filter_by(id=task_id, user_id=current_user_id).first()

    if not task:
        return jsonify({"message": "Task not found"}), 404

    task.title = data.get('title', task.title)
    task.description = data.get('description', task.description)
    task.status = data.get('status', task.status)
    task.priority = data.get('priority', task.priority)
    task.due_date = datetime.strptime(data.get('due_date'), '%Y-%m-%d') if data.get('due_date') else task.due_date

    db.session.commit()

    return jsonify({"message": "Task updated successfully!"}), 200

@app.route('/api/tasks/<int:task_id>', methods=['DELETE'])
@jwt_required()
def delete_task(task_id):
    current_user_id = get_jwt_identity()

    task = Task.query.filter_by(id=task_id, user_id=current_user_id).first()

    if not task:
        return jsonify({"message": "Task not found"}), 404

    db.session.delete(task)
    db.session.commit()

    return jsonify({"message": "Task deleted successfully!"}), 200

if __name__ == '__main__':
    app.run(debug=True)
