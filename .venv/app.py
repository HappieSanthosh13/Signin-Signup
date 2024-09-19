from flask import Flask, jsonify, request, session
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from flask_bcrypt import Bcrypt

app = Flask(__name__)

# Database and App Configuration
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:Happie%401305@localhost/signin'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'supersecretkey'  # Necessary for session management

bcrypt = Bcrypt(app)
CORS(app)
db = SQLAlchemy(app)

# User Model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)

    def __repr__(self):
        return f"User('{self.id}', '{self.email}', '{self.password}')"

# Home route
@app.route('/')
def home():
    return jsonify({"message": "Welcome to the home page"})

# Create User route
@app.route('/create-user', methods=['POST'])
def create_user():
    email = request.json.get("email")
    password = request.json.get("password")
    
    # Check if email already exists
    user_exists = User.query.filter_by(email=email).first() is not None
    if user_exists:
        return jsonify({"error": "Email already exists"}), 409

    # Hash the password and create a new user
    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
    new_user = User(email=email, password=hashed_password)
    
    # Add user to database
    db.session.add(new_user)
    db.session.commit()

    return jsonify({'message': 'User created successfully'}), 201

# Sign-in route
@app.route('/login', methods=["POST"])
def login():
    email = request.json.get('email')
    password = request.json.get("password")
    
    # Query user by email
    user = User.query.filter_by(email=email).first()
    if user is None or password is None:
        return jsonify({"message": "Unauthorized access"}), 401

    # Verify password
    if not bcrypt.check_password_hash(user.password, password.encode('utf-8')):
        return jsonify({"message": "Incorrect password"}), 401

    # Store user ID in session
    session["user_id"] = user.id

    return jsonify({
        "id": user.id,
        "email": user.email
    })
@app.route('/delete-user', methods=['DELETE'])
def delete_user():
    data = request.json
    email = data.get('email')  # Get the email from the request
    password = data.get('password')  # Get the password from the request

    # Query for the user by email
    user = User.query.filter_by(email=email).first()

    if user is None:
        return jsonify({"message": "User not found"}), 404

    # Verify the password
    if not bcrypt.check_password_hash(user.password, password):
        return jsonify({"message": "Incorrect password"}), 403  # Forbidden

    # Delete the user
    db.session.delete(user)
    db.session.commit()

    return jsonify({"message": f"User with email {email} deleted successfully"}), 200



if __name__ == '__main__':
    with app.app_context():
        db.create_all()  # Creates all tables based on models
    app.run(debug=True)
