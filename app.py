from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_cors import CORS
import re
import os

app = Flask(__name__)
CORS(app)

# -----------------------------
# DATABASE CONFIGURATION
# -----------------------------
DATABASE_URL = os.getenv("DATABASE_URL")  # Get Railway env variable

# Fix SSL issue with Railway databases
if DATABASE_URL and DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://")

app.config['SQLALCHEMY_DATABASE_URI'] = DATABASE_URL
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# -----------------------------
# DATABASE MODEL
# -----------------------------
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    fullname = db.Column(db.String(120), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    dob = db.Column(db.String(10), nullable=False)

with app.app_context():
    db.create_all()

# -----------------------------
# EMAIL VALIDATION FUNCTION
# -----------------------------
def is_valid_email(email):
    pattern = r'^[^\s@]+@[^\s@]+\.[^\s@]+$'
    return re.match(pattern, email) is not None

# -----------------------------
# REGISTER API
# -----------------------------
@app.route('/register', methods=['POST'])
def register_user():
    data = request.json

    fullname = data.get("name")
    email = data.get("email")
    password = data.get("password")
    dob = data.get("dob")

    if not fullname or len(fullname.strip()) < 3:
        return jsonify({"status": "error", "message": "Invalid name"}), 400

    if not is_valid_email(email):
        return jsonify({"status": "error", "message": "Invalid email format"}), 400

    existing_user = User.query.filter_by(email=email).first()
    if existing_user:
        return jsonify({"status": "error", "message": "Email already registered"}), 409

    if len(password) < 6:
        return jsonify({"status": "error", "message": "Password must be at least 6 characters"}), 400

    hashed_password = generate_password_hash(password)

    new_user = User(fullname=fullname, email=email, password_hash=hashed_password, dob=dob)
    db.session.add(new_user)
    db.session.commit()

    return jsonify({"status": "success", "message": "Account created successfully!"}), 201

# -----------------------------
# LOGIN API
# -----------------------------
@app.route('/login', methods=['POST'])
def login_user():
    data = request.json
    email = data.get("email")
    password = data.get("password")

    user = User.query.filter_by(email=email).first()

    if not user or not check_password_hash(user.password_hash, password):
        return jsonify({"status": "error", "message": "Invalid email or password"}), 401

    return jsonify({"status": "success", "message": "Login successful!", "user_id": user.id}), 200

# -----------------------------
# DEPLOYMENT SERVER CONFIG
# -----------------------------
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
