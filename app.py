from flask import Flask, jsonify, request
from flask_jwt_extended import (
    JWTManager, create_access_token,
    jwt_required, get_jwt_identity
)
from flask_sqlalchemy import SQLAlchemy
import bcrypt
from markupsafe import escape

app = Flask(__name__)

# Config
app.config["JWT_SECRET_KEY"] = "super-secret-key-change-in-production"  # nosec B105 - demo project, real deployment must use env var
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///app.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

jwt = JWTManager(app)
db = SQLAlchemy(app)

# Database Model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)

    def to_dict(self):
        # escape user data to prevent XSS when returned to client
        return {
            "id": self.id,
            "username": escape(self.username)
        }

# Create DB and test user
with app.app_context():
    db.create_all()
    # create test user: admin / Password123
    if not User.query.filter_by(username="admin").first():
        hashed_pw = bcrypt.hashpw(b"Password123", bcrypt.gensalt())
        new_user = User(username="admin", password_hash=hashed_pw.decode("utf-8"))
        db.session.add(new_user)
        db.session.commit()

# 1. POST /auth/login
@app.route("/auth/login", methods=["POST"])
def login():
    data = request.get_json()
    username = data.get("username")
    password = data.get("password")

    user = User.query.filter_by(username=username).first()
    if not user or not bcrypt.checkpw(password.encode("utf-8"), user.password_hash.encode("utf-8")):
        return jsonify({"msg": "Invalid username or password"}), 401

    access_token = create_access_token(identity=str(user.id))
    return jsonify(access_token=access_token), 200

# 2. GET /api/data (protected)
@app.route("/api/data", methods=["GET"])
@jwt_required()
def get_data():
    current_user_id = get_jwt_identity()
    users = User.query.all()
    user_list = [u.to_dict() for u in users]
    return jsonify({
        "msg": "Protected user data",
        "data": user_list,
        "request_user_id": escape(str(current_user_id))
    }), 200

# 3. Custom endpoint: GET /api/user/<user_id> (protected)
@app.route("/api/user/<int:user_id>", methods=["GET"])
@jwt_required()
def get_single_user(user_id):
    # SQLAlchemy ORM query, no string concat, prevent SQLi
    user = User.query.get(user_id)
    if not user:
        return jsonify({"msg": "User not found"}), 404
    return jsonify(user.to_dict()), 200

if __name__ == "__main__":
    app.run(debug=False)
