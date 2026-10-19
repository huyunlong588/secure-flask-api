from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
import bcrypt
import bleach

app = Flask(__name__)

# Config
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///app.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["JWT_SECRET_KEY"] = "super-secret-key-change-in-production-12345"
db = SQLAlchemy(app)
jwt = JWTManager(app)

# Database Model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)

# Create tables & seed test user
with app.app_context():
    db.create_all()
    # Only create test user if not exists
    if not User.query.filter_by(username="testuser").first():
        raw_pw = b"TestPass123!"
        hashed = bcrypt.hashpw(raw_pw, bcrypt.gensalt())
        new_user = User(username="testuser", password_hash=hashed.decode("utf-8"))
        db.session.add(new_user)
        db.session.commit()

# 1. POST /auth/login
@app.route("/auth/login", methods=["POST"])
def login():
    data = request.get_json()
    if not data or "username" not in data or "password" not in data:
        return jsonify({"msg": "Missing username or password"}), 400

    user = User.query.filter_by(username=data["username"]).first()
    if not user:
        return jsonify({"msg": "Bad username or password"}), 401

    if bcrypt.checkpw(data["password"].encode("utf-8"), user.password_hash.encode("utf-8")):
        access_token = create_access_token(identity=user.username)
        return jsonify(access_token=access_token), 200
    return jsonify({"msg": "Bad username or password"}), 401

# 2. GET /api/data (protected, return user list)
@app.route("/api/data", methods=["GET"])
@jwt_required()
def get_data():
    users = User.query.all()
    result = []
    for u in users:
        # XSS protection: sanitize user output
        safe_name = bleach.clean(u.username)
        result.append({"id": u.id, "username": safe_name})
    return jsonify(users=result), 200

# 3. Custom endpoint: POST /api/post (protected, create simple post)
@app.route("/api/post", methods=["POST"])
@jwt_required()
def create_post():
    current_user = get_jwt_identity()
    req_data = request.get_json()
    if not req_data or "content" not in req_data:
        return jsonify({"msg": "Missing post content"}), 400
    # XSS sanitize user input
    clean_content = bleach.clean(req_data["content"])
    return jsonify({
        "msg": "Post saved",
        "author": current_user,
        "content": clean_content
    }), 201

if __name__ == "__main__":
    app.run(debug=False)
