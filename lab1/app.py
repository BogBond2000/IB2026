import os

from flask import Flask, request, jsonify
from flask_jwt_extended import (
    JWTManager, create_access_token, get_jwt_identity
)
from markupsafe import escape
from sqlalchemy import select

from config import Config
from models import db, bcrypt, User, Post
from auth import auth_required, admin_required


def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)

    db.init_app(app)
    bcrypt.init_app(app)
    jwt = JWTManager(app)

    with app.app_context():
        db.create_all()
        if not User.query.filter_by(username="admin").first():
            admin = User(username="admin", role="admin")
            admin.set_password("AdminPass123!")
            db.session.add(admin)

            user = User(username="alice", role="user")
            user.set_password("UserPass123!")
            db.session.add(user)
            db.session.commit()

            db.session.add(Post(title="Первый пост",
                                content="Привет, мир!", author_id=admin.id))
            db.session.commit()

    @app.route("/auth/login", methods=["POST"])
    def login():
        data = request.get_json(silent=True) or {}
        username = (data.get("username") or "").strip()
        password = data.get("password") or ""

        if not username or not password:
            return jsonify({"msg": "username and password required"}), 400

        user = db.session.execute(
            select(User).where(User.username == username)
        ).scalar_one_or_none()

        if user is None or not user.check_password(password):
            return jsonify({"msg": "Invalid credentials"}), 401

        token = create_access_token(
            identity=str(user.id),
            additional_claims={"role": user.role, "username": user.username},
        )
        return jsonify(access_token=token, token_type="Bearer"), 200

    @app.route("/api/data", methods=["GET"])
    @auth_required
    def get_data():
        posts = Post.query.all()
        safe = [{
            "id": p.id,
            "title": str(escape(p.title)),
            "content": str(escape(p.content)),
            "author_id": p.author_id,
        } for p in posts]
        return jsonify(data=safe), 200

    @app.route("/api/posts", methods=["POST"])
    @auth_required
    def create_post():
        data = request.get_json(silent=True) or {}
        title = (data.get("title") or "").strip()
        content = (data.get("content") or "").strip()

        if not title or not content:
            return jsonify({"msg": "title and content required"}), 400
        if len(title) > 200:
            return jsonify({"msg": "title too long"}), 400

        safe_title = str(escape(title))
        safe_content = str(escape(content))

        user_id = int(get_jwt_identity())
        post = Post(title=safe_title, content=safe_content, author_id=user_id)
        db.session.add(post)
        db.session.commit()
        return jsonify(post.to_dict()), 201

    @app.route("/api/users", methods=["GET"])
    @admin_required
    def list_users():
        users = User.query.all()
        return jsonify(users=[u.to_dict() for u in users]), 200

    @jwt.unauthorized_loader
    def missing_token(reason):
        return jsonify({"msg": "Authorization token required"}), 401

    @jwt.invalid_token_loader
    def invalid_token(reason):
        return jsonify({"msg": "Invalid token"}), 401

    @jwt.expired_token_loader
    def expired_token(jwt_header, jwt_payload):
        return jsonify({"msg": "Token has expired"}), 401

    return app


if __name__ == "__main__":
    app = create_app()
    app.run(host="127.0.0.1", port=int(os.environ.get("PORT", "5000")))