#!/usr/bin/env python3
""" Flask App """
from flask import Flask, jsonify, request, abort, redirect
from auth import Auth

AUTH = Auth()

app = Flask(__name__)


@app.route("/", methods=["GET"])
def index():
    """GET /"""
    return jsonify({"message": "Bienvenue"})


@app.route("/users", methods=["POST"])
def users():
    """POST /users
    the end-point to register a user.
    """
    email = request.form.get("email")
    password = request.form.get("password")

    try:
        AUTH.register_user(email, password)
        return jsonify({"email": email, "message": "user created"})
    except ValueError:
        return jsonify({"message": "email already registered"}), 404


@app.route("/sessions", methods=["POST"])
def login():
    """POST /sessions
    generate a session_id for a user when he logs in
    """
    email = request.form.get("email")
    password = request.form.get("password")

    if not AUTH.valid_login(email, password):
        abort(401)
    session_id = AUTH.create_session(email)

    out = jsonify(email=email, message="logged in")
    out.set_cookie("session_id", session_id)
    return out


@app.route("/sessions", methods=["DELETE"])
def logout():
    """DELETE /sessions"""
    session_id = request.cookies.get("session_id")
    try:
        user = AUTH.get_user_from_session_id(session_id)
        if user is None:
            abort(403)
        AUTH.destroy_session(user.id)
    except Exception:
        abort(403)
    return redirect("/")


@app.route("/profile", methods=["GET"])
def profile():
    """GET /profile"""
    session_id = request.cookies.get("session_id")
    try:
        user = AUTH.get_user_from_session_id(session_id)
        if user is None:
            abort(403)
    except Exception:
        abort(403)
    return jsonify({"email": user.email}), 200


@app.route("/reset_password", methods=["POST"])
def get_reset_password_token():
    """POST /reset_password
    generates a token
    """
    email = request.form.get("email")
    try:
        reset_token = AUTH.get_reset_password_token(email)
        return jsonify({"email": email, "reset_token": reset_token}), 200
    except Exception:
        abort(403)


@app.route("/reset_password", methods=["PUT"])
def update_password():
    """PUT /reset_password
    Update password end-point
    """
    email = request.form.get("email")
    reset_token = request.form.get("reset_token")
    new_password = request.form.get("new_password")
    try:
        AUTH.update_password(reset_token, new_password)
        return jsonify({"email": email, "message": "Password updated"}), 200
    except Exception:
        abort(403)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port="5000")
