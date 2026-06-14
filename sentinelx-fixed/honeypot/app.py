import os
from flask import Flask, jsonify
from flask_cors import CORS
from .endpoints import honeypot_bp, logger



def create_honeypot_app():
    app = Flask(__name__)
    CORS(app, resources={r"/api/*": {"origins": "*"}})

    app.register_blueprint(honeypot_bp)


    @app.route("/api/health", methods=["GET"])
    def health():
        return jsonify({"status": "honeypot_active", "version": "1.0.0"})

    return app
