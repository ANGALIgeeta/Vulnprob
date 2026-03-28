from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
import threading
import uuid
import os

from scanner import Scanner

app = Flask(__name__, static_folder="../frontend/static")
CORS(app)

# In-memory job store
jobs = {}

@app.route("/")
def index():
    return send_from_directory("../frontend", "index.html")

@app.route("/api/scan", methods=["POST"])
def start_scan():
    data = request.get_json()
    url = data.get("url", "").strip()
    if not url:
        return jsonify({"error": "URL is required"}), 400
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    job_id = str(uuid.uuid4())
    jobs[job_id] = {"status": "running", "progress": 0, "results": [], "url": url}

    def run():
        scanner = Scanner(url, jobs[job_id])
        scanner.run_all()

    t = threading.Thread(target=run, daemon=True)
    t.start()

    return jsonify({"job_id": job_id})

@app.route("/api/status/<job_id>")
def get_status(job_id):
    job = jobs.get(job_id)
    if not job:
        return jsonify({"error": "Job not found"}), 404
    return jsonify(job)

if __name__ == "__main__":
    app.run(debug=True, port=5000)
