from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
from backend.models import db, StudentEntry, AuditLog, User
from backend.crypto_utils import HybridCrypto
import os
import json
import glob
import pandas as pd
import base64

app = Flask(__name__, static_folder='../static')
CORS(app)

# Configuration
basedir = os.path.abspath(os.path.dirname(__file__))

if os.environ.get('VERCEL'):
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:////tmp/guard.db'
else:
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, '../db/guard.db')

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db.init_app(app)

# Initialize HybridCrypto
crypto = HybridCrypto(os.path.join(basedir, 'keys/server_private.pem'))

STUDENT_DB = {}

def load_students():
    global STUDENT_DB
    print("Loading student databases...")
    db_dir = os.path.abspath(os.path.join(basedir, '../../satpam_app/db_folder'))
    for file_path in glob.glob(os.path.join(db_dir, '*.xlsx')):
        filename = os.path.basename(file_path)
        try:
            if filename == 'namakelasnpm_pt23.xlsx':
                df = pd.read_excel(file_path)
                for _, row in df.iterrows():
                    STUDENT_DB[str(row['NPM'])] = str(row['Nama'])
            elif filename == 'namakelasnpm_pt24.xlsx':
                df = pd.read_excel(file_path, header=1)
                for _, row in df.iterrows():
                    STUDENT_DB[str(row['NPM'])] = str(row['Nama'])
            elif filename in ['nama_kelas_npm.xlsx', 'pt_22.xlsx']:
                df = pd.read_excel(file_path, header=1)
                for _, row in df.iterrows():
                    if pd.notna(row.get('NPM')) and pd.notna(row.get('Nama')):
                        STUDENT_DB[str(row['NPM']).split('.')[0]] = str(row['Nama'])
            else:
                # Fallback check
                df = pd.read_excel(file_path)
                if 'NPM' in df.columns and 'Nama' in df.columns:
                     for _, row in df.iterrows():
                        if pd.notna(row.get('NPM')) and pd.notna(row.get('Nama')):
                            STUDENT_DB[str(row['NPM']).split('.')[0]] = str(row['Nama'])
        except Exception as e:
            print(f"Failed to load {filename}: {e}")
    print(f"Loaded {len(STUDENT_DB)} students into memory.")

load_students()

try:
    with app.app_context():
        db.create_all()
        # Create default user if none exists
        if not User.query.first():
            print("Creating default admin user...")
            default_user = User(username='admin')
            default_user.set_password('password123')
            db.session.add(default_user)
            db.session.commit()
except Exception as e:
    print(f"Database initialization error: {e}")

@app.route('/')
def index():
    return send_from_directory(app.static_folder, 'index.html')

@app.route('/login')
def login_page():
    return send_from_directory(app.static_folder, 'login.html')

@app.route('/login.js')
def login_js():
    return send_from_directory(app.static_folder, 'login.js')

@app.route('/dashboard')
def dashboard():
    return send_from_directory(app.static_folder, 'dashboard.html')

@app.route('/style.css')
def style():
    return send_from_directory(app.static_folder, 'style.css')

@app.route('/app.js')
def js_app():
    return send_from_directory(app.static_folder, 'app.js')

@app.route('/api/get_public_key', methods=['GET'])
def get_public_key():
    with open(os.path.join(basedir, 'keys/server_public.pem'), 'r') as f:
        return f.read()

@app.route('/api/get_students', methods=['GET'])
def get_students():
    # Return alphabetical list of students
    sorted_students = sorted([{"npm": k, "name": v} for k, v in STUDENT_DB.items()], key=lambda x: x['name'])
    return jsonify(sorted_students)

@app.route('/api/submit_entry', methods=['POST'])
def submit_entry():
    data = request.json
    encrypted_payload = data.get('payload')
    encrypted_key = data.get('key')
    guard_id = data.get('guard_id')

    try:
        # Hybrid Decryption
        decrypted_json = crypto.hybrid_decrypt(encrypted_payload, encrypted_key)
        entry_data = json.loads(decrypted_json)

        if isinstance(entry_data, list):
            for student in entry_data:
                if 'npm' not in student or 'name' not in student:
                    continue
                new_entry = StudentEntry(
                    npm=student['npm'],
                    name=student['name'],
                    keterangan=student.get('keterangan', ''),
                    guard_id=guard_id
                )
                db.session.add(new_entry)
                audit = AuditLog(
                    guard_id=guard_id,
                    action=f"Input massal keluar untuk Mahasiswa NPM: {student['npm']}"
                )
                db.session.add(audit)
        else:
            if 'npm' not in entry_data or 'name' not in entry_data:
                raise ValueError("Missing required fields in encrypted payload")
            new_entry = StudentEntry(
                npm=entry_data['npm'],
                name=entry_data['name'],
                keterangan=entry_data.get('keterangan', ''),
                guard_id=guard_id
            )
            db.session.add(new_entry)
            audit = AuditLog(
                guard_id=guard_id,
                action=f"Input data keluar untuk Mahasiswa NPM: {entry_data['npm']}"
            )
            db.session.add(audit)
        
        db.session.commit()

        return jsonify({"status": "success", "message": "Data saved successfully"}), 200
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/api/login', methods=['POST'])
def login():
    data = request.json
    encrypted_credentials = data.get('credentials')

    if not crypto:
        return jsonify({"status": "error", "message": "Server Crypto not initialized."}), 500

    if not encrypted_credentials:
        return jsonify({"status": "error", "message": "No credentials provided."}), 400

    try:
        # Decrypt payload using RSA
        decrypted_json = crypto.decrypt_rsa(encrypted_credentials)
        credentials = json.loads(decrypted_json)

        username = credentials.get('username')
        password = credentials.get('password')

        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            # For simplicity, returning a mock token (in a real app, use JWT)
            mock_token = base64.b64encode(username.encode()).decode()
            return jsonify({"status": "success", "token": mock_token, "username": username}), 200
        else:
            return jsonify({"status": "error", "message": "Invalid username or password"}), 401

    except Exception as e:
        # Don't expose internal errors, just say invalid username/password or server error
        return jsonify({"status": "error", "message": "Username atau password salah."}), 400

@app.route('/api/get_entries', methods=['GET'])
def get_entries():
    entries = StudentEntry.query.order_by(StudentEntry.timestamp.desc()).all()
    return jsonify([e.to_dict() for e in entries])

@app.route('/api/get_audit_logs', methods=['GET'])
def get_audit_logs():
    logs = AuditLog.query.order_by(AuditLog.timestamp.desc()).all()
    return jsonify([l.to_dict() for l in logs])

@app.route('/api/delete_entry/<int:entry_id>', methods=['DELETE'])
def delete_entry(entry_id):
    entry = StudentEntry.query.get(entry_id)
    if entry:
        audit = AuditLog(
            guard_id=entry.guard_id,
            action=f"Mahasiswa NPM {entry.npm} ({entry.name}) telah kembali ke kampus"
        )
        db.session.add(audit)
        db.session.delete(entry)
        db.session.commit()
        return jsonify({"status": "success"}), 200
    return jsonify({"status": "error", "message": "Not found"}), 404

@app.route('/api/delete_all_entries', methods=['DELETE'])
def delete_all_entries():
    try:
        audit = AuditLog(
            guard_id="SYSTEM",
            action="Semua mahasiswa log keluar ditandai telah kembali (log dikosongkan)"
        )
        db.session.add(audit)
        db.session.query(StudentEntry).delete()
        db.session.commit()
        return jsonify({"status": "success"}), 200
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True, port=5000)
