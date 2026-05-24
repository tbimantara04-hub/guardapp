from flask_sqlalchemy import SQLAlchemy
from datetime import datetime

db = SQLAlchemy()

class StudentEntry(db.Model):
    __tablename__ = 'student_entries'
    id = db.Column(db.Integer, primary_key=True)
    npm = db.Column(db.String(20), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    keterangan = db.Column(db.String(255))
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    guard_id = db.Column(db.String(50), nullable=False)

    def to_dict(self):
        return {
            'id': self.id,
            'npm': self.npm,
            'name': self.name,
            'keterangan': self.keterangan,
            'timestamp': self.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
            'guard_id': self.guard_id
        }

class AuditLog(db.Model):
    __tablename__ = 'audit_logs'
    id = db.Column(db.Integer, primary_key=True)
    guard_id = db.Column(db.String(50), nullable=False)
    action = db.Column(db.String(255), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {
            'id': self.id,
            'guard_id': self.guard_id,
            'action': self.action,
            'timestamp': self.timestamp.strftime('%Y-%m-%d %H:%M:%S')
        }

from werkzeug.security import generate_password_hash, check_password_hash

class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
