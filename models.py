from datetime import datetime
from app import db
from flask_dance.consumer.storage.sqla import OAuthConsumerMixin
from flask_login import UserMixin
from sqlalchemy import UniqueConstraint

# Mandatory tables for Replit Auth
class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id = db.Column(db.String, primary_key=True)
    email = db.Column(db.String, unique=True, nullable=True)
    first_name = db.Column(db.String, nullable=True)
    last_name = db.Column(db.String, nullable=True)
    profile_image_url = db.Column(db.String, nullable=True)
    is_admin = db.Column(db.Boolean, default=False)

    created_at = db.Column(db.DateTime, default=datetime.now)
    updated_at = db.Column(db.DateTime, default=datetime.now, onupdate=datetime.now)

class OAuth(OAuthConsumerMixin, db.Model):
    user_id = db.Column(db.String, db.ForeignKey(User.id))
    browser_session_key = db.Column(db.String, nullable=False)
    user = db.relationship(User)

    __table_args__ = (UniqueConstraint(
        'user_id',
        'browser_session_key',
        'provider',
        name='uq_user_browser_session_key_provider',
    ),)

# Monitoring-specific models
class IPAttempt(db.Model):
    __tablename__ = 'ip_attempts'
    id = db.Column(db.Integer, primary_key=True)
    ip_address = db.Column(db.String(45), nullable=False)
    attempt_count = db.Column(db.Integer, default=0)
    first_attempt = db.Column(db.DateTime, default=datetime.now)
    last_attempt = db.Column(db.DateTime, default=datetime.now)
    is_blocked = db.Column(db.Boolean, default=False)

class AccessLog(db.Model):
    __tablename__ = 'access_logs'
    id = db.Column(db.Integer, primary_key=True)
    ip_address = db.Column(db.String(45), nullable=False)
    user_id = db.Column(db.String, db.ForeignKey(User.id), nullable=True)
    request_path = db.Column(db.String(255))
    user_agent = db.Column(db.Text)
    timestamp = db.Column(db.DateTime, default=datetime.now)
    status = db.Column(db.String(20))  # allowed, blocked, error
