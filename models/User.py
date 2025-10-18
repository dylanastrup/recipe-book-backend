from datetime import datetime
from models import db 
from werkzeug.security import generate_password_hash, check_password_hash

class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    first_name = db.Column(db.String(50))    # New field
    last_name = db.Column(db.String(50))     # New field
    role = db.Column(db.String(20), nullable=False, default='user')   # New field
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationships
    recipe = db.relationship('Recipe', back_populates='user', cascade="all, delete-orphan")

    # Hash password before storing
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    # Check if a password matches the stored hash
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
