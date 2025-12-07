from models import db

class SiteSetting(db.Model):
    __tablename__ = 'site_settings'
    id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.String(50), unique=True, nullable=False) # e.g., "banner"
    value = db.Column(db.Text, nullable=True) # Stores JSON data (message, color, active)