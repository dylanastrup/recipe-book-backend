from datetime import datetime
from models import db 

class Tag(db.Model):
    __tablename__ = 'tags'
    id = db.Column(db.Integer, primary_key=True)
    tag_name = db.Column(db.String(50), unique=True, nullable=False)

    # Define relationships
    recipe = db.relationship('Recipe', secondary='recipe_tags', back_populates='tags')