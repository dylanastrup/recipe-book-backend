from datetime import datetime
from models import db 

class Recipe(db.Model):
    __tablename__ = 'recipes'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    recipe_name = db.Column(db.String(100), nullable=False)
    recipe_description = db.Column(db.Text)
    cuisine = db.Column(db.String(50))
    prep_time = db.Column(db.Integer)
    cook_time = db.Column(db.Integer)
    servings = db.Column(db.Integer)
    difficulty = db.Column(db.String(20))
    created_at = db.Column(db.DateTime, default=datetime.utcnow) 
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow) 

    # Define relationships
    recipe_ingredient = db.relationship('RecipeIngredient', back_populates='recipe')
    recipe_step = db.relationship('RecipeStep', back_populates='recipe')
    image = db.relationship('Image', back_populates='recipe')
    user = db.relationship('User', back_populates='recipe')

    # Many-to-Many relationship for tags (via recipe_tags)
    tags = db.relationship('Tag', secondary='recipe_tags', back_populates='recipe')