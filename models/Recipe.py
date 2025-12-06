from datetime import datetime
from models import db
from .RecipeStep import RecipeStep

class Recipe(db.Model):
    __tablename__ = 'recipes'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    
    # --- NEW: Link to the parent recipe (The one being "Spiced up") ---
    original_recipe_id = db.Column(db.Integer, db.ForeignKey('recipes.id'), nullable=True)
    
    recipe_name = db.Column(db.String(100), nullable=False)
    recipe_description = db.Column(db.Text)
    cuisine = db.Column(db.String(50))
    prep_time = db.Column(db.Integer)
    cook_time = db.Column(db.Integer)
    servings = db.Column(db.Integer)
    difficulty = db.Column(db.String(20))
    created_at = db.Column(db.DateTime, default=datetime.utcnow) 
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow) 

    # Relationships
    recipe_ingredient = db.relationship('RecipeIngredient', back_populates='recipe', cascade="all, delete-orphan")
    # Added order_by to ensure steps are always in order
    recipe_step = db.relationship('RecipeStep', back_populates='recipe', order_by='RecipeStep.step_number', cascade="all, delete-orphan")
    image = db.relationship('Image', back_populates='recipe', cascade="all, delete-orphan")
    user = db.relationship('User', back_populates='recipe')
    
    tags = db.relationship('Tag', secondary='recipe_tags', back_populates='recipe')
    ratings = db.relationship('Rating', back_populates='recipe', cascade="all, delete-orphan")

    # --- NEW: Relationship to access the parent/child info ---
    # This lets you say recipe.original_recipe to see where it came from
    original_recipe = db.relationship('Recipe', remote_side=[id], backref='remixes')