from datetime import datetime
from models import db 

class Ingredient(db.Model):
    __tablename__ = 'ingredients'
    id = db.Column(db.Integer, primary_key=True)
    ingredient_name = db.Column(db.String(100), unique=True, nullable=False)

    #Define relationships
    recipe_ingredient = db.relationship('RecipeIngredient', back_populates='ingredient')