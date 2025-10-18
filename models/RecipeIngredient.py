from datetime import datetime
from models import db 

class RecipeIngredient(db.Model):
    __tablename__ = 'recipe_ingredients'
    id = db.Column(db.Integer, primary_key=True)
    recipe_id = db.Column(db.Integer, db.ForeignKey('recipes.id'), nullable=False)
    ingredient_id = db.Column(db.Integer, db.ForeignKey('ingredients.id'), nullable=False)
    measurement_id = db.Column(db.Integer, db.ForeignKey('measurements.id'))
    ingredient_quantity = db.Column(db.Float, nullable=False)

    # Define relationships
    recipe = db.relationship('Recipe', back_populates='recipe_ingredient')
    ingredient = db.relationship('Ingredient', back_populates='recipe_ingredient')
    measurement = db.relationship('Measurement', back_populates='recipe_ingredient')