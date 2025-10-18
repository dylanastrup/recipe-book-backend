from datetime import datetime
from models import db 

class RecipeStep(db.Model):
    __tablename__ = 'recipe_steps'
    id = db.Column(db.Integer, primary_key=True)
    recipe_id = db.Column(db.Integer, db.ForeignKey('recipes.id'), nullable=False)
    step_number = db.Column(db.Integer, nullable=False)
    step_description = db.Column(db.Text, nullable=False)

    # Define relationships
    recipe = db.relationship('Recipe', back_populates='recipe_step')