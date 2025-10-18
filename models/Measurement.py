from datetime import datetime
from models import db 

class Measurement(db.Model):
    __tablename__ = 'measurements'
    id = db.Column(db.Integer, primary_key=True)
    measurement_name = db.Column(db.String(50), unique=True, nullable=False)

    #Define relationships
    recipe_ingredient = db.relationship('RecipeIngredient', back_populates='measurement')