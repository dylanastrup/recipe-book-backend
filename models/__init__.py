from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

# --- Association Tables ---
recipe_tags = db.Table('recipe_tags',
    db.Column('recipe_id', db.Integer, db.ForeignKey('recipes.id'), primary_key=True),
    db.Column('tag_id', db.Integer, db.ForeignKey('tags.id'), primary_key=True)
)

user_favorites = db.Table('user_favorites',
    db.Column('user_id', db.Integer, db.ForeignKey('users.id'), primary_key=True),
    db.Column('recipe_id', db.Integer, db.ForeignKey('recipes.id'), primary_key=True)
)

# --- Import Models ---
from .User import User
from .Recipe import Recipe
from .Ingredient import Ingredient
from .Measurement import Measurement
from .RecipeIngredient import RecipeIngredient
from .RecipeStep import RecipeStep
from .Image import Image
from .Tag import Tag
from .Rating import Rating 
from .Feedback import Feedback
from .SiteSetting import SiteSetting