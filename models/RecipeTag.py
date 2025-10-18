from datetime import datetime
from models import db 

recipe_tags = db.Table(
    'recipe_tags',
    db.Column('recipe_id', db.Integer, db.ForeignKey('recipes.id'),primary_key=True),
    db.Column('tag_id', db.Integer, db.ForeignKey('tags.id'),primary_key=True)
)