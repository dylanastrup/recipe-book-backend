from models import db

class Rating(db.Model):
    __tablename__ = 'ratings'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    recipe_id = db.Column(db.Integer, db.ForeignKey('recipes.id'), nullable=False)
    score = db.Column(db.Integer, nullable=False)

    # Relationships
    user = db.relationship('User', back_populates='ratings')
    recipe = db.relationship('Recipe', back_populates='ratings')