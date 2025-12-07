from datetime import datetime
from models import db

feedback_upvotes = db.Table('feedback_upvotes',
    db.Column('user_id', db.Integer, db.ForeignKey('users.id'), primary_key=True),
    db.Column('feedback_id', db.Integer, db.ForeignKey('feedback.id'), primary_key=True)
)

class Feedback(db.Model):
    __tablename__ = 'feedback'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    
    # 'bug', 'feature', 'other'
    type = db.Column(db.String(20), nullable=False) 
    
    title = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False)
    
    # 'new' (default), 'planned', 'in_progress', 'completed', 'declined'
    status = db.Column(db.String(20), default='new') 
    
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    # Relationship to User (so you know who submitted it)
    user = db.relationship('User', backref='feedbacks')

    upvoters = db.relationship('User', secondary=feedback_upvotes, backref=db.backref('upvoted_feedback', lazy='dynamic'))

    def to_dict(self, current_user=None):
        return {
            "id": self.id,
            "title": self.title,
            "description": self.description,
            "status": self.status,
            "type": self.type,
            "upvotes": len(self.upvoters),
            "has_upvoted": current_user in self.upvoters if current_user else False
        }