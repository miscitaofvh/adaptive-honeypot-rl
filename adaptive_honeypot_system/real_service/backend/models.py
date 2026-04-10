from flask_sqlalchemy import SQLAlchemy
from datetime import datetime, timezone

db = SQLAlchemy()

class User(db.Model):
    __tablename__ = 'users'
    id            = db.Column(db.Integer, primary_key=True)
    username      = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    bio           = db.Column(db.Text, default='')
    created_at    = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    articles      = db.relationship('Article', backref='author', lazy='dynamic')
    
    def to_dict(self):
        return {'id':self.id,'username':self.username,'bio':self.bio}

class Article(db.Model):
    __tablename__ = 'articles'
    id         = db.Column(db.Integer, primary_key=True)
    title      = db.Column(db.String(256), nullable=False)
    summary    = db.Column(db.Text, nullable=False)
    content    = db.Column(db.Text, nullable=False, default='')
    category   = db.Column(db.String(80), nullable=False, default='General')
    tags       = db.Column(db.String(256), default='')
    read_time  = db.Column(db.Integer, default=5)
    author_id  = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    
    def to_dict(self, include_content=False, related=None):
        d = {'id':self.id,'title':self.title,'summary':self.summary,'category':self.category,
             'tags':self.tags.split(',') if self.tags else [],'read_time':self.read_time,
             'author':self.author.to_dict() if self.author else None,'created_at':self.created_at.isoformat()}
        if include_content: d['content'] = self.content
        if related is not None: d['related'] = [r.to_dict() for r in related]
        return d
