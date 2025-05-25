import datetime

from itsdangerous import URLSafeTimedSerializer as Serializer
from main import db, login_manager, app
from flask_login import UserMixin

#pick a salt for password-resets
SALT = 'password-reset-salt'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    image_file = db.Column(db.String(20), nullable=False, default='default.jpg')
    password = db.Column(db.String(60), nullable=False)


    def get_reset_token(self, expires_sec=1800):
        s = Serializer(app.config['SECRET_KEY'], salt=SALT)
        return s.dumps({'user_id': self.id})

    @staticmethod
    def verify_reset_token(token, expires_sec=1800):
        s = Serializer(app.config['SECRET_KEY'], salt=SALT)
        try:
            user_id = s.loads(token, max_age=expires_sec)['user_id']
        except:
            return None
        return User.query.get(user_id)
    def __repr__(self):
        return f"User('{self.username}', '{self.email}')"

class SavedJob(db.Model):
    id         = db.Column(db.Integer, primary_key=True)
    user_id    = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    job_id     = db.Column(db.String, nullable=False)      # unique identifier from Adzuna or USAJobs
    api_used   = db.Column(db.String(20), nullable=False)  # To store 'adzuna' or 'usajobs'
    job_data   = db.Column(db.JSON, nullable=False)        # store title/company/location/url, etc.
    saved_at   = db.Column(db.DateTime, server_default=db.func.now())

    user = db.relationship('User', backref='saved_jobs')


class Resume(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    content = db.Column(db.Text, nullable=False)  # JSON string containing resume data and suggestions
    theme = db.Column(db.String(50), default='modern')
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.datetime, onupdate=datetime.datetime.utcnow)
    user = db.relationship('User', backref='resumes')

    def __repr__(self):
        return f"Resume('{self.id}', '{self.user_id}', '{self.theme}')"





    def __repr__(self):
        return f"SavedJob('{self.job_id}', api_used='{self.api_used}', user='{self.user.username}', saved_at='{self.saved_at}')"