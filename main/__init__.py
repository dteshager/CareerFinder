import os
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager
from flask_mail import Mail
from flask_dance.contrib.google import make_google_blueprint, google
from flask_dance.contrib.github import make_github_blueprint, github




from dotenv import load_dotenv

load_dotenv()




os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'
app = Flask(__name__)
app.config['SECRET_KEY']="cfa2f205ad8f7196954a5050e98cc199"
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'


#Google OAuth
google_bp = make_google_blueprint(
    client_id=os.getenv("GOOGLE_CLIENT_ID"),
    client_secret=os.getenv("GOOGLE_CLIENT_SECRET"),
    scope=["openid", "https://www.googleapis.com/auth/userinfo.email", "https://www.googleapis.com/auth/userinfo.profile"],
    redirect_to="google_login"
)

#GitHub OAuth
github_bp = make_github_blueprint(client_id=os.getenv("GITHUB_CLIENT_ID"),
                                   client_secret=os.getenv("GITHUB_CLIENT_SECRET"),
                                  redirect_to="github_login")

app.register_blueprint(google_bp, url_prefix='/login')
app.register_blueprint(github_bp, url_prefix='/login')

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message_category = 'info'

app.config['MAIL_SERVER'] = 'smtp.googlemail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.getenv("EMAIL_ADDRESS")
app.config['MAIL_PASSWORD'] = os.getenv('EMAIL_PASSWORD')
mail= Mail(app)



from main import routes