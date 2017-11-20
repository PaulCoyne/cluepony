# A very simple Clue Pony Alpha app to get started with...
# This version is from the Github
# This is the latest edit. Written in Gut Hub. Posted to PythonAnywhere
# This is an edit made 11:39. Push'ed to Pythonanywhere?
# Cloned git 12:42. Fresh start?!
# Pushed from PA OK - now commit to PA from GH?


import os
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'
import validators
import json
from datetime import datetime
from flask import Flask, redirect, render_template, session, request, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_login import login_user, LoginManager, UserMixin, logout_user, login_required, current_user
from werkzeug.security import check_password_hash
from flask_shorturl import ShortUrl
from requests_oauthlib import OAuth2Session
from requests.exceptions import HTTPError

basedir = os.path.abspath(os.path.dirname(__file__))
app = Flask(__name__)
app.config["DEBUG"] = True
su = ShortUrl(app)

SQLALCHEMY_DATABASE_URI = "mysql+mysqlconnector://{username}:{password}@{hostname}/{databasename}".format(
    username="cluepony",
    password="Ragpark69",
    hostname="cluepony.mysql.pythonanywhere-services.com",
    databasename="cluepony$ClueponyDB",
)
app.config["SQLALCHEMY_DATABASE_URI"] = SQLALCHEMY_DATABASE_URI
app.config["SQLALCHEMY_POOL_RECYCLE"] = 299
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config['SECURITY_POST_LOGIN'] = '/profile'
app.config['SOCIAL_FACEBOOK'] = {
    'consumer_key': '179641645948417',
    'consumer_secret': '556d9d8e04132fe9aaf3d4a4399dbdb2'
}

app.config['SOCIAL_GOOGLE'] = {
    'consumer_key': '879725201216-ro7lq6osvqfrk8gulo1rsnbqlj69lb55.apps.googleusercontent.com',
    'consumer_secret': 'VGUSnZkIZsg19uY88UAdKL76'
}

db = SQLAlchemy(app)
migrate = Migrate(app, db)

app.secret_key = "fugee the wondercat"
login_manager = LoginManager()
login_manager.init_app(app)

login_manager = LoginManager(app)
login_manager.login_view = "login"
login_manager.session_protection = "strong"

class User(UserMixin, db.Model):

    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(128))
    password_hash = db.Column(db.String(128))
    email = db.Column(db.String(100), unique=True, nullable=False)
    name = db.Column(db.String(100), nullable=True)
    avatar = db.Column(db.String(200))
    active = db.Column(db.Boolean, default=False)
    tokens = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.now)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def get_id(self):
        return self.username

    def is_active(self):
        """True, as all users are active."""
        return True

    def is_anonymous(self):
        """False, as anonymous users aren't supported."""
        return False

    def is_authenticated(self):
        return True

class Cluepony(db.Model):

    __tablename__ = "clueponies"

    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.String(4096))
    encoded_url = db.Column(db.String(4096))
    posted = db.Column(db.DateTime, default=datetime.now)
    publisher_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    publisher = db.relationship('User', foreign_keys=publisher_id)

class CluePonyEvent(db.Model):

    __tablename__ = "events"

    id = db.Column(db.Integer, primary_key=True)
    event_date = db.Column(db.DateTime, default=datetime.now)
    event_id = db.Column(db.Integer)

class Auth:
    CLIENT_ID = ('621466473238-khkicq7nbdruk9vuga0oj58fbh38pueh.apps.googleusercontent.com')
    CLIENT_SECRET = 'h2xppeVKpR1oxmf5WGIRPyUF'
    REDIRECT_URI = 'http://www.cluepony.com/gCallback'
    AUTH_URI = 'https://accounts.google.com/o/oauth2/auth'
    TOKEN_URI = 'https://accounts.google.com/o/oauth2/token'
    USER_INFO = 'https://www.googleapis.com/userinfo/v2/me'
    SCOPE = ['profile', 'email']


class Config:
    APP_NAME = "Test Google Login"
    SECRET_KEY = os.environ.get("SECRET_KEY") or "somethingsecret"


class DevConfig(Config):
    DEBUG = True
    SQLALCHEMY_DATABASE_URI = 'sqlite:///' + os.path.join(basedir, "test.db")


class ProdConfig(Config):
    DEBUG = True
    SQLALCHEMY_DATABASE_URI = 'sqlite:///' + os.path.join(basedir, "prod.db")


config = {
    "dev": DevConfig,
    "prod": ProdConfig,
    "default": DevConfig
}

@login_manager.user_loader
def load_user(user_id):
    return User.query.filter_by(username=user_id).first()


def get_google_auth(state=None, token=None):
    if token:
        return OAuth2Session(Auth.CLIENT_ID, token=token)
    if state:
        return OAuth2Session(
            Auth.CLIENT_ID,
            state=state,
            redirect_uri=Auth.REDIRECT_URI)
    oauth = OAuth2Session(
        Auth.CLIENT_ID,
        redirect_uri=Auth.REDIRECT_URI,
        scope=Auth.SCOPE)
    return oauth


@app.route("/", methods=["GET"])
def home():
    if request.method == "GET":
        return render_template("index.html")

@app.route("/index", methods=["GET"])
def index():
    if request.method == "GET":
        return render_template("index.html")

@app.route('/loginold', methods=["GET", "POST"])
def loginold():
    if request.method == "GET":
        return render_template("login.html")
    if request.method == "POST":
        user = load_user(request.form["username"])
        if not user.check_password(request.form["password"]):
            return render_template("login.html", error=True)
        login_user(user)
        return redirect(url_for('index'))
        #return render_template("login.html", error=False)
    if current_user.is_authenticated:
        return redirect(url_for('generator'))
    google = get_google_auth()
    auth_url, state = google.authorization_url(
        Auth.AUTH_URI, access_type='offline')
    session['oauth_state'] = state
    return render_template('login.html', auth_url=auth_url)

@app.route("/login/", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        #return render_template("login.html", error=False)
        google = get_google_auth()
        auth_url, state = google.authorization_url(
        Auth.AUTH_URI, access_type='offline')
        session['oauth_state'] = state
        return render_template('login.html', auth_url=auth_url)

    user = load_user(request.form["username"])
    if user is None:
        return render_template("login.html", error=True)

    if not user.check_password(request.form["password"]):
        return render_template("login.html", error=True)

    login_user(user)
    return redirect(url_for('index'))

@app.route("/publishers/", methods=["GET", "POST"])
def publishers_page():
    if request.method == "GET":
         return render_template("publisher.html", error=False)

@app.route("/teachers/", methods=["GET", "POST"])
def teachers_page():
    if request.method == "GET":
         return render_template("teachers.html", error=False)

@app.route("/terms/", methods=["GET", "POST"])
def terms():
    if request.method == "GET":
         return render_template("terms.html", error=False)

@app.route("/about/", methods=["GET", "POST"])
def about_page():
    if request.method == "GET":
         return render_template("about.html", error=False)

@app.route("/generator/", methods=["GET", "POST"])
def generator():
    if request.method == "GET":
         #return render_template("generator.html", clueponies=Cluepony.query.all())
         CluePonyPosts = Cluepony.query.count()
         ListofCluePonies = Cluepony.query.order_by(Cluepony.posted.desc()).limit(10).all()
         return render_template("generator.html", clueponies = ListofCluePonies, NewCluePonies = CluePonyPosts)

    if not validators.url(request.form["contents"]):
        return redirect(url_for('generator'))

    LastRow = Cluepony.query.count()
    url = su.encode_url(LastRow)
    cluepony = Cluepony(content=request.form["contents"], encoded_url=url,publisher=current_user)
    db.session.add(cluepony)
    db.session.commit()

    return redirect(url_for('generator'))

@app.route('/resource/view/<short_url>')
def resource(short_url):
    if not current_user.is_authenticated:
        return redirect(url_for('index'))
    google = get_google_auth()
    auth_url, state = google.authorization_url(
        Auth.AUTH_URI, access_type='offline')
    session['oauth_state'] = state
    return render_template('resource.html', auth_url=auth_url, cluepony_ID= short_url, error=False)

@app.route('/r/<short_url>')
def decode(short_url):
    Destination_URL = Cluepony.query.filter_by(encoded_url=short_url).first()
    event_id = Destination_URL.id
    event = CluePonyEvent(event_id=event_id)
    db.session.add(event)
    db.session.commit()

    redirect_url = Destination_URL.content
    try:
        return redirect(redirect_url)

    except Exception as e:
        print (e)

    return redirect(redirect_url)

@app.route('/profile')
@login_required
def profile():
    return render_template('profile.html')

@app.route('/gCallback')
def callback():
    # Redirect user to home page if already logged in.
    if current_user is None and current_user.is_authenticated:
        return redirect(url_for('index'))
    if 'error' in request.args:
        if request.args.get('error') == 'access_denied':
            return 'You denied access.'
        return 'Error encountered.'
    if 'code' not in request.args and 'state' not in request.args:
        return redirect(url_for('login'))
    else:
        # Execution reaches here when user has
        # successfully authenticated our app.
        google = get_google_auth(state=session['oauth_state'])
        try:
            token = google.fetch_token(
                Auth.TOKEN_URI,
                client_secret=Auth.CLIENT_SECRET,
                authorization_response=request.url)
        except HTTPError:
            return 'HTTPError occurred.'
        google = get_google_auth(token=token)
        resp = google.get(Auth.USER_INFO)
        if resp.status_code == 200:
            user_data = resp.json()
            email = user_data['email']
            user = User.query.filter_by(email=email).first()
            if user is None:
                user = User()
                user.email = email
            user.name = user_data['name']
            print(token)
            user.tokens = json.dumps(token)
            user.avatar = user_data['picture']
            db.session.add(user)
            db.session.commit()
            login_user(user)
            return redirect(url_for('about_page'))
        return 'Could not fetch your information.'

@app.route("/logout/")
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404


if __name__ == '__main__':
    # Bind to PORT if defined, otherwise default to 5000.
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)