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
from flask import Flask, flash, redirect, render_template, session, request, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_login import login_user, LoginManager, UserMixin, logout_user, login_required, current_user
from werkzeug.security import check_password_hash
from flask_shorturl import ShortUrl
from requests_oauthlib import OAuth2Session
from requests.exceptions import HTTPError
from flask_wtf import Form
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import Email, DataRequired
from itsdangerous import URLSafeTimedSerializer
from flask_mail import Mail, Message
import uuid
from flask_oauthlib.client import OAuth

basedir = os.path.abspath(os.path.dirname(__file__))

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

app = Flask(__name__)

app.config["DEBUG"] = True
SQLALCHEMY_DATABASE_URI = "mysql+mysqlconnector://{username}:{password}@{hostname}/{databasename}".format(
    username="cluepony",
    password="Ragpark69",
    hostname="cluepony.mysql.pythonanywhere-services.com",
    databasename="cluepony$ClueponyDB",
)

app.config["SQLALCHEMY_DATABASE_URI"] = SQLALCHEMY_DATABASE_URI
app.config["SQLALCHEMY_POOL_RECYCLE"] = 299
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SECURITY_PASSWORD_SALT"] = 'fugee the wondercat'
app.config['SECRET_KEY']= "fugee the wondercat"
app.config['SECURITY_POST_LOGIN'] = '/profile'
app.config['SOCIAL_FACEBOOK'] = {
    'consumer_key': '179641645948417',
    'consumer_secret': '556d9d8e04132fe9aaf3d4a4399dbdb2'
}

app.config['SOCIAL_GOOGLE'] = {
    'consumer_key': '879725201216-ro7lq6osvqfrk8gulo1rsnbqlj69lb55.apps.googleusercontent.com',
    'consumer_secret': 'VGUSnZkIZsg19uY88UAdKL76'
}


app.config.update(
    #EMAIL SETTINGS
    MAIL_SERVER='smtp.gmail.com',
    MAIL_PORT=465,
    MAIL_USE_SSL=True,
    MAIL_USERNAME = 'cluepony@gmail.com',
    MAIL_PASSWORD = 'Ragpark69!'
)
DEBUG = False
BCRYPT_LOG_ROUNDS = 13
WTF_CSRF_ENABLED = True
DEBUG_TB_ENABLED = False
DEBUG_TB_INTERCEPT_REDIRECTS = False
# mail accounts
app.config['MAIL_DEFAULT_SENDER'] = 'info@cluepony.com'

su = ShortUrl(app)
db = SQLAlchemy(app)
oauth = OAuth(app)
migrate = Migrate(app, db)
mail = Mail()
mail.init_app(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"
login_manager.session_protection = "strong"


# Put your consumer key and consumer secret into a config file
# and don't check it into github!!
microsoft = oauth.remote_app(
	'microsoft',
	consumer_key='35683781-6ce7-4334-b929-fca52b73a6d4',
	consumer_secret='wlOKHL51^}~ikrokMNZ668{',
	request_token_params={'scope': 'offline_access User.Read'},
	base_url='https://graph.microsoft.com/v1.0/',
	request_token_url=None,
	access_token_method='POST',
	access_token_url='https://login.microsoftonline.com/common/oauth2/v2.0/token',
	authorize_url='https://login.microsoftonline.com/common/oauth2/v2.0/authorize'
)

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
    registered_on = db.Column(db.DateTime, nullable=False)
    admin = db.Column(db.Boolean, nullable=False, default=False)
    confirmed = db.Column(db.Boolean, nullable=False, default=False)
    confirmed_on = db.Column(db.DateTime, nullable=True)

    def __init__(self, email, username, password, confirmed,
                 paid=False, admin=False, confirmed_on=None):
        self.email = email
        self.username = username
        self.password_hash = password
        self.registered_on = datetime.now()
        self.admin = admin
        self.confirmed = confirmed
        self.confirmed_on = confirmed_on

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def get_id(self):
        return str(self.email)

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

class SignupForm(Form):
    email = StringField('email',
                validators=[DataRequired(),Email()])
    username = StringField('username',
                validators=[DataRequired()])
    password = PasswordField(
                'password_hash',
                validators=[DataRequired()])
    submit = SubmitField("Sign In")

class LoginForm(Form):
    email = StringField('email',
                validators=[DataRequired(),Email()])
    password = PasswordField(
                'password_hash')
    submit = SubmitField("Log In")

@login_manager.user_loader
def load_user(email):
    return User.query.filter_by(email = email).first()

def send_email(to, subject, template):
    msg = Message(
        subject,
        recipients=[to],
        html=template,
        sender=app.config['MAIL_DEFAULT_SENDER']
    )
    mail.send(msg)

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

def generate_confirmation_token(email):
    serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
    return serializer.dumps(email, salt=app.config['SECURITY_PASSWORD_SALT'])


def confirm_token(token, expiration=3600):
    serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
    try:
        email = serializer.loads(
            token,
            salt=app.config['SECURITY_PASSWORD_SALT'],
            max_age=expiration
        )
    except:
        return False
    return email

@app.route('/azure')
def azureindex():
	return render_template('azure_hello.html')

@app.route('/azurelogin', methods = ['POST', 'GET'])
def loginazure():
	if 'microsoft_token' in session:
		return redirect(url_for('azureme'))

	# Generate the guid to only accept initiated logins
	guid = uuid.uuid4()
	session['state'] = guid

	return microsoft.authorize(callback=url_for('authorized', _external=True), state=guid)

@app.route('/logoutazure', methods = ['POST', 'GET'])
def logoutazure():
	session.pop('microsoft_token', None)
	session.pop('state', None)
	return redirect(url_for('index'))

@app.route('/login/authorized')
def authorized():
	response = microsoft.authorized_response()

	if response is None:
		return "Access Denied: Reason=%s\nError=%s" % (
			response.get('error'),
			request.get('error_description')
		)

	# Check response for state
	print("Response: " + str(response))
	if str(session['state']) != str(request.args['state']):
		raise Exception('State has been messed with, end authentication')

	# Okay to store this in a local variable, encrypt if it's going to client
	# machine or database. Treat as a password.
	session['microsoft_token'] = (response['access_token'], '')

	return redirect(url_for('me'))

@app.route('/azureme')
def azureme():
	me = microsoft.get('me')
	return render_template('azure_me.html', me=str(me.data))


@microsoft.tokengetter
def get_microsoft_oauth_token():
	return session.get('microsoft_token')

@app.route('/confirm/<token>')
@login_required
def confirm_email(token):
    try:
        email = confirm_token(token)
    except:
        flash('The confirmation link is invalid or has expired.', 'danger')
    user = User.query.filter_by(email=email).first_or_404()
    if user.confirmed:
        flash('Account already confirmed. Please login.', 'success')
    else:
        user.confirmed = True
        user.confirmed_on = datetime.now()
        db.session.add(user)
        db.session.commit()
        flash('You have confirmed your account. Thanks!', 'success')
    return redirect(url_for('index'))

@app.route("/", methods=["GET"])
def home():
    if request.method == "GET":
        return render_template("index.html")

@app.route("/index", methods=["GET"])
def index():
    if request.method == "GET":
        return render_template("index.html")

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    form = SignupForm()
    if request.method == 'GET':
        google = get_google_auth()
        auth_url, state = google.authorization_url(
        Auth.AUTH_URI, access_type='offline')
        session['oauth_state'] = state
        return render_template('signup.html', form = form, auth_url=auth_url)
    elif request.method == 'POST':
        if form.validate_on_submit():
            if User.query.filter_by(email=form.email.data).first():
                return render_template("signup.html", form=form, error=True)
            else:
                confirmed = False
                newuser = User(form.email.data, form.username.data, form.password.data, confirmed)
                db.session.add(newuser)
                db.session.commit()


                token = generate_confirmation_token(newuser.email)
                confirm_url = url_for('confirm_email', token=token, _external=True)
                html = render_template('activate.html', confirm_url=confirm_url)
                subject = "Please confirm your email"
                send_email(newuser.email, subject, html)

                login_user(newuser)
                flash('A confirmation email has been sent via email.', 'success')
                return redirect(url_for('index')) #should change this to a welcome page

        else:
            return render_template("signup.html", form=form, error=True)


@app.route('/login', methods=['GET','POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = LoginForm()
    if request.method == 'GET':
        google = get_google_auth()
        auth_url, state = google.authorization_url(
        Auth.AUTH_URI, access_type='offline')
        session['oauth_state'] = state
        return render_template('login.html', form=form, auth_url=auth_url)

    elif request.method == 'POST':
        if form.validate_on_submit():
            user=User.query.filter_by(email=form.email.data).first()
            if user:
                if user.password_hash == form.password.data:
                    login_user(user)
                    return redirect(url_for('index'))
                else:
                    return render_template("login.html", form=form, error=True)
            else:
                return render_template("login.html", form=form, error=True)
        else:
            return render_template("login.html", form=form, error=True)

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
        #return redirect(url_for('generator'))
        return render_template("generator.html", error=True)

    LastRow = Cluepony.query.count()
    url = su.encode_url(LastRow)
    cluepony = Cluepony(content=request.form["contents"], encoded_url=url,publisher=current_user)
    db.session.add(cluepony)
    db.session.commit()

    return redirect(url_for('generator'))

@app.route('/resource/view/<short_url>')
def resource(short_url):
    if request.method == "GET":
        return render_template('resource.html', cluepony_ID= short_url, error=False)

@app.route('/profile/view/<short_url>')
def profile(short_url):
    if not current_user.is_authenticated:
        return redirect(url_for('index'))
    google = get_google_auth()
    auth_url, state = google.authorization_url(
        Auth.AUTH_URI, access_type='offline')
    session['oauth_state'] = state
    return render_template('profile.html', auth_url=auth_url, cluepony_ID= short_url, error=False)

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
                user = User(user_data['email'],user_data['name'],"password", True)
                user.email = email
            user.name = user_data['name']
            print(token)
            user.tokens = json.dumps(token)
            user.avatar = user_data['picture']
            db.session.add(user)
            db.session.commit()
            login_user(user)
            return redirect(url_for('index'))
        return 'Could not fetch your information.'

@app.route("/logout")
@login_required
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