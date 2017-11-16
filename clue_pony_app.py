# A very simple Clue Pony Alpha app to get started with...
# This version is from the Github
# This is the latest edit. Written in Gut Hub. Posted to PythonAnywhere
# This is an edit made 11:39. Push'ed to Pythonanywhere?
# Cloned git 12:42. Fresh start?!
# Pushed from PA OK - now commit to PA from GH?


import os
import validators
from datetime import datetime
from flask import Flask, redirect, render_template, request, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_login import login_user, LoginManager, UserMixin, logout_user, login_required, current_user
from werkzeug.security import check_password_hash
from flask_shorturl import ShortUrl

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

db = SQLAlchemy(app)
migrate = Migrate(app, db)

app.secret_key = "fugee the wondercat"
login_manager = LoginManager()
login_manager.init_app(app)

class User(UserMixin, db.Model):

    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(128))
    password_hash = db.Column(db.String(128))
    email = db.Column(db.String(128))

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def get_id(self):
        return self.username

    def is_active(self):
        """True, as all users are active."""
        return True

    def is_authenticated(self):
        """Return True if the user is authenticated."""
        return self.authenticated

    def is_anonymous(self):
        """False, as anonymous users aren't supported."""
        return False

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
    event_id = db.Column(db.Integer, db.ForeignKey('clueponies.id'))


@login_manager.user_loader
def load_user(user_id):
    return User.query.filter_by(username=user_id).first()

@app.route("/", methods=["GET"])
def index():
    if request.method == "GET":
        return render_template("index.html")


@app.route("/login/", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return render_template("login.html", error=False)

    user = load_user(request.form["username"])

    if user is None:
        user = User(username=request.form["username"], email=request.form["email"],password_hash=request.form["password"])
        db.session.add(user)
        db.session.commit()

        return redirect(url_for('index'))

    if not user.check_password(request.form["password"]):
        return render_template("login.html", error=True)

    login_user(user)
    return redirect(url_for('index'))

@app.route("/publishers/", methods=["GET", "POST"])
def publishers_page():
    if request.method == "GET":
         return render_template("publisher.html", error=False)


@app.route("/about/", methods=["GET", "POST"])
def about_page():
    if request.method == "GET":
         return render_template("about.html", error=False)

@app.route("/generator/", methods=["GET", "POST"])
def generator():
    if request.method == "GET":
         return render_template("generator.html", clueponies=Cluepony.query.all())

    if not current_user.is_authenticated:
        return redirect(url_for('generator'))

    if not validators.url(request.form["contents"]):
        return redirect(url_for('generator'))

    LastRow = Cluepony.query.count()
    url = su.encode_url(LastRow)
    cluepony = Cluepony(content=request.form["contents"], encoded_url=url,publisher=current_user)
    db.session.add(cluepony)
    db.session.commit()

    return redirect(url_for('generator'))


@app.route('/<short_url>')
def decode(short_url):
    Destination_URL = Cluepony.query.filter_by(encoded_url=short_url).first()

    event_time = datetime.now

    event = CluePonyEvent(event_date=event_time)
    db.session.add(event)
    db.session.commit()

    redirect_url = Destination_URL.content
    try:
        return redirect(redirect_url)

    except Exception as e:
        print (e)

    return redirect(redirect_url)

@app.route("/logout/")
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