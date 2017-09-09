import os
import base64
from io import StringIO
from flask import Flask, render_template, g, redirect, url_for, flash, session, \
    abort, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from flask.ext.sqlalchemy import SQLAlchemy
from flask.ext.login import LoginManager, UserMixin, login_user, logout_user, \
    current_user, login_required
from flask.ext.bootstrap import Bootstrap
from flask.ext.wtf import Form
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import Required, Length, EqualTo
import onetimepass
import pyqrcode
from itsdangerous import (TimedJSONWebSignatureSerializer
                          as Serializer, BadSignature, SignatureExpired)
from flask_httpauth import HTTPBasicAuth
from pyCGA.opencgarestclients import OpenCGAClient
import time

conf = {
    "version": "v1",
    "rest": {
        "hosts": [
            "10.182.155.30:81/opencga-1.2.0"
        ]
    }
}

class SDGSCatalog():
    def __init__(self, study):
        self.session = OpenCGAClient(configuration=conf, user='pipeline', pwd='p1p3l1n3')
        self.study = str(study)

    def get_individual_count(self):
        return len(self.session.individuals.search(study=self.study).get())

    def get_sample_count(self):
        return len(self.session.samples.search(study=self.study).get())

    def get_variant_count(self):
        return self.session.analysis_variant.query(pag_size=10,data={})



s = SDGSCatalog(study=2)


# create application instance
app = Flask(__name__)
app.config.from_object('config')

# initialize extensions
bootstrap = Bootstrap(app)
db = SQLAlchemy(app)
lm = LoginManager(app)
auth = HTTPBasicAuth()

class User(UserMixin, db.Model):
    """User model."""
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), index=True)
    password_hash = db.Column(db.String(128))
    otp_secret = db.Column(db.String(16))

    def __init__(self, **kwargs):
        super(User, self).__init__(**kwargs)
        if self.otp_secret is None:
            # generate a random secret
            self.otp_secret = base64.b32encode(os.urandom(10)).decode('utf-8')

    @property
    def password(self):
        raise AttributeError('password is not a readable attribute')

    @password.setter
    def password(self, password):
        self.password_hash = generate_password_hash(password)

    def verify_password(self, password):
        return check_password_hash(self.password_hash, password)

    def get_totp_uri(self):
        return 'otpauth://totp/NewBornScreeningPortal:{0}?secret={1}&issuer=NewBornScreeningPortal' \
            .format(self.username, self.otp_secret)

    def verify_totp(self, token):
        return onetimepass.valid_totp(token, self.otp_secret)

    def generate_auth_token(self, expiration=600):
        s = Serializer(app.config['SECRET_KEY'], expires_in=expiration)
        return s.dumps({'id': self.id})

    @staticmethod
    def verify_auth_token(token):
        s = Serializer(app.config['SECRET_KEY'])
        try:
            print token
            data = s.loads(token)
            print data
        except SignatureExpired:
            return None  # valid token, but expired
        except BadSignature:
            return None  # invalid
        user = User.query.get(data['id'])
        return user

@auth.verify_password
def verify_password(username_or_token, password_totp):
    # first try to authenticate by token
    user = User.verify_auth_token(username_or_token)
    if current_user.is_authenticated():
        g.user = current_user
        return True
    if not user:
        password, totp = password_totp.split("/")
        # try to authenticate with username/password and 2fa code
        user = User.query.filter_by(username=username_or_token).first()
        if not user or not user.verify_password(password) or not user.verify_totp(int(totp)):
            return False
    g.user = user
    return True

@lm.user_loader
def load_user(user_id):
    """User loader callback for Flask-Login."""
    return User.query.get(int(user_id))


class RegisterForm(Form):
    """Registration form."""
    username = StringField('Username', validators=[Required(), Length(1, 64)])
    password = PasswordField('Password', validators=[Required()])
    password_again = PasswordField('Password again',
                                   validators=[Required(), EqualTo('password')])
    submit = SubmitField('Register')


class LoginForm(Form):
    """Login form."""
    username = StringField('Username', validators=[Required(), Length(1, 64)])
    password = PasswordField('Password', validators=[Required()])
    token = StringField('Token', validators=[Required(), Length(6, 6)])
    submit = SubmitField('Login')


@app.route('/')
def index():
    individual_count = s.get_individual_count()
    sample_count = s.get_sample_count()
    return render_template('index.html',individual_count=individual_count,sample_count=sample_count)


@app.route('/register', methods=['GET', 'POST'])
def register():
    """User registration route."""
    if current_user.is_authenticated():
        # if user is logged in we get out of here
        return redirect(url_for('index'))
    form = RegisterForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user is not None:
            flash('Username already exists.')
            return redirect(url_for('register'))
        # add new user to the database
        user = User(username=form.username.data, password=form.password.data)
        db.session.add(user)
        db.session.commit()

        # redirect to the two-factor auth page, passing username in session
        session['username'] = user.username
        return redirect(url_for('two_factor_setup'))
    return render_template('register.html', form=form)


@app.route('/twofactor')
def two_factor_setup():
    if 'username' not in session:
        return redirect(url_for('index'))
    user = User.query.filter_by(username=session['username']).first()
    if user is None:
        return redirect(url_for('index'))
    # since this page contains the sensitive qrcode, make sure the browser
    # does not cache it
    return render_template('two-factor-setup.html'), 200, {
        'Cache-Control': 'no-cache, no-store, must-revalidate',
        'Pragma': 'no-cache',
        'Expires': '0'}


@app.route('/qrcode')
def qrcode():
    if 'username' not in session:
        abort(404)
    user = User.query.filter_by(username=session['username']).first()
    if user is None:
        abort(404)

    # for added security, remove username from session
    del session['username']

    # render qrcode for FreeTOTP
    url = pyqrcode.create(user.get_totp_uri())
    stream = StringIO()
    url.svg(stream, scale=3)
    return stream.getvalue().encode('utf-8'), 200, {
        'Content-Type': 'image/svg+xml',
        'Cache-Control': 'no-cache, no-store, must-revalidate',
        'Pragma': 'no-cache',
        'Expires': '0'}


@app.route('/login', methods=['GET', 'POST'])
def login():
    """User login route."""
    if current_user.is_authenticated():
        # if user is logged in we get out of here
        return redirect(url_for('index'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user is None or not user.verify_password(form.password.data) or \
                not user.verify_totp(form.token.data):
            flash('Invalid username, password or token.')
            return redirect(url_for('login'))

        # log user in
        login_user(user)
        flash('You are now logged in!')
        return redirect(url_for('index'))
    return render_template('login.html', form=form)


@app.route('/logout')
def logout():
    """User logout route."""
    logout_user()
    return redirect(url_for('index'))

@app.route('/api')
@login_required
def api():
    token = current_user.generate_auth_token(300)
    ends = time.strftime("%b %d %Y %H:%M:%S", time.localtime(time.time()+300))
    return render_template('token.html',token=token,expires=ends)

@app.route('/api/token')
@auth.login_required
def get_auth_token():
    token = g.user.generate_auth_token(500)
    return jsonify({ 'token': token.decode('ascii') })

@app.route('/api/resource')
@auth.login_required
def get_resource():
    return jsonify({'data': 'Hello, %s!' % g.user.username})


# create database tables if they don't exist yet
db.create_all()


if __name__ == '__main__':
    app.run(host='0.0.0.0', debug=True)
