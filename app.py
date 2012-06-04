import re
import os
import json
import uuid
import stat
from datetime import timedelta, datetime
from functools import wraps
from wand.image import Image
from flask import Flask, request, session, g, redirect, url_for, \
    abort, render_template, flash, send_from_directory
from werkzeug import secure_filename
from flask.ext.sqlalchemy import SQLAlchemy
from flaskext.bcrypt import Bcrypt
from flaskext.wtf import Form, TextField, PasswordField, BooleanField, \
    Required, EqualTo, RecaptchaField, ValidationError
from flask.ext.login import (LoginManager, current_user, login_required,
                            login_user, logout_user, UserMixin, AnonymousUser,
                            confirm_login, fresh_login_required)
from flask.ext.oauth import OAuth
from wtforms.ext.dateutil.fields import DateField
import translitcodec

class MethodRewriteMiddleware(object):
    def __init__(self, app):
        self.app = app
    def __call__(self, environ, start_response):
        if 'METHOD_OVERRIDE' in environ.get('QUERY_STRING', ''):
            args = url_decode(environ['QUERY_STRING'])
            method = args.get('__METHOD_OVERRIDE__')
            if method:
                method = method.encode('ascii', 'replace')
                environ['REQUEST_METHOD'] = method
        return self.app(environ, start_response)

_punct_re = re.compile(r'[\t !"#$%&\'()*\-/<=>?@\[\\\]^_`{|},.]+')

def slugify(text, delim=u'-'):
    """Generates an ASCII-only slug."""
    result = []
    for word in _punct_re.split(text.lower()):
        word = word.encode('translit/long')
        if word:
            result.append(word)
    return unicode(delim.join(result))

DEBUG = True if os.environ.get('DEBUG') else False
UUID4_RE = re.compile(
    r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
)

MAX_CONTENT_LENGTH = 16 * 1024 * 1024
UPLOAD_FOLDER = os.path.join(os.getcwd(), 'static', 'uploads')
ALLOWED_EXTENSIONS = set(['jpg', 'png', 'gif'])
SQLALCHEMY_DATABASE_URI = 'sqlite:///%s' % os.path.join(os.getcwd(), 'dev.db')
SECRET_KEY = os.environ.get(
    'SECRET_KEY',
    'j2\xa9\xb7\xe4\xe4D\t\xc0\x052q\xfc\x8c\xe9\xbe\x0c\x0e#:\x9f\xc5\xa9\xcf'
)

RECAPTCHA_USE_SSL = True
RECAPTCHA_PUBLIC_KEY = '6Lc9EdISAAAAAEVtUpivYYV-xgzGtfrNGrTYfhwe' 
RECAPTCHA_PRIVATE_KEY = '6Lc9EdISAAAAACaPQmjh_rUUAldVoAhfZKydZrAQ'

PERMANENT_SESSION_LIFETIME = timedelta(days=180)

app = Flask(__name__)
app.config.from_object(__name__)
app.wsgi_app = MethodRewriteMiddleware(app.wsgi_app)

oauth = OAuth()
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager()
login_manager.anonymous_user = AnonymousUser
login_manager.login_view = 'login'
login_manager.login_message = u'Please log in to access this page'

facebook = oauth.remote_app('facebook',
    base_url='https://graph.facebook.com/',
    request_token_url=None,
    access_token_url='/oauth/access_token',
    authorize_url='https://www.facebook.com/dialog/oauth',
    consumer_key=os.environ.get('FB_API_KEY'),
    consumer_secret=os.environ.get('FB_SECRET'),
    request_token_params={'scope': 'email'}
)

class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(60))
    username = db.Column(db.String(60))
    pwdhash = db.Column(db.String())
    email = db.Column(db.String(60), unique=True)
    activate = db.Column(db.Boolean)
    created = db.Column(db.DateTime)
    fb_id = db.Column(db.String(30), unique=True)
    events = db.relationship('Event', backref='user', lazy='dynamic')
    activations = db.relationship('UserActivation', backref='user',
        lazy='dynamic')

    def __init__(self):
        self.activate = False
        self.created = datetime.utcnow()

    def __repr__(self):
        return '<User %r>' % self.username

    def check_password(self, password):
        return bcrypt.check_password_hash(self.pwdhash, password)

    def set_password(self, password):
        self.pwdhash = bcrypt.generate_password_hash(password)

    def get_id(self):
        return unicode(self.id)

    def is_active(self):
        return self.activate

    def is_anonymous(self):
        return False

    def is_authenticated(self):
        return True

class Event(db.Model):
    __tablename__ = 'events'
    slug = db.Column(db.String(100), primary_key=True)
    name = db.Column(db.String(100))
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), primary_key=True)
    date = db.Column(db.DateTime)

    def __repr__(self):
        return '<Event %r>' % self.username

    def __init__(self, user_id, name, date):
        self.user_id = user_id
        self.name = name
        self.date = date
        self.slug = slugify(name)

class UserActivation(db.Model):
    __tablename__ = 'activations'
    uuid = db.Column(db.String(40), primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    email_sent = db.Column(db.Boolean)
    created = db.Column(db.DateTime)

    def __repr__(self):
        return '<UserActivation %r>' % self.uuid

    def __init__(self, user_id):
        self.user_id = user_id
        self.uuid = str(uuid.uuid4())
        self.email_sent = False
        self.created = datetime.utcnow() 

@login_manager.user_loader
def load_user(id):
    return User.query.filter_by(id=id).first()
    
login_manager.setup_app(app)

class SignupForm(Form):
    name = TextField('Your name')
    email = TextField('Email', validators=[Required()])
    password = PasswordField('Password', validators=[Required()])
    accept_tos = BooleanField('I accept the Terms of Service', validators=[Required()])
    recaptcha = RecaptchaField()

class LoginForm(Form):
    email = TextField('Email')
    password = PasswordField('Password')

class EventForm(Form):
    name = TextField('Event name', validators=[Required()])
    date = DateField('Date', validators=[Required()])


def allowed_file(filename):
    return '.' in filename and \
        filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def scale_dimensions(img, max_size=100):
    width = img.width
    height = img.height
    max_dimension = height if height < width else width
    factor = float(max_size) / float(max_dimension)
    return (int(width * factor), int(height * factor))
    
def make_thumb(filename, thumb_filename, max_dim=80, max_width=80, max_height=80):
    with Image(filename=filename) as img:
        width, height = scale_dimensions(img, max_size=max_dim)
        with img.clone() as clone:
            clone.resize(width, height)
            clone.crop(left=(clone.width - max_width) / 2,
                       top=(clone.height - max_height) / 2,
                       width=max_width, height=max_height)
            clone.save(filename=thumb_filename)
    
def delete_files(file_id, prefixes=['', 'thumb-']):
    error = False
    for prefix in prefixes:
        try:
            os.remove(os.path.join(app.config['UPLOAD_FOLDER'], '%s%s' % (prefix, file_id)))
        except OSError:
            error = True
    return 404 if error else 200

def is_uuid_file(file):
    name = file.split('.')[0]
    return True if UUID4_RE.match(name) else False

def not_logged_in(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if current_user.is_authenticated():
            return redirect(url_for('home'))
        else:
            return f(*args, **kwargs)
    return wrapper
    
@app.route('/login/', methods=['GET', 'POST'])
@not_logged_in
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if not user or not user.check_password(form.password.data):
            form.errors['email'] = [u'Incorrect email or password.']
        elif login_user(user, remember=True, force=True):
            return redirect(request.args.get('next') or url_for('home'))
    return render_template('login.html', form=form)

@app.route('/fblogin/')
@not_logged_in
def fblogin():
    return facebook.authorize(callback=url_for('facebook_authorized',
        next=request.args.get('next') or request.referrer or None,
        _external=True))

@app.route('/logout/')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/')
def index():
    print url_for('facebook_authorized')
    return redirect(url_for('signup'))

@app.route('/signup/', methods=['GET', 'POST'])
@not_logged_in
def signup():
    form = SignupForm()
    if form.validate_on_submit():
        user = User()
        user.email = form.email.data
        user.name = form.name.data
        user.set_password(form.password.data)
        db.session.add(user)
        db.session.commit()
        login_user(user, remember=True, force=True)
        user_activation = UserActivation(user_id = user.id)
        db.session.add(user_activation)
        db.session.commit()
        flash('Your account was created successfully!', 'alert-success')
        return redirect(url_for('home'))
    return render_template('signup.html', form=form)

@app.route('/activate/<uuid>')
def activate(uuid):
    activation = UserActivation.query.filter_by(uuid=uuid).first_or_404()
    user = activation.user
    user.activate = True
    db.session.add(user)
    db.session.query(UserActivation).filter(UserActivation.user_id==user.id).delete()
    db.session.commit()
    flash('Your account was successfully activated!', 'alert-success')
    return redirect(url_for('home'))

@app.route('/events/', methods=['GET', 'POST'])
@login_required
def events():
    form = EventForm()
    if not current_user.activate:
        flash('Please confirm your email address before creating an event.', 'alert-error')
        return redirect(url_for('home'))
    elif form.validate_on_submit():
        event = Event(current_user.id, form.name.data, form.date.data)
        db.session.add(event)
        db.session.commit()
        flash('Your event was created successfully!', 'alert-success')
        return redirect(url_for('home'))
    return render_template('event.html', form=form, user=current_user)

@app.route('/home/')
@login_required
def home():
    return render_template('home.html', user=current_user)

@app.route('/events/<event>', methods=['DELETE', 'GET'])
def event(event):
    if request.method == 'DELETE':
        pass
    return ''

@app.route('/photos/<event>')
def photos():
    return ''

def process_uploads(request):
    stored = []
    for file in request.files.getlist('file'):
        if file and allowed_file(file.filename):

            file_id = '%s.%s' % (
                uuid.uuid4(), file.filename.rsplit('.', 1)[1]
            )
            filename = os.path.join(app.config['UPLOAD_FOLDER'], file_id)

            thumb_id = 'thumb-%s' % file_id
            thumb_filename = os.path.join(
                app.config['UPLOAD_FOLDER'], thumb_id
            )

            file.save(filename)
            make_thumb(filename, thumb_filename)
            
            size = os.stat(filename).st_size

            stored.append({'name': 'View a larger version', 'size': size,
                'url': '/upload/%s' % file_id,
                'thumbnail_url': '/upload/%s' % thumb_id,
                'delete_url': '/upload/%s' % file_id,
                'delete_type': 'DELETE',
                'file_id': file_id
            })
    return stored
    
@app.route('/upload/', methods=['GET', 'POST'])
def upload():
    if request.method == 'POST':
        for file_id in request.form.iterkeys():
            if is_uuid_file(file_id):
                delete_files(file_id)
        stored = process_uploads(request)
        return render_template('upload.html', photos=stored)
    return render_template('upload.html')

@app.route('/jsupload/', methods=['POST'])
def jsupload():
    stored = process_uploads(request)
    return json.dumps(stored)

@app.route('/upload/<filename>', methods=['GET', 'DELETE'])
def serve(filename):
    if request.method == 'DELETE':
        result = delete_files(filename)
        return '', result
    return send_from_directory(app.config['UPLOAD_FOLDER'],
                               filename)

@app.route('/fblogin/authorized')
@facebook.authorized_handler
def facebook_authorized(resp):
    next_url = request.args.get('next') or url_for('home')
    if resp is None:
        flash('You denied the login')
        return redirect(next_url)

    session['fb_access_token'] = (resp['access_token'], '')

    me = facebook.get('/me')
    user = User.query.filter_by(email=me.data['email']).first()
    if user is None:
        user = User()
        user.fb_id = me.data['id']
        user.email = me.data['email']
        user.name = me.data['name']
        user.activate = True
        db.session.add(user)
    elif user.fb_id is None:
        user.fb_id = me.data['id']
        db.session.add(user)

    db.session.commit()
    login_user(user, remember=True)

    flash('You are now logged in as %s' % user.email, 'alert-success')
    return redirect(next_url)

@facebook.tokengetter
def get_facebook_oauth_token():
    return session.get('fb_access_token')

if __name__ == '__main__':
    app.run()
