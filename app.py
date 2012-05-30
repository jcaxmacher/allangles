import re
import os
import json
import uuid
import stat
from wand.image import Image
from flask import Flask, request, session, g, redirect, url_for, \
    abort, render_template, flash, send_from_directory
from werkzeug import secure_filename
from flask.ext.sqlalchemy import SQLAlchemy
from flaskext.bcrypt import Bcrypt
from flaskext.wtf import Form, TextField, PasswordField, BooleanField, validators, RecaptchaField

DEBUG = True
UUID4_RE = re.compile(
    r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
)

MAX_CONTENT_LENGTH = 16 * 1024 * 1024
UPLOAD_FOLDER = os.path.join(os.getcwd(), 'static', 'uploads')
ALLOWED_EXTENSIONS = set(['jpg', 'png', 'gif'])
SQLALCHEMY_DATABASE_URI = 'sqlite:///%s' % os.path.join(os.getcwd(), 'dev.db')

app = Flask(__name__)
app.config.from_object(__name__)
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

class User(db.Model):
    __tablename__ = 'users'
    uid = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(60))
    pwdhash = db.Column(db.String())
    email = db.Column(db.String(60))
    activate = db.Column(db.Boolean)
    created = db.Column(db.DateTime)

    def __init__(self, username, password, email):
        self.username = username
        self.pwdhash = bcrypt.generate_password_hash(password)
        self.email = email
        self.activate = False
        self.created = datetime.utcnow()

    def __repr__(self):
        return '<User %r>' % self.username

    def check_password(self, password):
        return bcrypt.check_password_hash(self.pwdhash, password)

class SignupForm(Form):
    username = TextField('Username', [validators.Required()])
    password = PasswordField('Password', [validators.Required(), validators.EqualTo('confirm', message='Passwords must match')])
    confirm = PasswordField('Confirm Password', [validators.Required()])
    email = TextField('eMail', [validators.Required()])
    accept_tos = BooleanField('I accept the TOS', [validators.Required])
    recaptcha = RecaptchaField()

class LoginForm(Form):
    username = TextField('Username', [validators.Required()])
    password = TextField('Password', [validators.Required()])

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

@app.route("/signup/", methods=['GET', 'POST'])
def signup():
    form = SignupForm()
    return render_template('signup.html', form=form)

#user = User.query.filter_by(username=form.username)

@app.route("/upload/", methods=['GET', 'POST'])
def upload():
    if request.method == 'POST':
        for file_id in request.form.iterkeys():
            if is_uuid_file(file_id):
                delete_files(file_id)
        stored = []
        print request.form.keys()
        for file in request.files.getlist('file'):
            if file and allowed_file(file.filename):
                file_id = '%s.%s' % (uuid.uuid4(), file.filename.rsplit('.', 1)[1])
                filename = os.path.join(app.config['UPLOAD_FOLDER'], file_id)

                thumb_id = 'thumb-%s' % file_id
                thumb_filename = os.path.join(app.config['UPLOAD_FOLDER'], thumb_id)

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
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return json.dumps(stored)
        else:
            return render_template('upload.html', photos=stored)
    return render_template('upload.html')

@app.route("/upload/<filename>", methods=['GET', 'DELETE'])
def serve(filename):
    if request.method == 'DELETE':
        result = delete_files(filename)
        return '', result
    return send_from_directory(app.config['UPLOAD_FOLDER'],
                               filename)

if __name__ == '__main__':
    app.run()
