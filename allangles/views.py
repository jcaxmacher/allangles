from flask import (request, session, g, redirect, url_for, abort,
                   render_template, flash, send_from_directory)
from flaskext.wtf import (Form, TextField, PasswordField, BooleanField,
                          Required, EqualTo, RecaptchaField,
                          ValidationError, IntegerField)
from wtforms.ext.dateutil.fields import DateField
from flask.ext.login import (current_user, login_required, login_user,
                             logout_user, confirm_login,
                             fresh_login_required)
from sqlalchemy.exc import IntegrityError
from functools import wraps
from urlparse import urlparse
import translitcodec
from allangles.utils import *
from allangles.models import *
from allangles import app, facebook
from allangles import configuration as config
import uuid
import json
import boto

ses = boto.connect_ses(
    aws_access_key_id=os.environ.get('AWS_KEY'),
    aws_secret_access_key=os.environ.get('AWS_SECRET')
)

class SignupForm(Form):
    name = TextField('<h4>Full name</h4>', validators=[Required()])
    email = TextField('<h4>Email address</h4>', validators=[Required()])
    username = TextField('<h4>Username<br><small>Choose a unique name. There are no rules. Smaller and simpler is better because your username will be part of the web address that event attendees use to send you photos.</small></h4>', validators=[Required()])
    password = PasswordField('<h4>Password</h4>', validators=[Required()])
    recaptcha = RecaptchaField('<h4>Fill in what you see<br><small>or use the buttons on the right to get a new picture or audio challenge if the one displayed is too cryptic.</small></h4>')

class LoginForm(Form):
    email = TextField('Email')
    password = PasswordField('Password')

class EventForm(Form):
    name = TextField('Name', validators=[Required()])
    date = DateField('Date', validators=[Required()])
    zip_code = IntegerField('Zip Code', validators=[Required()])

class InitialProfileForm(Form):
    username = TextField('Choose a username', validators=[Required()])

def not_logged_in(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if current_user.is_authenticated():
            return redirect(url_for('profile'))
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
            return redirect(request.args.get('next') or url_for('profile'))
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
        user.username = form.username.data
        user.userslug = slugify(form.username.data)
        user.set_password(form.password.data)
        try:
            db.session.add(user)
            db.session.commit()
        except IntegrityError as e:
            if 'column userslug' in str(e):
                form.username.errors.append('Sorry, that username is not available.  Please choose another.')
            if 'column email' in str(e):
                form.email.errors.append('It appears that email is already in use. Send an email to <a href="mailto:robot@allangl.es">robot@allangl.es</a> to request a password reset.')
            return render_template('signup.html', form=form)
        login_user(user, remember=True, force=True)
        user_activation = UserActivation(user_id = user.id)
        db.session.add(user_activation)
        db.session.commit()
        flash('Your account was created successfully!', 'alert-success')
        ses.send_email(config.EMAIL,
            'Activate your AllAngl.es account',
            'Please confirm your email address by clicking the following link: http://allangl.es/activate/%s If you did not sign up for an AllAngl.es account, you can safely ignore or delete this email.' % user_activation.uuid,
            [user.email])
        return redirect(url_for('unconfirmed'))
    return render_template('signup.html', form=form)

@app.route('/resetpassword/')
def reset_password():
    pass
@app.route('/activate/<uuid>')
def activate(uuid):
    activation = UserActivation.query.filter_by(uuid=uuid).first_or_404()
    user = activation.user
    user.activate = True
    db.session.add(user)
    db.session.delete(activation)
    db.session.commit()
    flash('Your account was successfully activated!', 'alert-success')
    return redirect(url_for('profile'))

@app.route('/event/', methods=['GET', 'POST'])
@login_required
def event():
    form = EventForm()
    if not current_user.activate:
        flash('Please confirm your email address before creating an event.', 'alert-error')
        return redirect(url_for('unconfirmed'))
    elif form.validate_on_submit():
        event = Event(current_user.id, form.name.data,
                      form.date.data, form.zip_code.data)
        db.session.add(event)
        db.session.commit()
        flash('Your event was created successfully!', 'alert-success')
        return redirect(url_for('events'))
    return render_template('event.html', form=form, user=current_user)

@app.route('/events/')
@login_required
def events():
    if not len(current_user.events.all()):
        return redirect(url_for('event'))
    return render_template('events.html', user=current_user)

@app.route('/home/')
@login_required
def home():
    return render_template('home.html', user=current_user)

@app.route('/photos/<event>')
def photos():
    return ''

@app.route('/<user_slug>/<event_slug>/', methods=['GET', 'POST'])
def upload(user_slug, event_slug):
    user = User.query.filter_by(userslug=user_slug).first_or_404()
    event = Event.query.filter_by(slug=event_slug,
                                  user_id=user.id).first_or_404()
    if request.method == 'POST':
        for file_id in request.form.iterkeys():
            if is_uuid_file(file_id):
                delete_files(file_id)
        stored = process_uploads(request, event=event)
        return render_template('upload.html', photos=stored,
                               event=event)
    return render_template('upload.html', event=event, user=current_user)

@app.route('/<user_slug>/<event_slug>/view/')
def gallery(user_slug, event_slug):
    user = User.query.filter_by(userslug=user_slug).first_or_404()
    event = Event.query.filter_by(slug=event_slug,
                                  user_id=user.id).first_or_404()
    photos = db.session.query(Photo).join(Photo.event).filter(Event.slug==event_slug).join(Event.user).filter(User.userslug==user_slug).all()
    return render_template('gallery.html', photos=photos, event=event, user=current_user)

@app.route('/jsupload/', methods=['POST'])
def jsupload():
    url_path = urlparse(request.referrer).path
    path_parts = url_path.split('/')
    if len(path_parts) < 3:
        abort(403)
    _, user_slug, event_slug = path_parts[:3]
    user = User.query.filter_by(userslug=user_slug).first_or_404()
    event = Event.query.filter_by(slug=event_slug, user_id=user.id).first_or_404()
    stored = process_uploads(request, event=event)
    return json.dumps(stored)

@app.route('/upload/<filename>', methods=['GET', 'DELETE'])
def serve(filename):
    if request.method == 'DELETE':
        result = delete_files(filename)
        return '', result
    return send_from_directory(app.config['UPLOAD_FOLDER'],
                               filename)

@app.route('/profile/', methods=['POST', 'GET'])
@login_required
def profile():
    form = InitialProfileForm()
    if not current_user.activate:
        flash('Please confirm your email address before attempting to add a username', 'alert-error')
        return redirect(url_for('unconfirmed'))
    elif form.validate_on_submit():
        current_user.username = form.username.data
        current_user.userslug = slugify(current_user.username)
        db.session.add(current_user)
        db.session.commit()
        flash('Your username was added successfully.', 'alert-success')
        return redirect(url_for('events'))
    return render_template('profile.html', form=form, user=current_user)

@app.route('/unconfirmed/')
@login_required
def unconfirmed():
    return render_template('unconfirmed.html', user=current_user)

@app.route('/resend/')
@login_required
def resend():
    activation = UserActivation.query.filter_by(user_id=current_user.id).first_or_404()
    activation.email_sent = False
    db.session.add(activation)
    db.session.commit()
    return redirect(url_for('unconfirmed'))

@app.route('/fblogin/authorized')
@facebook.authorized_handler
def facebook_authorized(resp):
    next_url = request.args.get('next') or url_for('profile')
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
