import uuid
from datetime import datetime
from flaskext.bcrypt import Bcrypt
from allangles import db, app
from allangles.utils import slugify

bcrypt = Bcrypt(app)

class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(60))
    username = db.Column(db.String(60))
    userslug = db.Column(db.String(60), unique=True)
    pwdhash = db.Column(db.String(200))
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
    photos = db.relationship('Photo', backref='event', lazy='dynamic')
    zip_code = db.Column(db.Integer)

    def __repr__(self):
        return '<Event %r>' % self.name

    def __init__(self, user_id, name, date, zip_code):
        self.user_id = user_id
        self.name = name
        self.date = date
        self.slug = slugify(name)
        self.zip_code = zip_code

class UserActivation(db.Model):
    __tablename__ = 'activations'
    uuid = db.Column(db.String(40))
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), primary_key=True)
    email_sent = db.Column(db.Boolean)
    created = db.Column(db.DateTime)

    def __repr__(self):
        return '<UserActivation %r>' % self.uuid

    def __init__(self, user_id):
        self.user_id = user_id
        self.uuid = str(uuid.uuid4())
        self.email_sent = False
        self.created = datetime.utcnow() 

class Photo(db.Model):
    __tablename__ = 'photos'
    uuid = db.Column(db.String(40), primary_key=True)
    user_id = db.Column(db.Integer)
    #, db.ForeignKey('users.id'))
    event_slug = db.Column(db.String(40))
    #, db.ForeignKey('events.slug'))
    created = db.Column(db.DateTime)
    cloud_hosted = db.Column(db.Boolean)
    original = db.Column(db.String(60))
    web = db.Column(db.String(60))
    thumb = db.Column(db.String(60))
    owner_uuid = db.Column(db.String(60))
    owner_name = db.Column(db.String(60))
    __table_args__ = (db.ForeignKeyConstraint([user_id, event_slug],
                                              [Event.user_id, Event.slug]),
                      {})

    def get_thumb_url(self):
        return u'%s/%s' % (app.config.get('UPLOAD_PREFIX'), self.thumb)
    thumb_url = property(get_thumb_url)

    def get_web_url(self):
        return u'%s/%s' % (app.config.get('UPLOAD_PREFIX'), self.web)
    web_url = property(get_web_url)

    def get_url(self):
        return u'%s/%s' % (app.config.get('UPLOAD_PREFIX'), self.original)
    url = property(get_url)

    def __repr__(self):
        return '<Photo %r>' % self.uuid

    def __init__(self, user_id, event_slug, uuid, original, thumb,
        web, owner_uuid, owner_name):
        self.user_id = user_id
        self.event_slug = event_slug
        self.uuid = uuid
        self.cloud_hosted = False
        self.created = datetime.utcnow() 
        self.original = original
        self.thumb = thumb
        self.web = web
        self.owner_uuid = owner_uuid
        self.owner_name = owner_name[:60]
