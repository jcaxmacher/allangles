import re
import os
import boto
from datetime import datetime, timedelta
from flask import (Flask, request, session, g, redirect, url_for, abort,
                   render_template, flash, send_from_directory)
from flask.ext.sqlalchemy import SQLAlchemy
from flask.ext.login import LoginManager, AnonymousUser
from flask.ext.oauth import OAuth
from allangles.middleware import MethodRewriteMiddleware
from flask_pewee.db import Database

app = Flask(__name__)
app.config.from_object('allangles.configuration')
app.wsgi_app = MethodRewriteMiddleware(app.wsgi_app)

oauth = OAuth()
db = Database(app)

login_manager = LoginManager()
login_manager.anonymous_user = AnonymousUser
login_manager.login_view = 'login'
login_manager.login_message = u'Please log in to access this page'
@login_manager.user_loader
def load_user(id):
    from allangles.models import User
    return User.query.filter_by(id=id).first()
login_manager.setup_app(app)

facebook = oauth.remote_app('facebook',
    base_url='https://graph.facebook.com/',
    request_token_url=None,
    access_token_url='/oauth/access_token',
    authorize_url='https://www.facebook.com/dialog/oauth',
    consumer_key=os.environ.get('FB_API_KEY'),
    consumer_secret=os.environ.get('FB_SECRET'),
    request_token_params={'scope': 'email'}
)

import allangles.views
