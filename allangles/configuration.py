import os
from datetime import timedelta

DEBUG = True if os.environ.get('DEBUG') else False
EMAIL = os.environ.get('OUTGOING_EMAIL', 'AllAngl.es Email Robot <robot@allangl.es>')

UPLOAD_PREFIX = '/upload'
MAX_CONTENT_LENGTH = 16 * 1024 * 1024
UPLOAD_FOLDER = os.path.join(os.getcwd(), 'allangles', 'static', 'uploads')
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
