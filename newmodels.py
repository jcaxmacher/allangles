from peewee import *

database = SqliteDatabase('dev.db', **{})

class UnknownFieldType(object):
    pass

class BaseModel(Model):
    class Meta:
        database = database

class Activations(BaseModel):
    created = DateTimeField()
    email_sent = BooleanField()
    user = PrimaryKeyField(db_column='user_id')
    uuid = CharField()

    class Meta:
        db_table = 'activations'

class Events(BaseModel):
    date = DateTimeField()
    name = CharField()
    slug = PrimaryKeyField()
    user = PrimaryKeyField(db_column='user_id')
    zip_code = IntegerField()

    class Meta:
        db_table = 'events'

class Photos(BaseModel):
    cloud_hosted = BooleanField()
    created = DateTimeField()
    event_slug = CharField()
    original = CharField()
    thumb = CharField()
    user = IntegerField(db_column='user_id')
    uuid = PrimaryKeyField()

    class Meta:
        db_table = 'photos'

class Users(BaseModel):
    activate = BooleanField()
    created = DateTimeField()
    email = CharField()
    fb = CharField(db_column='fb_id')
    name = CharField()
    pwdhash = UnknownFieldType()
    username = CharField()
    userslug = CharField()

    class Meta:
        db_table = 'users'

