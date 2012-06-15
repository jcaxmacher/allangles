import re
import os
import uuid
from wand.image import Image
from allangles import app, db
from allangles import configuration as config
from flask import session

UUID4_RE = re.compile(
    r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
)
_punct_re = re.compile(r'[\t !"#$%&\'()*\-/<=>?@\[\\\]^_`{|},.]+')

def slugify(text, delim=u'-'):
    """Generates an ASCII-only slug."""
    result = []
    for word in _punct_re.split(text.lower()):
        word = word.encode('translit/long')
        if word:
            result.append(word)
    return unicode(delim.join(result))

def allowed_file(filename):
    return '.' in filename and \
        filename.rsplit('.', 1)[1].lower() in config.ALLOWED_EXTENSIONS

def scale_dimensions(img, max_size=100):
    width = img.width
    height = img.height
    max_dimension = height if height < width else width
    factor = float(max_size) / float(max_dimension)
    return (int(width * factor), int(height * factor))
    
def make_resize(filename, new_filename, max_dim, max_width, max_height):
    with Image(filename=filename) as img:
        width, height = scale_dimensions(img, max_size=max_dim)
        with img.clone() as clone:
            clone.resize(width, height)
            #clone.crop(left=(clone.width - max_width) / 2,
            #           top=(clone.height - max_height) / 2,
            #           width=max_width, height=max_height)
            clone.save(filename=new_filename)

def resize(filename, sizes):
    with Image(filename=filename) as img:
        for newfile, dim in sizes:
            width, height = scale_dimensions(img, max_size=dim)
            with img.clone() as clone:
                clone.resize(width, height)
                clone.save(filename=newfile)
    
def delete_files(file_id, prefixes=['', 'thumb-', 'web-']):
    error = False
    for prefix in prefixes:
        try:
            os.remove(os.path.join(app.config['UPLOAD_FOLDER'], '%s%s' % (prefix, file_id)))
        except OSError:
            pass
    return 200

def is_uuid_file(file):
    name = file.split('.')[0]
    return True if UUID4_RE.match(name) else False

def process_uploads(request, event=None):
    stored = []
    for file in request.files.getlist('file'):
        if file and allowed_file(file.filename):

            file_uuid = str(uuid.uuid4())
            file_id = '%s.%s' % (
                file_uuid, file.filename.rsplit('.', 1)[1]
            )
            filename = os.path.join(app.config['UPLOAD_FOLDER'], file_id)

            thumb_id = 'thumb-%s' % file_id
            thumb_filename = os.path.join(
                app.config['UPLOAD_FOLDER'], thumb_id
            )

            web_id = 'web-%s' % file_id
            web_filename = os.path.join(
                app.config['UPLOAD_FOLDER'], web_id
            )


            file.save(filename)
            resize(filename, [(thumb_filename, 80), (web_filename, 1000)])
            
            size = os.stat(filename).st_size

            stored.append({'name': 'View a larger version', 'size': size,
                'url': '/static/uploads/%s' % web_id,
                'thumbnail_url': '/static/uploads/%s' % thumb_id,
                'delete_url': '/upload/%s' % file_uuid,
                'delete_type': 'DELETE',
                'file_id': file_id
            })

            from allangles.models import Photo
            photo = Photo(event.user_id, event.slug, file_uuid, file_id, thumb_id, web_id, session['owner_uuid'])
            db.session.add(photo)
    db.session.commit()
    return stored

