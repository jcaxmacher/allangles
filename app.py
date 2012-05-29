import re
import os
import json
import uuid
import stat
from wand.image import Image
from flask import Flask, request, session, g, redirect, url_for, \
    abort, render_template, flash, send_from_directory
from werkzeug import secure_filename
from flaskext.uploads import (UploadSet, configure_uploads, IMAGES,
                              UploadNotAllowed, patch_request_class)

UUID4_RE = re.compile(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$')

AWS_ACCESS_KEY = "AKIAIOVXMOUEL26POEBQ"
AWS_SECRET_KEY = "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"
SEND_FILE_MAX_AGE_DEFAULT = 0
MAX_CONTENT_LENGTH = 16 * 1024 * 1024

AWS_POLICY = """
{"expiration": "2019-01-01T00:00:00Z",
  "conditions": [ 
    {"bucket": "allangles"}, 
    ["starts-with", "$key", "uploads/"],
    {"acl": "private"},
    {"success_action_redirect": "http://localhost"},
    ["starts-with", "$Content-Type", "image/"],
    ["content-length-range", 0, 1048576]
  ]
}
"""
DEBUG = True

UPLOAD_FOLDER = os.path.join(os.getcwd(), 'static', 'uploads')
print UPLOAD_FOLDER
ALLOWED_EXTENSIONS = set(['jpg', 'png', 'gif'])

app = Flask(__name__)
app.config.from_object(__name__)

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
