import os
import json
import stat
from flask import Flask, request, session, g, redirect, url_for, \
    abort, render_template, flash
from werkzeug import secure_filename
from flaskext.uploads import (UploadSet, configure_uploads, IMAGES,
                              UploadNotAllowed, patch_request_class)

AWS_ACCESS_KEY = "AKIAIOVXMOUEL26POEBQ"
AWS_SECRET_KEY = "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"

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
        filename.rsplit('.', 1)[1] in ALLOWED_EXTENSIONS

@app.route("/upload/", methods=['GET', 'POST'])
def upload():
    if request.method == 'POST':
        good = []
        for f in request.files.getlist('file'):
            if f and allowed_file(f.filename):
                filename = secure_filename(f.filename)
                f.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                size = os.stat(os.path.join(app.config['UPLOAD_FOLDER'], filename)).st_size
                print dir(f)
                print f.headers
                good.append({'name': f.filename, 'size': size,
                    'url': '/static/uploads/%s' % filename,
                    'thumbnail_url': '/static/uploads/%s' % filename,
                    'delete_url': '/static/uploads/%s' % filename,
                    'delete_type': 'DELETE'
                })
        return json.dumps(good)
    return render_template('upload.html')

if __name__ == '__main__':
    app.run()
