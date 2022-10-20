import os
from io import BytesIO
from glob import glob
from zipfile import ZipFile
from flask import Flask, flash, request, redirect, render_template, send_from_directory,send_file
from werkzeug.utils import secure_filename
from encryption import encrypt_file
from generate_key import generate_key

UPLOAD_FOLDER = '../public'
ALLOWED_EXTENSIONS = {'txt'}

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/', methods=['GET', 'POST'])
def upload_file():
    if request.method == 'POST':
        if 'file' not in request.files:
            flash('No file part')
            return redirect(request.url)
        file = request.files['file']
        if file.filename == '':
            flash('No selected file')
            return redirect(request.url)
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            generate_key(filename)
            encrypt_file(filename)
            stream = BytesIO()
            with ZipFile(stream, 'w') as zf:
                for file in glob(os.path.join('../public/', '*.txt')):
                    zf.write(file, os.path.basename(file))
                for file in glob(os.path.join('../public/', '*.key')):
                    zf.write(file, os.path.basename(file))
            stream.seek(0)
            return send_file(stream,
                    mimetype = 'zip',
                    download_name='Encrypted.zip',
                    as_attachment = True)
    return render_template('base.html', mode='decrypt')
   

@app.route('/uploads/<name>')
def download_file(name):
    return send_from_directory(app.config["UPLOAD_FOLDER"], name,as_attachment=True)






