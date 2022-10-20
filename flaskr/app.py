import os
from flask import Flask, flash, request, redirect, url_for
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
            generate_key()
            encrypt_file(filename)
            return redirect(url_for('upload_file', name=filename))
    if request.method == 'POST' and request.path == '/decrypt':
        print('dada')
    return '''
    <html lang="en">
    <head>
        <meta charset="UTF-8" />
        <meta http-equiv="X-UA-Compatible" content="IE=edge" />
        <meta name="viewport" content="width=device-width, initial-scale=1.0" />
        <title>Zadanie 2</title>
        <link rel="stylesheet" href="./static/style.css" />
        <link rel="preconnect" href="https://fonts.googleapis.com" />
        <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin />
        <link
        href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;700&display=swap"
        rel="stylesheet"
        />
    </head>
    <body>
        <div class=center>
        <div class=title>
            <h1>Šifrovanie a dešifrovanie súborov</h1>
            <h3>symetrickým kľúčom K</h3>
        </div>
        <section>
            <form method=post enctype=multipart/form-data>
                <input type=file name=file>
                <input type=submit value=Upload>
            </form>
        </section>
        </div>
    </body>
    </html>

    '''






