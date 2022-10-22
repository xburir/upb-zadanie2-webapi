from fileinput import filename
import os
import time
from io import BytesIO
from glob import glob
from zipfile import ZipFile
from flask import Flask, flash, request, redirect, render_template, send_from_directory, send_file
from decryption import decrypt_file
from werkzeug.utils import secure_filename
from encryption import encrypt_file
from generate_key import generate_key

#Vyrobila tvůrčí skupina Aleny Poledňákové a Vladimíra Tišňovského

UPLOAD_FOLDER = '../public'
DECRYPT_UPLOAD_FOLDER = '../public/decryption'
ALLOWED_EXTENSIONS = {'txt'}

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['DECRYPT_UPLOAD_FOLDER'] = DECRYPT_UPLOAD_FOLDER
app.config['SECRET_KEY'] = "<some key>" 
app.config['SESSION_TYPE'] = 'filesystem'


def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


@app.route('/encrypt', methods=['GET', 'POST'])
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
            start_time = time.time()
            generate_key(filename)
            encrypt_file(filename)
            print("--- %s seconds ---" % (time.time() - start_time))
            stream = BytesIO()
            with ZipFile(stream, 'w') as zf:
                for file in glob(os.path.join('../public/', '*.txt')):
                    zf.write(file, os.path.basename(file))
                for file in glob(os.path.join('../public/', '*.key')):
                    zf.write(file, os.path.basename(file))
            stream.seek(0)
            return send_file(stream,
                             mimetype='zip',
                             download_name='Encrypted.zip',
                             as_attachment=True)
    return render_template('base.html.jinja', mode='encrypt')

def find(list, condition):
    for i in range(len(list)):
        if condition(list[i]):
            return list[i]
    return None

@app.route('/decrypt', methods=['GET', 'POST'])
def decrypt():
    if request.method == 'POST':
        if 'file' not in request.files:
            flash('No file part')
            return redirect(request.url)
        file = request.files['file']
        if file.filename.strip() == '':
            flash('No selected file')
            return redirect(request.url)
        file_list =request.files.getlist('file')
        if len(file_list) != 2:
            flash('Upload two files - file to decode and key')
            return redirect(request.url)
        file_to_decrypt = find(file_list, lambda file: file.filename.endswith('.txt'))
        decryption_key = find(file_list, lambda file: file.filename.endswith('.key'))
        if file_to_decrypt == None or decryption_key == None:
            flash('Invalid files submitted')
            return redirect(request.url)

       

        file_to_decrypt_filename = secure_filename(file_to_decrypt.filename)
        file_to_decrypt.save(os.path.join(app.config['DECRYPT_UPLOAD_FOLDER'], file_to_decrypt_filename))
        decryption_key_filename = secure_filename(decryption_key.filename)
        decryption_key.save(os.path.join(app.config['DECRYPT_UPLOAD_FOLDER'], decryption_key_filename))
        decrypt_file(file_to_decrypt.filename, decryption_key.filename)
        return send_from_directory(app.config["DECRYPT_UPLOAD_FOLDER"], 'decrypted.txt', as_attachment=True)

    return render_template('base.html.jinja', mode='decrypt')


@app.route('/')
def redirect_to_encrypt():
    return redirect('/encrypt')


@app.route('/uploads/<name>')
def download_file(name):
    return send_from_directory(app.config["UPLOAD_FOLDER"], name, as_attachment=True)
