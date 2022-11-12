from __future__ import print_function
from base64 import b64decode, b64encode
from fileinput import filename
import os
import time
from io import BytesIO
from glob import glob
from zipfile import ZipFile
from flask import Flask, flash, request, redirect, render_template, send_from_directory, send_file, session
from decryption import decrypt_file
from werkzeug.utils import secure_filename
from encryption import encrypt_file
from generate_key import generate_key
from flask_mysqldb import MySQL
import rsa
import sys
import check_password



UPLOAD_FOLDER = '../public'
DECRYPT_UPLOAD_FOLDER = '../public/decryption'
ALLOWED_EXTENSIONS = {'txt'}

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['DECRYPT_UPLOAD_FOLDER'] = DECRYPT_UPLOAD_FOLDER
app.config['SECRET_KEY'] = "<some key>" 
app.config['SESSION_TYPE'] = 'filesystem'

#ZMENIT NA ZAKLADE SERVERA
app.config['MYSQL_HOST'] = '127.0.0.1'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = 'root'
app.config['MYSQL_DB'] = 'UPB'
 
mysql = MySQL(app)

def generate_RSA():  #TU VYGENERUJEME RSA KLUC
    (pubKey, privKey) = rsa.newkeys(1024)
    return pubKey, privKey

def load_keys():
    with open('keys/pubkey.pem', 'rb') as f:
        pubkey = rsa.PublicKey.load_pkcs1(f.read())
    with open('keys/privkey.pem', 'rb') as f:
        privkey = rsa.PrivateKey.load_pkcs1(f.read())
    return pubkey, privkey

def encrypt_RSA(msg, key):
    return rsa.encrypt(msg, key)

def decrypt_RSA(ciphertext, key):
    try:
        return rsa.decrypt(ciphertext, key).decode('ascii')
    except:
        return False

def sign_sha1(msg, key):
    return rsa.sign(msg.encode('ascii'), key, 'SHA-1')

def verify_sha1(msg, signature, key):
    try:
        return rsa.verify(msg.encode('ascii'), signature, key) == 'SHA-1'
    except:
        False

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


@app.route('/encrypt', methods=['GET', 'POST'])
def upload_file():
    if "user" not in session:
        print("user not in session")
        return redirect('/login')
    if request.method == 'POST':
        if "open" in request.form:
            pubKey, privKey = generate_RSA()
            stream = BytesIO() #VYGENERUJEME A STIAHNEME KLUCE
            with ZipFile(stream, 'w') as zf:
                zf.writestr("publickey.pem",pubKey.save_pkcs1('PEM'))
                zf.writestr("privatekey.pem",privKey.save_pkcs1('PEM'))
            stream.seek(0)
            return send_file(stream,
                             mimetype='zip',
                             download_name='RSA.zip',
                             as_attachment=True)
        if 'file' in request.files and "open" not in request.form:
            file = request.files['file']
            if file.filename.strip() == '':
                flash('No selected file')
                return redirect(request.url)
            file_list =request.files.getlist('file')
            if len(file_list) != 2:
                flash('Upload two files - file to decode and key')
                return redirect(request.url)
#-----------------------------------------------------------------------------------------------------
            #NACITANIE FILEU A RSA KLUCA
            file_to_encrypt = find(file_list, lambda file: file.filename.endswith('.txt'))
            RSA_public_key = find(file_list, lambda file: file.filename.endswith('.pem'))

            if file_to_encrypt == None or RSA_public_key == None:
                flash('Invalid files submitted')
                return redirect(request.url)
        #----------------------------------------------------------------------------------------------------
            if file and allowed_file(file_to_encrypt.filename):
                filename = secure_filename(file_to_encrypt.filename)
                RSA_key_file_name = secure_filename(RSA_public_key.filename)

                file_to_encrypt.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                RSA_public_key.save(os.path.join(app.config['UPLOAD_FOLDER'], RSA_key_file_name))

                with open(app.config['UPLOAD_FOLDER'] +'/'+RSA_public_key.filename, 'rb') as publicRSAKEY:
                    RSA_public_key=rsa.PublicKey.load_pkcs1(publicRSAKEY.read())
                #------------------------------------------------------------------------------------------
                AES_key = generate_key(filename) #TUTO KLUC DOSTANEME KLUC, ULOZI SA DO PUBLIC ZLOZKY
                AES_encrypted = encrypt_RSA(AES_key, RSA_public_key)
                encrypt_file(filename, AES_encrypted, AES_key)
                

                stream = BytesIO()
                with ZipFile(stream, 'w') as zf:
                    for file in glob(os.path.join('../public/', '*.txt')):
                        zf.write(file, os.path.basename(file))
                stream.seek(0)
                os.remove(app.config['UPLOAD_FOLDER'] +'/'+RSA_key_file_name)
                os.remove(app.config['UPLOAD_FOLDER'] +'/'+filename)
                return send_file(stream,
                             download_name='Encrypted.zip',
                                as_attachment=True)
            else:
                flash('Invalid files submitted')
    return render_template('endecrypt.html.jinja', mode='encrypt')

def find(list, condition):
    for i in range(len(list)):
        if condition(list[i]):
            return list[i]
    return None

@app.route('/decrypt', methods=['GET', 'POST'])
def decrypt():
    if "user" not in session:
        return redirect('/login')
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
        RSA_private_key = find(file_list, lambda file: file.filename.endswith('.pem'))
        if file_to_decrypt == None or RSA_private_key == None:
            flash('Invalid files submitted')
            return redirect(request.url)
       #-----------------------------------------------------------------------------------------------------------------------------------------
        file_to_decrypt_filename = secure_filename(file_to_decrypt.filename)
        file_to_decrypt.save(os.path.join(app.config['DECRYPT_UPLOAD_FOLDER'], file_to_decrypt_filename))
        RSA_private_key_filename = secure_filename(RSA_private_key.filename)
        RSA_private_key.save(os.path.join(app.config['DECRYPT_UPLOAD_FOLDER'], RSA_private_key_filename))
        
        with open(app.config['DECRYPT_UPLOAD_FOLDER'] +'/'+RSA_private_key.filename, 'rb') as privateRSAKEY:
                RSA_private_key=rsa.PrivateKey.load_pkcs1(privateRSAKEY.read())
        
        decrypt_file(file_to_decrypt.filename, RSA_private_key)
        return send_from_directory(app.config["DECRYPT_UPLOAD_FOLDER"], 'decrypted.txt', as_attachment=True)
        #-------------------------------------------------------------------------------------------------------------------------------------------
    return render_template('endecrypt.html.jinja', mode='decrypt')

@app.route('/')
def redirect_to_encrypt():
    return redirect('/encrypt')

@app.route('/uploads/<name>')
def download_file(name):
    if "user" not in session:
        return redirect('/login')
    return send_from_directory(app.config["UPLOAD_FOLDER"], name, as_attachment=True)

@app.route('/download')
def download_decrypter():
    if "user" not in session:
        return redirect('/login')
    return send_from_directory("../","Offline_Decrypter.exe", as_attachment=True)

'''
Podstatou saltingu je ukrytie dalsej informacie v hashi, vytvorenom z hesla. Ide o skupinu znakov, 
ktora sa pridaju k heslu a az potom sa zahashuje. Kazde heslo ulozene v systeme ma svoj vlastny salt, ktory je ulozeny s 
prihlasovacim menom a zahashovanym heslom. Salt je najcastejsie nahodne generovane císlo
'''
def generate_salt(password):
    #príklad vytvorenie saltu, z maleho pismena m, z císla c, zo znaku z, z velkého písmena v
    salt = ""
    for key in password:
        if(key.isupper()):
            salt += 'v'
        elif(key.islower()):
            salt += 'm'
        elif(key.isnumeric()):
            salt += 'c'
        else:
            salt += 'z'
    return salt

def generate_hashed_pass(salt,password):
    #priklad vytvorenia hashovaneho hesla
    return salt+password+salt

def register(userName,password,firstName,lastName,email):
    salt = generate_salt(password)
    hashed_pass = generate_hashed_pass(salt,password)
    try:
        cursor = mysql.connection.cursor()
        statement = ("INSERT INTO users (userName,hashed_pass,salt,firstName,lastName,email) VALUES(%s,%s,%s,%s,%s,%s)")
        params = (userName,hashed_pass,salt,firstName,lastName,email)
        cursor.execute(statement,params)
        mysql.connection.commit()
        cursor.close()
        return 0
    except Exception as e:
        print(e)
        if(e.args[0] == 1062):
            flash("Username or email address already exists")
        return -1


def login(userName,password):
    salt = generate_salt(password)
    hashed_pass = generate_hashed_pass(salt,password)
    cursor = mysql.connection.cursor()
    cursor.execute("SELECT * FROM users WHERE userName = %s",[userName])
    response = cursor.fetchone()
    if(hashed_pass == response[4]):
        return 0
    else:
        flash("Nesprávne meno alebo heslo")
        return -1


@app.route('/login', methods=['GET', 'POST'])
def login_route():
    if "user" in session:
        print("redirecting to encrypt")
        return redirect('/encrypt')
    if "login" in request.form:
        userName = request.form.get("userName")
        password = request.form.get("password")
        if login(userName,password) == 0:
            session["user"] = userName
            return redirect(('/encrypt'))
    return render_template('login.html.jinja')

@app.route('/register', methods=['GET','POST'])
def register_route():
    if "user" in session:
        return redirect('/encrypt')
    if "register" in request.form:
        firstName = request.form.get("firstName")
        lastName = request.form.get("lastName")
        email = request.form.get("email")
        userName = request.form.get("userName")
        password = request.form.get("password")
        passAgain = request.form.get("passwordAgain")
        if(password and check_password.check_weak_password(password=password)):
            flash('Weak password, please use password with at least 8 symbols including one upper letter, special symbol and number.')
            return render_template('register.html.jinja')
        if(password != passAgain):
            flash("Passwords dont match")
            return render_template('register.html.jinja')
        if register(userName,password,firstName,lastName,email) == 0:
            session["user"] = userName
            return redirect('/encrypt')
    return render_template('register.html.jinja')

@app.route('/logout')
def logout_route():
    session.pop("user",None)
    return redirect('/login')
