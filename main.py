from flask import Flask, render_template, url_for, request, session, redirect
from flask_bcrypt import Bcrypt
from flask_pymongo import pymongo
import secrets
import bcrypt
import string
import os

CONNECTION_STRING = os.environ.get("MONGO_KEY")
client = pymongo.MongoClient(CONNECTION_STRING)
db = client['GameRampStore']

app = Flask(__name__)
app.secret_key = secrets.token_urlsafe(32)
bcrypt = Bcrypt(app)

# default vars for flask
account = 'Sign In'
loginlink = "{{ url_for('login') }}"
librarylink = "{{ url_for('index') }}"


@app.route('/')
def home_redirect():
    return redirect(url_for('index'))


@app.route('/account')
def acc_check():
    global account
    if 'username' in session:
        account = session['username'].upper()
        return render_template('profile.html', account=account)

    return render_template('login.html', account=account)


@app.route('/home')
def index():
    global account
    if 'username' in session:
        account = session['username'].upper()
        return render_template('library.html', account=account)

    return render_template('home.html', account=account)


@app.route('/login', methods=['POST'])
def login():
    global account
    users = db['UserInfo']
    login_user = users.find_one({'username': request.form['username']})

    if login_user:
        if bcrypt.check_password_hash(login_user['password'], request.form['pass'].encode('utf-8')):
            session['username'] = request.form['username']
            return redirect(url_for('index'))

    error = "The username or password that you have entered is incorrect."
    return render_template('login.html', account=account, error=error)


@app.route('/register', methods=['POST', 'GET'])
def register():
    global account

    if request.method == 'POST':

        if request.form['pass'] == request.form['passconfirm']:
            users = db['UserInfo']
            existing_user = users.find_one(
                {'username': request.form['username']})

            if existing_user is None:
                hashpass = bcrypt.generate_password_hash(
                    request.form['pass'].encode('utf-8'))
                users.insert(
                    {'username': request.form['username'], 'password': hashpass})
                # session['username'] = request.form['username']
                return redirect(url_for('index'))

            else:
                error = "The username that you entered already exists."
                return render_template('register.html', account=account, error=error)

        else:
            error = "The passwords you entered do not match."
            return render_template('register.html', account=account, error=error)

    else:
        return render_template('register.html',  account=account,  acclink=loginlink)


@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('index'))


@app.route('/store')
def store():
    global account
    if 'username' in session:
        account = session['username'].upper()
        return render_template('store.html', account=account)

    return render_template('home.html', account=account)


@app.route('/profile')
def profile():
    global account
    if 'username' in session:
        account = session['username'].upper()
        return render_template('profile.html', account=account)

    return render_template('home.html', account=account)


@app.route('/library')
def library():
    global account
    if 'username' in session:
        account = session['username'].upper()
        return render_template('library.html', account=account)

    return render_template('home.html', account=account)


@app.route('/about')
def about():
    global account
    if 'username' in session:
        account = session['username'].upper()
        return render_template('about.html', account=account)

    return render_template('about.html', account=account)


if __name__ == '__main__':
    app.config['SESSION_TYPE'] = 'mongodb'
    app.run(debug=True)
