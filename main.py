from flask import Flask, render_template, url_for, request, session, redirect
from flask_bcrypt import Bcrypt
from flask_pymongo import pymongo
import secrets
import string
import os

CONNECTION_STRING = os.environ.get("MONGO_KEY")
client = pymongo.MongoClient(CONNECTION_STRING)
db = client['GameRampStore']

app = Flask(__name__)
app.secret_key = secrets.token_urlsafe(32)
bcrypt = Bcrypt(app)

# default vars for flask
account = 'Log In'
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

    if request.method == 'POST':
        global account
        users = db['UserInfo']
        login_user = users.find_one({'username': request.form['username']})

        if login_user:
            if bcrypt.check_password_hash(
                    login_user['password'],
                    request.form.get('pass', False).encode('utf-8')):
                session['username'] = request.form['username']
                return redirect(url_for('index'))
        else:
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
                users.insert({
                    'email': request.form['email'],
                    'profilename': request.form['profilename'],
                    'username': request.form['username'],
                    'password': hashpass,
                    'games': [],
                    'balance': 5000
                })
                # session['username'] = request.form['username']
                return render_template(
                    'login.html',
                    account=account,
                    comment='Your account was added successfully!')

            else:
                error = "The username that you entered already exists."
                return render_template('register.html',
                                       account=account,
                                       error=error)

        else:
            error = "The passwords you entered do not match."
            return render_template('register.html',
                                   account=account,
                                   error=error)

    else:
        return render_template('register.html',
                               account=account,
                               acclink=loginlink)


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

    return redirect(url_for('index'))


@app.route('/profile')
def profile():
    global account
    global db
    if 'username' in session:
        account = session['username'].upper()
        userinfo = db['UserInfo']
        user = userinfo.find_one({"username": session['username']})

        if user:
            return render_template('profile.html',
                                   account=account,
                                   username=user['username'],
                                   prof=user['profilename'],
                                   games=user['games'],
                                   ngames=len(user['games']),
                                   balance=user['balance'])
        else:
            return redirect(url_for('index'))
    else:
        return redirect(url_for('index'))


@app.route('/library')
def library():
    global account
    if 'username' in session:
        account = session['username'].upper()
        return render_template('library.html', account=account)

    return redirect(url_for('index'))


@app.route('/about')
def about():
    global account
    if 'username' in session:
        account = session['username'].upper()
        return render_template('about.html', account=account, layout='layout')
    else:
        return render_template('about.html', account=account, layout='home')


@app.route('/accountsettings')
def acc_settings():

    global account
    if 'username' in session:
        account = session['username'].upper()
        return render_template('accountsettings.html', account=account)

    else:
        return redirect(url_for('index'))


@app.route('/changeusername', methods=['POST', 'GET'])
def changeusername():
    global account
    if 'username' in session:
        account = session['username'].upper()

        if request.method == 'POST':
            userinfo = db['UserInfo']
            user = userinfo.find_one({"username": request.form['oldusername']})

            if user:
                existing_user = userinfo.find_one(
                    {"username": request.form['newusername']})
                if existing_user:
                    return render_template('accountsettings.html', account=account, error="The New Username already exists!")
                else:
                    userinfo.update_one({'username': request.form['oldusername']}, {
                                        "$set": {"username": request.form['newusername']}})
                    session['username'] = request.form['newusername']     
                    account = session['username'].upper()
                    return render_template('accountsettings.html', account=account, comment="New Username set successfully!")

            else:
                return render_template('accountsettings.html', account=account, error="The Old username is incorrect.")
    else:
        return redirect(url_for('index'))


@app.route('/changepassword', methods=['POST', 'GET'])
def changepassword():
    global account
    if 'username' in session:
        account = session['username'].upper()
        return render_template('library.html', account=account)

    return redirect(url_for('index'))


if __name__ == '__main__':
    app.config['SESSION_TYPE'] = 'mongodb'
    app.run(debug=True)
