from flask import Flask, render_template, url_for, request, session, redirect
from flask_bcrypt import Bcrypt
from flask_pymongo import pymongo
import secrets
import string
import os
import functools


CONNECTION_STRING = os.environ.get("MONGO_KEY")
client = pymongo.MongoClient(CONNECTION_STRING)
db = client['GameRampStore']

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY")
app.config['SEND_FILE_MAX_AGE_DEFAULT'] = 0
bcrypt = Bcrypt(app)

# default vars for flask
account = 'Log In'


@app.route('/')
def home_redirect():
    return redirect(url_for('index'))


def checkif_loggedin(func):
    @functools.wraps(func)
    def secure_function(*args, **kwargs):
        if 'username' not in session:
            return redirect(url_for("login", next=request.url))
        return func(*args, **kwargs)

    return secure_function


@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    return response


@app.route('/account')
@checkif_loggedin
def acc_check():

    if 'username' in session:

        return render_template('library.html',
                               account=session['username'].upper())
    else:
        return redirect(url_for('login'))


@app.route('/home')
def index():
    if 'username' in session:
        return render_template('library.html',
                               account=session['username'].upper())
    else:
        return render_template('home.html', account="Log In")


@app.route('/login', methods=['POST', 'GET'])
def login():
    if request.method == 'POST':
        users = db['UserInfo']
        login_user = users.find_one({'username': request.form['username']})

        # if the user exists in the database
        if login_user:
            if bcrypt.check_password_hash(
                    login_user['password'],
                    request.form.get('pass', False).encode('utf-8')):
                session['username'] = request.form['username']
                return redirect(url_for('index'))

            else:
                error = "The username or password that you have entered is incorrect."
                return render_template('login.html',
                                       account="Log In",
                                       error=error)
        else:
            error = "The username or password that you have entered is incorrect."
            return render_template('login.html', account="Log In", error=error)

    else:
        return render_template('login.html', account="Log In")


@app.route('/register', methods=['POST', 'GET'])
def register():

    if request.method == 'POST':
        # If the passwords match
        if request.form['pass'] == request.form['passconfirm']:
            users = db['UserInfo']
            existing_user = users.find_one(
                {'username': request.form['username']})

            # If there is no existing user with the same username
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
                    account="Log In",
                    comment='Your account was added successfully!')

            else:
                error = "The username that you entered already exists."
                return render_template('register.html',
                                       account="Log In",
                                       error=error)

        else:
            error = "The passwords you entered do not match."
            return render_template('register.html',
                                   account="Log In",
                                   error=error)

    else:
        return render_template('register.html',
                               account="Log In")


@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('index'))


@app.route('/store')
@checkif_loggedin
def store():
    return render_template('store.html', account=session['username'].upper())


@app.route('/profile')
@checkif_loggedin
def profile():
    global db
    user = db['UserInfo'].find_one({"username": session['username']})
    return render_template('profile.html',
                           account=session['username'].upper(),
                           username=user['username'],
                           prof=user['profilename'],
                           games=user['games'],
                           ngames=len(user['games']),
                           balance=user['balance'])


@app.route('/library')
@checkif_loggedin
def library():

    return render_template('library.html', account=session['username'].upper())


@app.route('/about')
def about():
    if 'username' in session:

        return render_template('about.html',
                               account=session['username'].upper(),
                               layout='layout')
    else:
        return render_template('about.html', account="Log In", layout='home')


@app.route('/accountsettings')
@checkif_loggedin
def acc_settings():

    return render_template('accountsettings.html',
                           account=session['username'].upper(),
                           elementID=1)


@app.route('/changeprofilename', methods=['POST', 'GET'])
@checkif_loggedin
def changeprofilename():

    if request.method == 'POST':
        userinfo = db['UserInfo']
        user = userinfo.find_one({"profilename": request.form['oldname']})

        if user:
            userinfo.update_one(
                {'username': session['username']},
                {"$set": {
                    "profilename": request.form['newname']
                }})

            return render_template(
                'accountsettings.html',
                account=session['username'].upper(),
                name_comment="New Profile Name set successfully!",
                elementID=1)

        else:
            return render_template(
                'accountsettings.html',
                account=session['username'].upper(),
                name_error="The Old Profile Name is incorrect.",
                elementID=1)


@app.route('/changeusername', methods=['POST', 'GET'])
@checkif_loggedin
def changeusername():

    if request.method == 'POST':
        userinfo = db['UserInfo']
        user = userinfo.find_one({"username": request.form['oldusername']})

        if user:
            existing_user = userinfo.find_one(
                {"username": request.form['newusername']})
            if existing_user:
                return render_template(
                    'accountsettings.html',
                    account=session['username'].upper(),
                    uname_error="The New Username already exists!")
            else:
                userinfo.update_one(
                    {'username': request.form['oldusername']},
                    {"$set": {
                        "username": request.form['newusername']
                    }})
                session['username'] = request.form['newusername']

                return redirect(url_for('logout'))

        else:
            return render_template(
                'accountsettings.html',
                account=session['username'].upper(),
                uname_error="The Old username is incorrect.",
                elementID=2)


@app.route('/changepassword', methods=['POST', 'GET'])
@checkif_loggedin
def changepassword():

    if request.method == 'POST':
        userinfo = db['UserInfo']
        user = userinfo.find_one({'username': session['username']})

        if user:
            if bcrypt.check_password_hash(
                    user['password'],
                    request.form.get('oldpass', False).encode('utf-8')):
                hashpass = bcrypt.generate_password_hash(
                    request.form['newpass'].encode('utf-8'))
                userinfo.update_one({'username': user['username']},
                                    {"$set": {
                                        'password': hashpass
                                    }})

                return redirect(url_for('logout'))

            else:
                return render_template(
                    'accountsettings.html',
                    account=session['username'].upper(),
                    pass_error="The Old password is incorrect.",
                    elementID=3)


@app.route('/deleteaccount', methods=['POST', 'GET'])
@checkif_loggedin
def deleteaccount():

    if request.method == 'POST':
        userinfo = db['UserInfo']

        if request.form['username'] == session['username']:
            user = userinfo.find_one({"username": request.form['username']})
            if user:
                userinfo.remove({'username': request.form['username']})
                return redirect(url_for('logout'))

            else:
                return render_template('accountsettings.html',
                                       account=session['username'].upper(),
                                       del_error="The Username is incorrect.",
                                       elementID=4)

        else:
            return render_template('accountsettings.html',
                                   account=session['username'].upper(),
                                   del_error="The Username is incorrect.",
                                   elementID=4)


if __name__ == '__main__':
    app.config['SESSION_TYPE'] = 'mongodb'
    app.run(debug=True)
