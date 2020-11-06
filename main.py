from flask import Flask, render_template, url_for, request, session, redirect
from flask_bcrypt import Bcrypt
from flask_pymongo import pymongo
import bcrypt
import os



CONNECTION_STRING = os.environ.get("MONGO_KEY")
client = pymongo.MongoClient(CONNECTION_STRING)
db = client['GameRampStore']

app = Flask(__name__)
bcrypt = Bcrypt(app)

@app.route('/')
def index():
    if 'username' in session: 
        session.clear()
        return render_template('loggedin.html')

    return render_template('login.html')

@app.route('/login', methods=['POST'])
def login():
    users = db['UserInfo']
    login_user = users.find_one({'username':request.form['username']})

    if login_user:
        if bcrypt.check_password_hash(login_user['password'], request.form['pass'].encode('utf-8')):            
            session['username'] = request.form['username']
            return redirect(url_for('index'))

    error = "The username or password that you have entered is incorrect."
    return render_template('login.html', error = error)

@app.route('/register', methods=['POST', 'GET'])
def register():
    if request.method == 'POST':
        if request.form['pass'] == request.form['passconfirm']:
            users = db['UserInfo']
            existing_user = users.find_one({'username':request.form['username']})

            if existing_user is None:
                hashpass = bcrypt.generate_password_hash(request.form['pass'].encode('utf-8'))
                users.insert({'username' : request.form['username'], 'password' : hashpass})
                # session['username'] = request.form['username']
                return redirect(url_for('index'))
            
            else:
                error = "The username that you entered already exists."    
                return render_template('register.html', error = error)

        error = "The passwords you entered do not match."    
        return render_template('register.html', error = error)
    else:
        return render_template('register.html')


# @app.route('/logout')
# def logout():
#     session.pop('username',None)
#     return redirect(url_for('index'))

if __name__ == '__main__':
    app.secret_key = 'mysecret'
    app.config['SESSION_TYPE'] = 'mongodb'
    app.run(debug=True)