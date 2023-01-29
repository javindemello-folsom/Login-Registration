from flask import Flask, render_template, request, redirect, session, flash
from flask_app import app
from flask_app.models.user_model import User
from flask_bcrypt import Bcrypt
bcrypt = Bcrypt(app)


@app.route('/')
def index():
    return render_template("index.html")


@app.route('/register', methods=["POST"])
def register():
    if not User.validate_user(request.form):
        return redirect('/')

    pw_hash = bcrypt.generate_password_hash(request.form['password'])
    print(pw_hash)
    
    data = {
        "fname": request.form['fname'],
        "lname": request.form['lname'],
        "email": request.form['email'],
        "password" : pw_hash
    }
    user_id = User.save(data)
    session['user_id'] = user_id 
    session['fname'] = data['fname']
    session['logged_in'] = True
    
    return redirect("/dashboard")


@app.route('/login', methods=["POST"])
def login():
    # see if the username provided exists in the database
    data = { "email" : request.form["email"] }
    user_in_db = User.get_by_email(data)
    # user is not registered in the db
    if not user_in_db:
        flash(u"Invalid Email/Password","login")
        return redirect("/")
    if not bcrypt.check_password_hash(user_in_db.password, request.form['password']):
        # if we get False after checking the password
        flash(u"Invalid Email/Password","login")
        return redirect('/')
    # if the passwords matched, we set the user_id into session
    session['user_id'] = user_in_db.id
    session['fname'] = user_in_db.first_name
    # never render on a post!!!
    session['logged_in'] = True
    return redirect("/dashboard")


@app.route('/dashboard')
def dashboard():
    print(session['logged_in'])
    if session['logged_in'] == False:
        return redirect('/')
    return render_template('dashboard.html')


@app.route('/logout', methods=["POST"])
def logout():
    session.clear
    session['logged_in'] = False
    return redirect('/')