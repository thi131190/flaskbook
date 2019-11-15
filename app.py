from flask_sqlalchemy import SQLAlchemy
from flask import Flask, render_template, request, flash, redirect, url_for
from flask_login import UserMixin, LoginManager, login_required, login_user, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config['SECRET_KEY'] = 'thisissecret'
app.config['SEND_FILE_MAX_AGE_DEFAULT'] = 0
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///flaskbook.db'

db = SQLAlchemy(app)


class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(20), nullable=False, unique=True)
    email = db.Column(db.String(50), nullable=False, unique=True)
    password = db.Column(db.String(255), nullable=False)

    def generate_password(self, password):
        self.password = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password, password)


class Post(db.Model):
    __tablename__ = 'posts'
    id = db.Column(db.Integer, primary_key=True)
    body = db.Column(db.String, nullable=False)
    user_id = db.Column(db.Integer, nullable=False)
    created_at = db.Column(db.DateTime, server_default=db.func.now())
    updated_at = db.Column(
        db.DateTime, server_default=db.func.now(), server_onupdate=db.func.now())


class Comment(db.Model):
    __tablename__ = 'comments'
    id = db.Column(db.Integer, primary_key=True)
    body = db.Column(db.String, nullable=False)
    user_id = db.Column(db.Integer, nullable=False)
    post_id = db.Column(db.Integer, nullable=False)
    created_at = db.Column(db.DateTime, server_default=db.func.now())
    updated_at = db.Column(
        db.DateTime, server_default=db.func.now(), server_onupdate=db.func.now())


db.create_all()


login_manager = LoginManager(app)


@login_manager.user_loader
def load_user(id):
    return User.query.get(id)


login_manager.login_view = 'login'


@app.route('/')
def root():
    return render_template('views/index.html')


@app.route('/register', methods=['POST', 'GET'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('root'))
    if request.method == 'POST':
        check_email = User.query.filter_by(email=request.form['email']).first()
        if check_email:
            flash('Email already taken', 'warning')
            return redirect(url_for('register'))
        new_user = User(name=request.form['name'],
                        email=request.form['email'])
        new_user.generate_password(request.form['password'])
        db.session.add(new_user)
        db.session.commit()
        login_user(new_user)
        flash('Successfully create an account and logged in', 'success')
        return redirect(url_for('root'))
    return render_template('views/register.html')


@app.route('/login', methods=['POST', 'GET'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('root'))
    if request.method == 'POST':
        user = User.query.filter_by(email=request.form['email']).first()
        if not user:
            flash('Email is not registered', 'warning')
            return redirect(url_for('register'))
        if user.check_password(request.form['password']):
            login_user(user)
            flash(f'Welcome back {current_user.name} !', 'success')
            return redirect(url_for('root'))
        flash('wrong password or email', 'warning')
        return redirect(url_for('login'))
    return render_template('views/login.html')


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


if __name__ == "__main__":
    app.run(debug=True)
