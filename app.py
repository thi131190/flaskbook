from flask_sqlalchemy import SQLAlchemy
from flask import Flask
from flask_login import UserMixin, LoginManager, login_required, login_user, logout_user, current_user

app = Flask(__name__)
app.config['SECRET_KEY'] = 'thisissecret'
app.config['SEND_FILE_MAX_AGE_DEFAULT'] = 0
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///flaskbook.db'

db = SQLAlchemy(app)

login_manager = LoginManager(app)

if __name__ == "__main__":
    app.run(debug=True)
