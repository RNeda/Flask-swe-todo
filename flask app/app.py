from flask import Flask, render_template, url_for, request, redirect, flash
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from flask_login import LoginManager, login_user, login_required, logout_user, UserMixin, current_user
from wtforms import StringField, PasswordField, SubmitField, EmailField
from wtforms.validators import InputRequired, Length, Email,EqualTo
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import os 

file_path = os.path.abspath(os.getcwd())+"/baza.db" 

app = Flask(__name__)
app.config['SECRET_KEY'] = 'tajna_lozinka'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///'+file_path 
db = SQLAlchemy(app)


#Inicijalizacija login managera
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


#Modeli
class Todo(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.String(200), nullable=False)
    date_created = db.Column(db.DateTime, default=datetime.now) 
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    def __repr__(self):
        return '<Task %r>' % self.id

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    tasks = db.relationship('Todo', backref='author', lazy=True)

    def __repr__(self):
        return '<user %r>' % self.id


#Forme
#Register forma
class RegisterForm(FlaskForm):
    username = StringField('Username', validators=[InputRequired(), Length(min=4, max=25)])
    email = EmailField('Email', validators=[InputRequired(), Email()])
    password = PasswordField('Password', validators=[InputRequired(), Length(min=4)])
    confirm_password = PasswordField('Confirm Password', validators=[
        InputRequired(), EqualTo('password', message='Passwords must match')
    ])
    submit = SubmitField('Register')

#Login forma
class LoginForm(FlaskForm):
    email = EmailField('Email', validators=[InputRequired(), Email()])
    password = PasswordField('Password', validators=[InputRequired()])
    submit = SubmitField('Login')

#Login loader
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


#Rute
@app.route('/', methods=['POST', 'GET'])
def hellopage():
    return render_template('hellopage.html')

#Prikaz to-do liste
@app.route('/index', methods=['POST', 'GET'])
@login_required
def index():
    tasks = []
    if request.method == 'POST':
        task_content = request.form['content']
        new_task = Todo(content=task_content, user_id=current_user.id)

        try:
            db.session.add(new_task)
            db.session.commit()
            return redirect(url_for('index'))
        except:
            return 'There was an issue adding your task'

    else:
        tasks = Todo.query.filter_by(user_id=current_user.id).order_by(Todo.date_created).all()
        return render_template('index.html', tasks=tasks)

#Obrisi iz liste
@app.route('/delete/<int:id>')
def delete(id):
    task_to_delete = Todo.query.get_or_404(id)

    try:
        db.session.delete(task_to_delete)
        db.session.commit()
        return redirect(url_for('index'))
    except:
        return 'There was a problem deleting that task'

#Update u listi
@app.route('/update/<int:id>', methods=['GET', 'POST'])
def update(id):
    task = Todo.query.get_or_404(id)

    if request.method == 'POST':
        task.content = request.form['content']

        try:
            db.session.commit()
            return redirect(url_for('index'))
        except:
            return 'There was an issue updating your task'

    else:
        return render_template('update.html', task=task)

#Registracija
@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        if User.query.filter_by(email=form.email.data).first():
            flash('Email already in use.')
            return redirect(url_for('register'))
        hashed_password = generate_password_hash(form.password.data)
        new_user = User(
            username=form.username.data,
            email=form.email.data,
            password=hashed_password
        )
        db.session.add(new_user)
        db.session.commit()
        flash('Registration successful! Please log in.')
        return redirect(url_for('login'))
    return render_template('register.html', form=form)

#Login
@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and check_password_hash(user.password, form.password.data):
            login_user(user)
            return redirect(url_for('index'))  
        flash('Invalid email or password.')
    return render_template('login.html', form=form)

#Logout
@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.')
    return redirect(url_for('hellopage'))

if(__name__) == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True)