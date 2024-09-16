from flask import Flask, render_template, redirect, url_for, flash, get_flashed_messages
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, IntegerField, PasswordField
from wtforms.validators import Length, DataRequired, ValidationError, Regexp, NumberRange, EqualTo
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///app.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = '7376c6a415dd1a2068605e5c'
bcrypt = Bcrypt(app)
db = SQLAlchemy(app)
login_manager = LoginManager(app)

class RegisterForm(FlaskForm):
    def validate_name(self, name_to_check):
        name = Item.query.filter_by(name=name_to_check.data).first()
        if name:
            raise ValidationError('Name Already Exists')

    def validate_rollno(self, rollno_to_check):
        rollno = Item.query.filter_by(rollno=rollno_to_check.data).first()
        if rollno:
            raise ValidationError('Roll Number Already Exists')

    name = StringField(
        label='Name',
        validators=[
            Length(min=3, max=50),
            DataRequired(),
            Regexp('^[A-Za-z ]*$', message="Name must contain only letters and spaces.")
        ]
    )
    age = IntegerField(label='Age', validators=[DataRequired()])
    rollno = IntegerField(label='Roll Number', validators=[DataRequired()])
    contact = IntegerField(label='Contact', validators=[NumberRange(min=1, max=10000000000), DataRequired()])
    submit = SubmitField(label='Submit')

class LoginForm(FlaskForm):
    username = StringField(validators=[DataRequired()])
    password = PasswordField(validators=[DataRequired()])
    submit = SubmitField(label='Login')

class UserRegisterForm(FlaskForm):
    def validate_username(self, username_to_check):
        username = User.query.filter_by(username=username_to_check.data).first()
        if username:
            raise ValidationError('Username Already Exists')

    def validate_email_address(self, email_address_to_check):
        email_address = User.query.filter_by(email_address=email_address_to_check.data).first()
        if email_address:
            raise ValidationError('Email Already Exists')

    username = StringField(
        label='Username',
        validators=[Length(min=3, max=30), DataRequired()]
    )
    email_address = StringField(
        label='Email',
        validators=[Length(min=6, max=50), DataRequired()]
    )
    password = PasswordField(
        label='Password',
        validators=[Length(min=8), DataRequired()]
    )
    confirm_password = PasswordField(
        label='Confirm Password',
        validators=[EqualTo('password', message="Passwords must be the same"), DataRequired()]
    )
    submit = SubmitField(label='Register')

class Item(db.Model):
    sno = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String, nullable=False)
    age = db.Column(db.Integer, nullable=False)
    rollno = db.Column(db.Integer, nullable=False, unique=True)  # Changed to Integer
    contact = db.Column(db.String, nullable=False)
    owner = db.Column(db.Integer, db.ForeignKey('user.id'))

    def __repr__(self):
        return f"Item {self.name}"

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(length=30), nullable=False, unique=True)
    email_address = db.Column(db.String(length=50), nullable=False, unique=True)
    password_hash = db.Column(db.String(length=60), nullable=False)
    items = db.relationship('Item', backref='owned_user', lazy=True)

    @property
    def password(self):
        raise AttributeError('Password is not a readable attribute.')

    @password.setter
    def password(self, plain_text_password):
        self.password_hash = bcrypt.generate_password_hash(plain_text_password).decode('utf-8')

    def check_password_correction(self, attempted_password):
        return bcrypt.check_password_hash(self.password_hash, attempted_password)


@app.route('/')
def home():
    return render_template('home.html')

@app.route('/member')
def member():
    items = Item.query.all()
    return render_template('member.html', items=items)

@app.route('/addmember', methods=['GET', 'POST'])
def add_member():
    form = RegisterForm()
    if form.validate_on_submit():
        item_to_create = Item(name=form.name.data,
                              age=form.age.data,
                              rollno=form.rollno.data,
                              contact=form.contact.data)
        db.session.add(item_to_create)
        db.session.commit()
        flash('YOU ARE A MEMBER OF KT GANG', 'success')
        return redirect(url_for('member'))

    if form.errors != {}:
        for err_msg in form.errors.values():
            flash(f'There was an error: {err_msg}', category='danger')

    return render_template('addmember.html', form=form)

@app.route('/kick/<int:sno>', methods=['POST'])
def kick(sno):
    item_to_delete = Item.query.get_or_404(sno)
    db.session.delete(item_to_delete)
    db.session.commit()
    flash(f'{item_to_delete.name} has been Kicked.', 'success')
    return redirect(url_for('member'))

@app.route('/register', methods=['GET', 'POST'])
def register_user():
    form = UserRegisterForm()
    if form.validate_on_submit():
        user_to_create = User(
            username=form.username.data,
            email_address=form.email_address.data,
            password=form.password.data
        )
        db.session.add(user_to_create)
        db.session.commit()
        flash('Account Created Successfully', 'success')
        return redirect(url_for('home'))

    if form.errors != {}:
        for err_msg in form.errors.values():
            flash(f'There was an error: {err_msg}', 'danger')

    return render_template('register.html', form=form)


@app.route('/login', methods=['GET', 'POST'])
def login_user():
    form = LoginForm()
    if form.validate_on_submit():
        attempted_user = User.query.filter_by(username=form.username.data).first()
        if attempted_user and attempted_user.check_password_correction(attempted_password=form.password.data):
            login_user(attempted_user)  # Calls the Flask-Login login_user function
            flash(f'You are successfully logged in as: {attempted_user.username}', 'success')
            return redirect(url_for('member'))
        else:
            flash('Username and Password do not match. Please try again.', 'danger')
    return render_template('login.html', form=form)

if __name__ == '__main__':
    app.run(debug=True)
