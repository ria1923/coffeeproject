import os
import time

from flask import Flask, render_template, redirect, url_for, request, flash, send_from_directory, send_file, session
from flask_login import UserMixin, LoginManager, login_required, current_user, logout_user, login_user
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///coffeevending.db'
db = SQLAlchemy()
db.init_app(app)
app.config['SECRET_KEY'] = '8BYkEfBA105donzWlSihBXox7C0sKR6b'

login_manager = LoginManager()
login_manager.init_app(app)


@login_manager.user_loader
def load_user(user_id):
    return db.get_or_404(User, user_id)


class User(UserMixin, db.Model):
    id = db.Column(db.INTEGER, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    email = db.Column(db.String(100), nullable=False)
    password = db.Column(db.String(100), nullable=False)


class Coffee(db.Model):
    coffee_id = db.Column(db.INTEGER, primary_key=True)
    coffee_name = db.Column(db.String(30), nullable=False)
    milk_required_ml = db.Column(db.INTEGER, nullable=False)
    coffee_require_ml = db.Column(db.INTEGER, nullable=False)
    water_required_ml = db.Column(db.INTEGER, nullable=False)
    amount = db.Column(db.INTEGER, nullable=False)


class Resources(db.Model):
    resource_id = db.Column(db.INTEGER, primary_key=True)
    milk_stock = db.Column(db.INTEGER, nullable=False)
    coffee_powder_stock = db.Column(db.INTEGER, nullable=False)
    water_stock = db.Column(db.INTEGER, nullable=False)
    wallet = db.Column(db.INTEGER, nullable=False)


with app.app_context():
    db.create_all()


@app.route("/")
def index():
    logout_user()
    return render_template("index.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        user = User.query.filter_by(username=username).first()

        if user and check_password_hash(user.password, password):
            flash('Login successful!', 'success')
            login_user(user)
            return redirect(url_for('home'))
        else:
            flash('Invalid username or password. Please try again.', 'error')
        # return render_template('login.html')

    return render_template('login.html')


@app.route("/logout")
def logout():
    logout_user()
    return redirect(url_for("index"))


@app.route("/signup", methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form.get("username")
        email = request.form.get("email")
        passw = request.form.get("password")
        existing_user = User.query.filter((User.username == username) | (User.email == email)).first()
        if existing_user:
            flash('Username or email already taken', 'error')
        else:
            hashed_pass = generate_password_hash(passw, method="pbkdf2:sha256", salt_length=8)
            new_user = User(username=username, password=hashed_pass, email=email)
            db.session.add(new_user)
            db.session.commit()
            login_user(new_user)
            return redirect(url_for("home"))
    return render_template("signup.html")


@app.route("/home")
@login_required
def home():
    return render_template("home.html", name=current_user.username)


def has_enough_resources(coffee_name):
    coffee_resources = db.session.query(Coffee).filter_by(coffee_name=coffee_name).first()

    if coffee_resources:
        available_resources = db.session.query(Resources).first()

        # Check if there are enough resources
        if (
                available_resources.milk_stock >= coffee_resources.milk_required_ml and
                available_resources.coffee_powder_stock >= coffee_resources.coffee_require_ml and
                available_resources.water_stock >= coffee_resources.water_required_ml
        ):
            return True
        else:
            return False


@app.route("/coffee", methods=['GET', 'POST'])
@login_required
def coffee():
    if request.method == 'POST':
        coffee = request.form.get('coffee_type')

        if coffee == 'Espresso':
            return redirect(url_for('Espresso'))
        elif coffee == 'Cappuccino':
            return redirect(url_for('Cappuccino'))
        elif coffee == 'Latte':
            return redirect(url_for("Latte"))
    return render_template("home.html")


check = 0


@app.route("/espresso")
@login_required
def Espresso():
    coffee_name = 'Espresso'
    if has_enough_resources(coffee_name):
        session['coffee_name'] = coffee_name
        return redirect(url_for("payment"))
    else:
        return render_template("restock.html")


@app.route("/latte")
@login_required
def Latte():
    coffee_name = 'Latte'
    if has_enough_resources(coffee_name):
        session['coffee_name'] = coffee_name
        return redirect(url_for("payment"))
    else:
        return render_template("restock.html")

@app.route("/cappuccino")
@login_required
def Cappuccino():
    coffee_name = 'Cappuccino'
    if has_enough_resources(coffee_name):
        session['coffee_name'] = coffee_name
        return redirect(url_for("payment"))
    else:
        return render_template("restock.html")


def update_resources(coffee_name):
    coffee = Coffee.query.filter_by(coffee_name=coffee_name).first()
    resources = Resources.query.first()

    if coffee and resources:
        if resources.milk_stock > 0 and resources.water_stock > 0 and resources.coffee_powder_stock > 0:
            resources.milk_stock -= coffee.milk_required_ml
            resources.coffee_powder_stock -= coffee.coffee_require_ml
            resources.water_stock -= coffee.water_required_ml
            resources.wallet += coffee.amount
            db.session.commit()
            return True
        else:
            return "Restock required"


@app.route("/payment", methods=['GET', 'POST'])
@login_required
def payment():
    if request.method == 'POST':
        coffee_name = session.get('coffee_name')
        quarter = request.form.get('quarter')
        dime = request.form.get('dime')
        nickel = request.form.get('nickel')
        penny = request.form.get('penny')
        total_amount_inserted = (int(quarter) * 0.25) + (int(dime) * 0.10) + (int(nickel) * 0.05) + (int(penny) * 0.01)
        coffee = Coffee.query.filter_by(coffee_name=coffee_name).first()
        change = 0
        if total_amount_inserted > coffee.amount:
            change = total_amount_inserted - coffee.amount
        elif total_amount_inserted < coffee.amount:
            short = coffee.amount - total_amount_inserted
            return render_template("payment.html", short=short)
        if update_resources(coffee_name):
            session['change'] = change
            session[coffee_name] = coffee_name
            return redirect(url_for("success"))
    return render_template("payment.html")


@app.route("/pass")
def report():
    password = request.args.get('pass')
    if password == 'report':
        resources = Resources.query.first()
        amount = resources.wallet
        milk = resources.milk_stock
        water = resources.water_stock
        coffee = resources.coffee_powder_stock

        return render_template("report.html", coffee=coffee, water=water, amount=amount, milk=milk)


@app.route("/success")
@login_required
def success():
    coffee_name = session.get('coffee_name')
    # time.sleep(2)
    change = session.get('change')
    if change == 0:
        money_change = False
    else:
        money_change = True
    return render_template('success.html', coffeename=coffee_name, change=change, user=current_user.username,
                           money_change=money_change)
system_turned_off = False
@app.route('/turn_off', methods=['GET'])
def turn_off():
    global system_turned_off
    # Check if the provided parameter is 'turnoff'
    turnoff_param = request.args.get('action')

    if turnoff_param == 'turnoff':
        system_turned_off = True
        return render_template("turned_off.html")
    else:

        return redirect(url_for("login"))

if __name__ == "__main__":
    app.run(debug=True, port=5000)
