from flask import Flask, render_template, request, redirect, session, flash
from flask_sqlalchemy import SQLAlchemy
import os

app = Flask(__name__)


app.secret_key = os.environ.get("SECRET_KEY", "secureiot123")


database_url = os.environ.get("DATABASE_URL")


if database_url and database_url.startswith("postgres://"):
    database_url = database_url.replace("postgres://", "postgresql://", 1)

app.config["SQLALCHEMY_DATABASE_URI"] = database_url
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)




class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    fullname = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)


class Device(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    device_name = db.Column(db.String(100))
    device_type = db.Column(db.String(100))
    ip_address = db.Column(db.String(100))
    status = db.Column(db.String(50))


class SecurityLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    event = db.Column(db.String(200))
    level = db.Column(db.String(50))


# Create tables
with app.app_context():
    if database_url:
        db.create_all()




@app.route("/")
def home():
    return render_template("index.html")




@app.route("/register", methods=["GET", "POST"])
def register():

    if request.method == "POST":

        fullname = request.form["fullname"]
        email = request.form["email"]
        password = request.form["password"]

        check = User.query.filter_by(email=email).first()

        if check:
            flash("Email Already Exists")
            return redirect("/register")

        new_user = User(
            fullname=fullname,
            email=email,
            password=password
        )

        db.session.add(new_user)

        db.session.add(
            SecurityLog(
                event=f"New User Registered : {fullname}",
                level="INFO"
            )
        )

        db.session.commit()

        flash("Registration Successful")
        return redirect("/login")

    return render_template("register.html")




@app.route("/login", methods=["GET", "POST"])
def login():

    if request.method == "POST":

        email = request.form["email"]
        password = request.form["password"]

        user = User.query.filter_by(
            email=email,
            password=password
        ).first()

        if user:

            session["user"] = user.fullname

            db.session.add(
                SecurityLog(
                    event=f"{user.fullname} Logged In",
                    level="INFO"
                )
            )

            db.session.commit()

            return redirect("/dashboard")

        flash("Invalid Email or Password")

    return render_template("login.html")




@app.route("/dashboard")
def dashboard():

    if "user" not in session:
        return redirect("/login")

    device_count = Device.query.count()

    online_count = Device.query.filter_by(
        status="Online"
    ).count()

    offline_count = Device.query.filter_by(
        status="Offline"
    ).count()

    log_count = SecurityLog.query.count()

    recent_logs = SecurityLog.query.order_by(
        SecurityLog.id.desc()
    ).limit(5).all()

    return render_template(
        "dashboard.html",
        name=session["user"],
        device_count=device_count,
        online_count=online_count,
        offline_count=offline_count,
        log_count=log_count,
        recent_logs=recent_logs
    )




@app.route("/devices")
def devices():

    if "user" not in session:
        return redirect("/login")

    devices = Device.query.all()

    return render_template(
        "devices.html",
        devices=devices
    )




@app.route("/add_device", methods=["GET", "POST"])
def add_device():

    if "user" not in session:
        return redirect("/login")

    if request.method == "POST":

        device = Device(
            device_name=request.form["device_name"],
            device_type=request.form["device_type"],
            ip_address=request.form["ip_address"],
            status=request.form["status"]
        )

        db.session.add(device)

        db.session.add(
            SecurityLog(
                event=f"Device Added : {device.device_name}",
                level="INFO"
            )
        )

        db.session.commit()

        flash("Device Added Successfully")

        return redirect("/devices")

    return render_template("add_device.html")




@app.route("/delete_device/<int:id>")
def delete_device(id):

    if "user" not in session:
        return redirect("/login")

    device = Device.query.get(id)

    if device:

        db.session.add(
            SecurityLog(
                event=f"Device Deleted : {device.device_name}",
                level="WARNING"
            )
        )

        db.session.delete(device)

        db.session.commit()

    return redirect("/devices")




@app.route("/security_logs")
def security_logs():

    if "user" not in session:
        return redirect("/login")

    logs = SecurityLog.query.order_by(
        SecurityLog.id.desc()
    ).all()

    return render_template(
        "security_logs.html",
        logs=logs
    )



@app.route("/threat_detection")
def threat_detection():

    if "user" not in session:
        return redirect("/login")

    threats = []

    devices = Device.query.all()

    for device in devices:

        if device.status == "Offline":

            threats.append(
                f"{device.device_name} ({device.ip_address}) is Offline"
            )

    return render_template(
        "threat_detection.html",
        threats=threats
    )




@app.route("/logout")
def logout():

    session.clear()

    flash("Logged Out Successfully")

    return redirect("/")



@app.route("/about")
def about():
    return render_template("about.html")



if __name__ == "__main__":
    app.run(debug=True)
