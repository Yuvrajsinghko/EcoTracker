from urllib import response
from flask import (
    Flask,
    flash,
    redirect,
    render_template,
    request,
    session,
    url_for,
    make_response,
)
import pymysql
from functools import wraps
from datetime import date, datetime
import time
import uuid
import re
from werkzeug.security import generate_password_hash, check_password_hash

EMAIL_REGEX = re.compile(r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,63}$")
PHONE_REGEX = re.compile(
    r"^(?!(\d)\1{9}$)"
    r"(?!1234567890$)"
    r"(?!9876543210$)"
    r"(?!9898989898$)"
    r"(?!7878787878$)"
    r"(?!5656565656$)"
    r"(?!1212121212$)"
    r"(?!2323232323$)"
    r"(?!4545454545$)"
    r"(?!6767676767$)"
    r"(?!8989898989$)"
    r"(?![6-9]0{9}$)"
    r"[6-9][0-9]{9}$"
)

app = Flask(__name__)

app.config.update(
    SESSION_COOKIE_SECURE=False,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax'
)


db = pymysql.connections.Connection(
    host="localhost",
    user="yuvraj",
    password="root69",
    database="greendb",
    cursorclass=pymysql.cursors.DictCursor,
)


app.secret_key = "secretkey"

INACTIVITY_LIMIT = 300


@app.before_request
def enforce_session_rules():
    
    if request.endpoint in ("login", "signup", "submit", "register", "static"):
        return None

    username = session.get("username")
    token = session.get("session_token")
    user_id = session.get("user_id")

    if not username or not token or not user_id:
        return redirect(url_for("login"))
    cursor = db.cursor()
    try:

        cursor.execute(
            "SELECT active_session, last_active FROM SignupDetails WHERE id = %s",(
                user_id,
            )
        )

        user = cursor.fetchone()

        if not user:
            session.clear()
            return redirect(url_for("login"))
        # Enforce single-session
        if not user["active_session"] or user["active_session"] != token:
            session.clear()
            flash("You were logged out because you logged in from another device.")
            return redirect(url_for("login"))

        # Enforce inactivity
        if user["last_active"]:
            current_time = datetime.now()
            last_active = user["last_active"]
            elapsed_time = (current_time - last_active).total_seconds()
            if elapsed_time > INACTIVITY_LIMIT:
                cursor.execute(
                    "UPDATE SignupDetails SET active_session = NULL,last_active = NULL WHERE id = %s",
                    (user_id,),
                )
                db.commit()
                session.clear()
                flash("You were logged out due to inactivity")
                return redirect(url_for("login"))
        # Update last active
        cursor.execute(
            "UPDATE SignupDetails SET last_active = %s WHERE id = %s",(datetime.now(),
                user_id,
            )
        )
        db.commit()
    
    except Exception as e:
        print(f"Session validation error: {e}")
        session.clear()
        return redirect(url_for("login"))
    finally:
        cursor.close()


@app.route("/")
def login():
    return render_template("Login.html")


@app.route("/signup")
def signup():
    return render_template("Signup.html")


@app.route("/submit", methods=["POST"])
def submit():

    username = request.form.get("username")
    password = request.form.get("password")

    if not username or not password:
        flash("Please provide both username and password", "danger")
        return render_template("Login.html")
    cursor = db.cursor()
    try:
        cursor.execute(
            "SELECT id,user_password,active_session FROM SignupDetails WHERE username = %s",
            (username,),
        )
        user = cursor.fetchone()

        if user and check_password_hash(user["user_password"], password):
            # Always generate new token only ON login (not refresh)
            session_token = str(uuid.uuid4())
            cursor.execute(
                "UPDATE SignupDetails SET active_session = %s, last_active = %s WHERE id = %s",
                (session_token, datetime.now(), user["id"]),
            )
            db.commit()

            
            session.clear()
            session["username"] = username
            session["session_token"] = session_token
            session["user_id"] = user["id"]
            return render_template("success.html")

        else:

            flash("Invalid username or password", "danger")
            return render_template("Login.html")

    except Exception as e:
        print(f"Login error: {e}")
        flash("An error occurred during login", "danger")
        return render_template("Login.html")
    finally:
        cursor.close()
@app.route("/register", methods=["POST"])
def register():
    cursor = db.cursor()
    name = request.form.get("name")
    email = request.form.get("email")
    user_phone_no = request.form.get("phone")
    age = request.form.get("age")
    gender = request.form.get("gender")
    password = request.form.get("password")

    u_sername = request.form.get("username")
    confirm_password = request.form.get("confirmPassword")

    hashed_password = generate_password_hash(
        password, method="pbkdf2:sha256", salt_length=16
    )

    errors = []

    cursor.execute(
        "SELECT username FROM SignupDetails WHERE username = %s", (u_sername,)
    )
    user = cursor.fetchone()

    if user:
        flash("Username already exist", "danger")
        return redirect(url_for("signup"))
    else:
        if not (4 <= len(name) <= 16):
            errors.append("Name must be 4-16 characters long.")

        if not EMAIL_REGEX.fullmatch(email):
            errors.append("Invalid email address")

        if not PHONE_REGEX.fullmatch(user_phone_no):
            errors.append("Invalid phone number")

        try:
            age_val = int(age)
            if not (18 <= age_val <= 90):
                errors.append("Age must be between 18 and 90.")
        except ValueError:
            errors.append("Invalid Age")

        if gender not in ["Male", "Female", "Other"]:
            errors.append("Please select a valid gender.")

        if not (8 <= len(u_sername) <= 12):
            errors.append("Username must be 8-12 characters")

        password_regex = re.compile(
            r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,32}$"
        )

        if not password_regex.fullmatch(password):
            errors.append(
                "Password must be 8–12 chars, include uppercase, lowercase, number & special character."
            )

        if password != confirm_password:
            errors.append("Passwords do not match.")

        if errors:
            for error in errors:
                flash(error, "danger")
            return redirect(url_for("signup"))
        else:
            cursor.execute(
                "INSERT INTO SignupDetails (name,age,gender,username,email,phone_no,user_password,date_joined) VALUES(%s,%s,%s,%s,%s,%s,%s,%s)",
                (
                    name,
                    age,
                    gender,
                    u_sername,
                    email,
                    user_phone_no,
                    hashed_password,
                    date.today(),
                ),
            )
            db.commit()
            cursor.close()
            flash("Registration successful!", "success")
            return render_template("Login.html")


def calculate_green_points(carbon_score):

    if carbon_score <= 10:
        return 100  # Excellent
    elif carbon_score <= 20:
        return 75  # Good
    elif carbon_score <= 40:
        return 50  # Average
    else:
        return 25  # Needs improvement


def calculate_carbon_score(form_data):

    total_carbon = 0.0

    distance = float(form_data.get("commute_distance") or 0)

    mode = form_data.get("commute_mode", "")

    if mode == "Car":
        total_carbon += distance * 0.2
    elif mode == "Bike":
        total_carbon += distance * 0.1
    elif mode == "Public-Transport":
        total_carbon += distance * 0.08
    elif mode == "Train":
        total_carbon += distance * 0.04
    elif mode == "Flight":
        total_carbon += distance * 0.15 + 50
    # Walk / Cycle = 0
    else:
        total_carbon += 0

    # Work Location
    work_location = form_data.get("work_location", "")
    if work_location == "Home":
        total_carbon += 1
    elif work_location == "Office":
        total_carbon += 3
    elif work_location == "Travel":
        total_carbon += 5
    elif work_location == "Other":
        total_carbon += 2

    # Diet
    diet = form_data.get("diet", "")
    if diet == "Vegan":
        total_carbon += 1.5
    elif diet == "Vegetarian":
        total_carbon += 2.5
    elif diet == "Pescatarian":
        total_carbon += 3.5
    elif diet == "Non-Vegetarian":
        total_carbon += 4.8

    # Meal Source (workplace food choice)
    meal_source = form_data.get("meal_source", "")
    if meal_source == "Home-Packed":
        total_carbon += 1
    elif meal_source == "Office-Cafeteria":
        total_carbon += 2
    elif meal_source == "Local-Restaurant":
        total_carbon += 3
    elif meal_source == "Food-Delivery":
        total_carbon += 4
    elif meal_source == "Client-Catered":
        total_carbon += 2.5

    # Digital Intensity
    digital = form_data.get("digital_intensity", "")
    if digital == "Light":
        total_carbon += 0.5
    elif digital == "Moderate":
        total_carbon += 1
    elif digital == "Heavy":
        total_carbon += 2
    elif digital == "Intensive":
        total_carbon += 3
    # Printing Intensity
    printing = form_data.get("printing_level", "")
    if printing == "Minimal":
        total_carbon += 0.5
    elif printing == "Moderate":
        total_carbon += 1
    elif printing == "Heavy":
        total_carbon += 2

    return round(total_carbon, 2)


@app.route("/dailyentrypage", methods=["GET", "POST"])
def daily_user_entry():
    if request.method == "GET":
        username = session.get("username", None)

        if username:
            return render_template("daily_entry.html")
        else:

            return redirect(url_for("login"))

    else:
        username = session.get("username", None)
        if not username:
            return "Please log in first"

        cursor = db.cursor()
        cursor.execute("SELECT id FROM SignupDetails WHERE username = %s", (username,))
        id = cursor.fetchone()
        user_id = id["id"]

        carbon = calculate_carbon_score(request.form)

        reward_points = calculate_green_points(carbon)

        # Get form data
        work_location = request.form.get("work_location")
        vehicle_type = request.form.get("commute_mode")
        distance_travelled = request.form.get("commute_distance")
        diet_type = request.form.get("diet")
        food_source = request.form.get("meal_source")
        digital_intensity = request.form.get("digital_intensity")
        printing_done = request.form.get("printing_level")

        # Insert into detail tables and get the LAST INSERT IDs
        print("Checkpoint-1")
        cursor.execute(
            "INSERT INTO EmployeePoints(user_id,points_earned,date_earned)VALUES(%s,%s,%s)",
            (user_id, reward_points, date.today()),
        )

        employee_point_id = cursor.lastrowid

        cursor.execute(
            "INSERT INTO TransportDetails(user_id,mode_of_transport,distance_travelled,work_location) VALUES(%s,%s,%s,%s)",
            (user_id, vehicle_type, distance_travelled, work_location),
        )
        transport_id = cursor.lastrowid  # Get the ID of the just-inserted record

        cursor.execute(
            "INSERT INTO DietDetails(user_id,diet_type,food_source)VALUES(%s,%s,%s)",
            (user_id, diet_type, food_source),
        )
        diet_id = cursor.lastrowid

        cursor.execute(
            "INSERT INTO LifestyleHabits(user_id,digital_footprint,printing_today) VALUES(%s,%s,%s)",
            (user_id, digital_intensity, printing_done),
        )
        lifestyle_id = cursor.lastrowid

        print("Checkpoint-2")
        # Insert into DailyEntry using the specific IDs from this entry
        cursor.execute(
            "INSERT INTO DailyEntry(signup_ref_id,transport_ref_id,diet_ref_id,lifestyle_ref_id,user_point_id_ref ,carbon_score,date_of_entry) VALUES(%s,%s,%s,%s,%s,%s,%s)",
            (
                user_id,
                transport_id,
                diet_id,
                lifestyle_id,
                employee_point_id,
                carbon,
                date.today(),
            ),
        )

        db.commit()
        cursor.close()
        message = flash("Your daily entry has been added successfully")
        return render_template(
            "daily_entry_status.html", name=username, message=message
        )


@app.route("/success")
def registration_done():
    username = session.get("username", None)
    if not username:
        return render_template("Login.html")
    else:
        return render_template("success.html", name=username)


@app.route("/profile")
def profile():
    username = session.get("username", None)
    if not username:
        return render_template("Login.html")
    else:
        cursor = db.cursor()
        cursor.execute(
            "SELECT name,age,gender,username,phone_no,email,user_password,date_joined FROM SignupDetails WHERE username = %s",
            (username,),
        )
        user = cursor.fetchone()
        cursor.close()
    return render_template("profile.html", user=user)


@app.route("/entries_overview")
def entries_overview():
    username = session.get("username", None)
    if not username:
        return render_template("Login.html")
    else:
        cursor = db.cursor()
        cursor.execute("SELECT id FROM SignupDetails WHERE username = %s", (username,))
        user = cursor.fetchone()
        if not user:
            cursor.close()
            return render_template("Login.html")
        user_id = user["id"]

        cursor.execute(
            "SELECT d.daily_id,d.carbon_score,d.date_of_entry,e.points_earned FROM DailyEntry d  JOIN EmployeePoints e ON d.user_point_id_ref = e.emp_point_id  WHERE user_id = %s ORDER BY date_of_entry DESC",
            (user_id,),
        )
        entries = cursor.fetchall()
        cursor.close()

    return render_template("entries_overview.html", entries=entries)


@app.route("/entry/<int:entry_id>")
def view_single_entry(entry_id):
    cursor = db.cursor()
    cursor.execute(
        "SELECT d.*,t.mode_of_transport,t.distance_travelled,t.work_location,di.diet_type,di.food_source,l.digital_footprint,l.printing_today,e.points_earned FROM DailyEntry d JOIN "
        "TransportDetails t ON d.transport_ref_id = t.transport_id JOIN DietDetails di ON d.diet_ref_id = di.diet_id JOIN LifestyleHabits l ON d.lifestyle_ref_id = l.lifestyle_id JOIN EmployeePoints e ON d.user_point_id_ref = e.emp_point_id WHERE d.daily_id = %s",
        (entry_id,),
    )
    entry = cursor.fetchone()
    cursor.close()
    return render_template("view_entry.html", entry=entry)


@app.route("/entry/delete/<int:entry_id>")
def delete_entry(entry_id):
    cursor = db.cursor()
    cursor.execute("SELECT * FROM DailyEntry WHERE daily_id = %s", (entry_id,))
    daily_dict = cursor.fetchone()
    if not daily_dict:
        return redirect(url_for("entries_overview.html"))

    else:
        cursor.execute("DELETE FROM DailyEntry WHERE daily_id = %s", (entry_id,))

        cursor.execute(
            "DELETE FROM EmployeePoints WHERE emp_point_id = %s",
            (daily_dict["user_point_id_ref"]),
        )
        cursor.execute(
            "DELETE FROM TransportDetails WHERE transport_id = %s",
            (daily_dict["transport_ref_id"],),
        )
        cursor.execute(
            "DELETE FROM DietDetails WHERE diet_id = %s", (daily_dict["diet_ref_id"],)
        )
        cursor.execute(
            "DELETE FROM LifestyleHabits WHERE lifestyle_id = %s",
            (daily_dict["lifestyle_ref_id"],),
        )

    db.commit()
    cursor.close()

    return redirect(url_for("entries_overview"))


@app.route("/entry/edit/<int:entry_id>", methods=["GET", "POST"])
def edit_entry(entry_id):
    username = session.get("username", None)
    if not username:
        return render_template("Login.html")

    try:
        cursor = db.cursor()

        cursor.execute("SELECT id FROM SignupDetails WHERE username = %s", (username,))
        a = cursor.fetchone()
        user_id = a["id"]
        cursor.execute(
            "SELECT d.*,t.mode_of_transport,t.distance_travelled,t.work_location,di.diet_type,di.food_source,l.digital_footprint,l.printing_today,e.points_earned FROM DailyEntry d JOIN "
            "TransportDetails t ON d.transport_ref_id = t.transport_id JOIN DietDetails di ON d.diet_ref_id = di.diet_id JOIN LifestyleHabits l ON d.lifestyle_ref_id = l.lifestyle_id JOIN EmployeePoints e ON d.user_point_id_ref = e.emp_point_id WHERE d.daily_id = %s",
            (entry_id,),
        )
        entry = cursor.fetchone()
        if not entry:
            flash("Entry not found or access denied")
            return redirect(url_for("entries_overview"))
        if request.method == "GET":
            return render_template("edit_entry.html", entry=entry)

        carbon = calculate_carbon_score(request.form)
        reward_points = calculate_green_points(carbon)
        form_data = {
            "vehicle_type": request.form.get("commute_mode"),
            "work_location": request.form.get("work_location"),
            "distance_travelled": float(request.form.get("commute_distance", 0) or 0),
            "diet_type": request.form.get("diet"),
            "food_source": request.form.get("meal_source"),
            "digital_footprint": request.form.get("digital_intensity"),
            "printing_done": request.form.get("printing_level"),
            "carbon_score": carbon,
            "reward_points": reward_points,
        }

        cursor.execute(
            "UPDATE TransportDetails SET mode_of_transport=%s, distance_travelled=%s,work_location = %s WHERE transport_id=%s",
            (
                form_data["vehicle_type"],
                form_data["distance_travelled"],
                form_data["work_location"],
                entry["transport_ref_id"],
            ),
        )

        cursor.execute(
            "UPDATE DietDetails SET diet_type=%s, food_source=%s WHERE diet_id=%s",
            (
                form_data["diet_type"],
                form_data["food_source"],
                entry["diet_ref_id"],
            ),
        )
        cursor.execute(
            " UPDATE EmployeePoints SET points_earned = %s,date_earned = %s WHERE emp_point_id = %s",
            (form_data["reward_points"], date.today(), entry["user_point_id_ref"]),
        )

        cursor.execute(
            "UPDATE DailyEntry SET carbon_score=%s WHERE daily_id=%s",
            (form_data["carbon_score"], entry_id),
        )
        db.commit()
        cursor.close()
        flash("Entry updated successfully!", "success")

        return redirect(url_for("view_single_entry", entry_id=entry_id))
    except Exception as e:
        db.rollback()
        print(f"ERROR: {e}")
        flash("Failed to update entry", "error")

        return redirect(url_for("entries_overview"))


@app.route("/leaderboard", methods=["GET", "POST"])
def user_leaderboard():
    username = session.get("username", None)
    if not username:
        return redirect(url_for("login"))
    else:
        cursor = db.cursor()

        cursor.execute(
            """
            SELECT s.name,s.username,SUM(emp.points_earned) as total_points,COUNT(de.daily_id) as total_entries,
            AVG(de.carbon_score) as avg_carbon_score 
            FROM SignupDetails s JOIN EmployeePoints emp ON s.id=emp.user_id JOIN DailyEntry de ON s.id = de.signup_ref_id GROUP BY s.id ORDER BY total_points DESC LIMIT 10
        """
        )

        top_users = cursor.fetchall()

        cursor.execute("SELECT id FROM SignupDetails WHERE username = %s", (username,))
        user_result = cursor.fetchone()

        if user_result:
            user_id = user_result["id"]

            cursor.execute(
                "SELECT SUM(emp.points_earned) as my_points,COUNT(de.daily_id) as my_entries,AVG (de.carbon_score) as my_avg_carbon FROM EmployeePoints emp JOIN DailyEntry de ON emp.user_id = de.signup_ref_id WHERE emp.user_id = %s",
                (user_id,),
            )
            current_user_stats = cursor.fetchone()
        cursor.close()

        return render_template(
            "leaderboard.html",
            top_users=top_users,
            current_user_stats=current_user_stats,
            username=username,
        )


@app.route("/update_profile", methods=["POST"])
def update_user_profile():
    username = session.get("username", None)
    if not username:
        return redirect(url_for("login"))

    name = request.form.get("name")
    age = request.form.get("age")
    gender = request.form.get("gender")
    phone_no = request.form.get("phone_no")
    email = request.form.get("email")
    errors = []
    if not name or not (4 <= len(name) <= 16):
        errors.append("Name must be 4-16 characters long.")

    if not EMAIL_REGEX.fullmatch(email):
        errors.append("Invalid email address")

    if not PHONE_REGEX.fullmatch(phone_no):
        errors.append("Invalid phone number")

    try:
        age_val = int(age)
        if not (18 <= age_val <= 90):
            errors.append("Age must be between 18 and 90.")
    except (ValueError, TypeError):
        errors.append("Invalid Age")

    if gender not in ["Male", "Female", "Other"]:
        errors.append("Please select a valid gender.")

    if errors:
        for error in errors:
            flash(error, "error")
        return redirect(url_for("profile"))

    try:
        cursor = db.cursor()
        cursor.execute("SELECT id FROM SignupDetails WHERE username = %s", (username,))
        a = cursor.fetchone()
        if not a:
            flash("User not found", "error")
            return redirect(url_for("profile"))

        user_id = a["id"]

        cursor.execute(
            "UPDATE SignupDetails SET name = %s, age = %s, gender = %s, phone_no = %s, email = %s WHERE id = %s",
            (name, age, gender, phone_no, email, user_id),
        )
        db.commit()
        cursor.close()
        flash("Profile updated successfully!", "success")

    except Exception as e:
        db.rollback()
        print(f"Database error:{e}")
        flash("Error updating profile", "error")

    return redirect(url_for("profile"))


@app.route("/change_password", methods=["POST"])
def pass_change():
    username = session["username"]
    errors = []
    if username:
        cursor = db.cursor()

        cursor.execute("SELECT id FROM SignupDetails WHERE username = %s", (username,))
        a = cursor.fetchone()
        user_id = a["id"]

        new_password = request.form.get("new_password")
        confirm_password = request.form.get("confirm_password")

        password_regex = re.compile(
            r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,32}$"
        )
        if not password_regex.fullmatch(new_password):
            errors.append(
                "Password must be 8–12 chars, include uppercase, lowercase, number & special character."
            )
        if new_password != confirm_password:
            errors.append("Passwords do not match.")

        if errors:
            for error in errors:
                flash(error, "danger")
            return redirect(url_for("profile"))
        else:
            hashed_password = generate_password_hash(
                new_password, method="pbkdf2:sha256", salt_length=16
            )
            cursor.execute(
                "UPDATE SignupDetails SET user_password = %s WHERE id = %s",
                (hashed_password, user_id),
            )
            db.commit()
            cursor.close()
            flash("Password updated successfully", "success")
            return redirect(url_for("profile"))


@app.route("/delete_profile", methods=["POST"])
def delete_user_profile():
    username = session.get("username", None)
    if not username:
        return redirect(url_for("login"))
    try:
        cursor = db.cursor()
        cursor.execute("SELECT id FROM SignupDetails WHERE username = %s", (username,))
        a = cursor.fetchone()
        user_id = a["id"]
        cursor.execute("DELETE FROM SignupDetails WHERE  id = %s", (user_id,))
        db.commit()
        cursor.close()
        session.clear()
        flash("Account deleted successfully!", "success")
        return redirect(url_for("login"))

    except Exception as e:
        db.rollback()
        flash("Error deleteing profile", "error")
        return redirect(url_for("profile"))


@app.route("/logout")
def logout():
    user_id = session.get("user_id")
    if user_id:
        cursor = db.cursor()
        try:
            cursor.execute(
                "UPDATE SignupDetails SET  active_session = NULL,last_active = NULL WHERE id = %s",(
                    user_id,
                )
            )
            db.commit()
        except Exception as e:
            print(f"Logout error: {e}")
        finally:
            cursor.close()   
        

    session.clear()
    response = make_response(redirect(url_for("login")))
    response.headers["Cache-Control"] = "no-cache, no_store ,must_revalidate"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    return response


if __name__ == "__main__":
    app.run(debug=True)


# def login_required(view_func):
#     @wraps(view_func)
#     def wrapper(*args, **kwargs):
#         if "username" not in session:
#             return redirect(url_for("login"))

#         response = make_response(view_func(*args, **kwargs))
#         response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
#         response.headers["Pragma"] = "no-cache"
#         response.headers["Expires"] = "0"

#         return response

#     return wrapper
