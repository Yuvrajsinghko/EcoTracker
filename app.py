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
from flask_caching import Cache
from functools import wraps
from datetime import date, datetime
import time
import uuid
import re
from werkzeug.security import generate_password_hash, check_password_hash
from database import get_db

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

# Configure Flask app
app.config.update(
    SESSION_COOKIE_SECURE=False,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    CACHE_TYPE="SimpleCache",
    CACHE_DEFAULT_TIMEOUT=300
)

# Initialize cache
cache = Cache(app)

# Use connection pool instead of single connection
db = get_db()


app.secret_key = "secretkey"

INACTIVITY_LIMIT = 300


@app.before_request
def enforce_session_rules():

    if request.endpoint in ("login", "signup", "submit", "register", "static","main"):
        return None

    username = session.get("username")
    token = session.get("session_token")
    user_id = session.get("user_id")

    if not username or not token or not user_id:
        session.clear()
        return redirect(url_for("main"))

    cursor = db.cursor()
    try:

        cursor.execute(
            "SELECT active_session, last_active FROM SignupDetails WHERE id = %s",
            (user_id,),
        )

        user = cursor.fetchone()

        if not user:
            session.clear()
            return redirect(url_for("main"))
        # Enforce single-session
        if not user["active_session"] or user["active_session"] != token:
            session.clear()
            flash("You were logged out because you logged in from another device.")
            return redirect(url_for("main"))

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
                return redirect(url_for("main"))
        # Update last active
        cursor.execute(
            "UPDATE SignupDetails SET last_active = %s WHERE id = %s",
            (
                datetime.now(),
                user_id,
            ),
        )
        db.commit()

    except Exception as e:
        print(f"Session validation error: {e}")
        session.clear()
        return redirect(url_for("login"))
    finally:
        cursor.close()


@app.route("/")
def main():
    return render_template("landing.html")


@app.route("/signup")
def signup():
    return render_template("Signup.html")

@app.route("/login")
def login():
    return render_template("Login.html")



@app.route("/success")
def registration_done():
    username = session.get("username", None)
    if not username:
        return render_template("Login.html")
    else:
        return render_template("success.html", name=username)


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
            return redirect(url_for("registration_done"))

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

    errors = []

    if not all(
        [name, email, user_phone_no, age, gender, password, u_sername, confirm_password]
    ):
        errors.append("All fields are required.")
        for error in errors:
            flash(error, "danger")
        return render_template("Signup.html")

    hashed_password = generate_password_hash(
        password, method="pbkdf2:sha256", salt_length=16
    )

    cursor.execute(
        "SELECT username email FROM SignupDetails WHERE username = %s ", (u_sername,)
    )
    user_name = cursor.fetchone()

    print(user_name)
    if user_name:
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


def get_user_stats(user_id, days=30):
    """Get basic user statistics for the last N days"""
    cursor = db.cursor()
    cursor.execute(
        """
        SELECT d.carbon_score, d.date_of_entry,
               t.mode_of_transport, t.distance_travelled, t.work_location,
               di.diet_type, e.points_earned
        FROM DailyEntry d 
        JOIN TransportDetails t ON d.transport_ref_id = t.transport_id 
        JOIN DietDetails di ON d.diet_ref_id = di.diet_id 
        JOIN EmployeePoints e ON d.user_point_id_ref = e.emp_point_id
        WHERE d.signup_ref_id = %s 
        AND d.date_of_entry >= DATE_SUB(CURDATE(), INTERVAL %s DAY)
        ORDER BY d.date_of_entry DESC
    """,
        (user_id, days),
    )

    entries = cursor.fetchall()
    cursor.close()

    if not entries:
        return None

    # Basic calculations
    carbon_scores = [entry["carbon_score"] for entry in entries]
    total_distance = sum(entry["distance_travelled"] or 0 for entry in entries)

    stats = {
        "total_entries": len(entries),
        "avg_carbon": round(sum(carbon_scores) / len(carbon_scores), 1),
        "total_carbon": round(sum(carbon_scores), 1),
        "total_points": sum(entry["points_earned"] for entry in entries),
        "total_distance": round(total_distance, 1),
        "best_day": min(carbon_scores),
        "worst_day": max(carbon_scores),
        "entries": entries,
    }

    return stats


def get_simple_tips(stats):
    """Generate basic tips based on user stats"""
    if not stats:
        return ["Start tracking your daily activities to get tips!"]

    tips = []

    # High carbon footprint
    if stats["avg_carbon"] > 25:
        tips.append(
            {
                "icon": "⚠️",
                "message": "Your carbon footprint is high. Try using public transport or working from home more often.",
                "category": "Reduce Emissions",
            }
        )

    # Good performance
    elif stats["avg_carbon"] < 15:
        tips.append(
            {
                "icon": "🌟",
                "message": "Great job! Your carbon footprint is low. Keep up the good work.",
                "category": "Keep Going",
            }
        )

    # High travel distance
    if (
        stats["total_distance"] > stats["total_entries"] * 15
    ):  # More than 15km/day average
        tips.append(
            {
                "icon": "🚗",
                "message": "You travel long distances daily. Consider carpooling or remote work options.",
                "category": "Transport",
            }
        )

    # Consistency encouragement
    if stats["total_entries"] < 20:
        tips.append(
            {
                "icon": "📅",
                "message": "Track more days to get better insights and improve your environmental impact.",
                "category": "Tracking",
            }
        )

    # General tip
    tips.append(
        {
            "icon": "🌱",
            "message": "Small daily changes add up. Try one eco-friendly habit this week.",
            "category": "General",
        }
    )

    return tips[:4]  # Return max 4 tips


@app.route("/insights")
@cache.memoize(timeout=300)  # Cache user-specific data for 5 minutes
def user_insights():
    """Simple insights page"""
    username = session.get("username", None)
    if not username:
        return redirect(url_for("login"))

    cursor = db.cursor()
    cursor.execute("SELECT id FROM SignupDetails WHERE username = %s", (username,))
    user_result = cursor.fetchone()
    cursor.close()

    if not user_result:
        return redirect(url_for("login"))

    user_id = user_result["id"]
    stats = get_user_stats(user_id)
    tips = get_simple_tips(stats)

    return render_template(
        "simple_insights.html", stats=stats, tips=tips, username=username
    )


@app.route("/simple_report")
def simple_report():
    """Basic monthly report"""
    username = session.get("username", None)
    if not username:
        return redirect(url_for("login"))

    cursor = db.cursor()
    cursor.execute("SELECT id FROM SignupDetails WHERE username = %s", (username,))
    user_result = cursor.fetchone()
    cursor.close()

    if not user_result:
        return redirect(url_for("login"))

    user_id = user_result["id"]
    stats = get_user_stats(user_id, days=30)

    # Get user ranking
    cursor = db.cursor()
    cursor.execute(
        """
        SELECT COUNT(*) + 1 as user_rank
        FROM (
            SELECT SUM(emp.points_earned) as total_points
            FROM DailyEntry de 
            JOIN EmployeePoints emp ON de.user_point_id_ref = emp.emp_point_id
            WHERE de.date_of_entry >= DATE_SUB(CURDATE(), INTERVAL 30 DAY)
            GROUP BY de.signup_ref_id
            HAVING total_points > %s
        ) as better_users
    """,
        (stats["total_points"] if stats else 0,),
    )

    rank_result = cursor.fetchone()
    user_rank = rank_result["user_rank"] if rank_result else 1
    cursor.close()

    if stats:
        stats["rank"] = user_rank

    return render_template("simple_report.html", stats=stats, username=username)


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
@cache.cached(timeout=60)  # Cache for 1 minute
def user_leaderboard():
    username = session.get("username", None)
    if not username:
        return redirect(url_for("login"))

    cursor = db.cursor()
    try:
        cursor.execute(
            """
            SELECT 
                s.id,
                s.name,
                s.username,
                COALESCE(SUM(emp.points_earned), 0) AS total_points,
                COALESCE(COUNT(DISTINCT de.daily_id), 0) AS total_entries,
                COALESCE(AVG(de.carbon_score), 0) AS avg_carbon_score
            FROM SignupDetails s
            LEFT JOIN DailyEntry de ON s.id = de.signup_ref_id
            LEFT JOIN EmployeePoints emp ON de.user_point_id_ref = emp.emp_point_id
            GROUP BY s.id, s.name, s.username
            ORDER BY total_points DESC
            LIMIT 3
            """,
        )
        top_3_winners = cursor.fetchall()

        # 1) Pagination params
        page = request.args.get("page", 1, type=int)
        if page < 1:
            page = 1
        per_page = 5
        cursor.execute(
            """
            SELECT COUNT(*) AS total_users
            FROM SignupDetails
            """
        )
        row = cursor.fetchone()

        total_users = row["total_users"] if row and row.get("total_users") else 0

        # 3) total_pages (ceiling division), ensure at least 1 page
        total_pages = max(1, (total_users + per_page - 1) // per_page)

        # 4) clamp page to available range and compute offset
        if page > total_pages:
            page = total_pages
        offset = (page - 1) * per_page

        cursor.execute(
            """
            SELECT 
                s.id,
                s.name,
                s.username,
                COALESCE(SUM(emp.points_earned), 0) AS total_points,
                COALESCE(COUNT(DISTINCT de.daily_id), 0) AS total_entries,
                COALESCE(AVG(de.carbon_score), 0) AS avg_carbon_score
            FROM SignupDetails s
            LEFT JOIN DailyEntry de ON s.id = de.signup_ref_id
            LEFT JOIN EmployeePoints emp ON de.user_point_id_ref = emp.emp_point_id
            GROUP BY s.id, s.name, s.username
            ORDER BY total_points DESC
            LIMIT %s OFFSET %s
            """,
            (per_page, offset),
        )

        top_users = cursor.fetchall()

        cursor.execute("SELECT id FROM SignupDetails WHERE username = %s", (username,))
        user_result = cursor.fetchone()
        current_user_stats = None

        if user_result:
            user_id = user_result["id"]

            # Also fix the current user stats query
            cursor.execute(
                """
                SELECT SUM(emp.points_earned) as my_points,
                       COUNT(DISTINCT de.daily_id) as my_entries,
                       AVG(de.carbon_score) as my_avg_carbon 
                FROM DailyEntry de 
                JOIN EmployeePoints emp ON de.user_point_id_ref = emp.emp_point_id
                WHERE de.signup_ref_id = %s
                """,
                (user_id,),
            )
            current_user_stats = cursor.fetchone()
    finally:

        cursor.close()

    start_rank = (page - 1) * per_page + 1

    return render_template(
        "leaderboard.html",
        top_3_winners=top_3_winners,
        top_users=top_users,
        current_user_stats=current_user_stats,
        username=username,
        page=page,
        total_pages=total_pages,
        per_page=per_page,
        start_rank=start_rank,
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
        flash("Error deleting profile", "error")
        return redirect(url_for("profile"))


@app.route("/logout")
def logout():
    user_id = session.get("user_id")
    if user_id:
        cursor = db.cursor()
        try:
            cursor.execute(
                "UPDATE SignupDetails SET  active_session = NULL,last_active = NULL WHERE id = %s",
                (user_id,),
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
    # Import and start session cleanup
    from session_cleanup import cleanup_thread
    app.run(debug=True, threaded=True)


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
