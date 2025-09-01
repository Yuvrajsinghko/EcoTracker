from os import error
from flask import Flask, flash, redirect, render_template, request, session, url_for
import pymysql
import random
from datetime import date
import re 
from werkzeug.security import generate_password_hash, check_password_hash

EMAIL_REGEX = re.compile(r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,63}$")
PHONE_REGEX = re.compile(
    r"^(?!(\d)\1{9}$)(?!1234567890$)(?!9876543210$)"
    r"(?!9898989898$)(?!7878787878$)(?!5656565656$)"
    r"(?!1212121212$)(?!2323232323$)(?!4545454545$)"
    r"(?!6767676767$)(?!8989898989$)[6-9][0-9]{9}$"
)

app = Flask(__name__)
db = pymysql.connections.Connection(
    host="localhost",
    user="yuvraj",
    password="root69",
    database="greendb",
    cursorclass=pymysql.cursors.DictCursor,
)


app.secret_key = "secretkey"


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
    cursor = db.cursor()
    
    cursor.execute(
        "SELECT username,user_password FROM SignupDetails WHERE username = %s",
        (username,),
    )
    user = cursor.fetchone()
    
    cursor.close()
    
    if user and check_password_hash(user["user_password"],password):
        
        session["username"] = username  # Store username in session
        return render_template("success.html", name=username)
    else:
        
        flash("Invalid username or password","danger")
        return render_template("Login.html")


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
    confirm_password= request.form.get("confirmPassword")
    hashed_password=generate_password_hash(password,method='pbkdf2:sha256', salt_length=16)

    errors=[]

    cursor.execute("SELECT username FROM SignupDetails WHERE username = %s",(u_sername,))
    user=cursor.fetchone()

    if user:
        flash("Username already exist","danger")
        return redirect(url_for('signup'))
    else:
        if not (4 <=len(name) <=16):
            errors.append("Name must be 4-16 characters long.")

    
        if not EMAIL_REGEX.fullmatch(email):
            errors.append("Invalid email address")

    
        if not PHONE_REGEX.fullmatch(user_phone_no):
            errors.append("Invalid phone number")


        try:
            age_val=int(age)
            if not (18 <= age_val <=90):
                errors.append("Age must be between 18 and 90.")
        except ValueError:
            errors.append("Invalid Age")
        
        if gender not in ["Male","Female","Other"]:
            errors.append("Please select a valid gender.")
        
        if not (8 <= len(u_sername) <= 12):
            errors.append("Username must be 8-12 characters")

        password_regex = re.compile(r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,32}$")

        if not password_regex.fullmatch(password):
            errors.append("Password must be 8–12 chars, include uppercase, lowercase, number & special character.")

        if password != confirm_password:
            errors.append("Passwords do not match.")

        if errors:
            for error in errors:
                flash(error,"danger")
            return redirect(url_for('signup'))
        else:
            cursor.execute(
            "INSERT INTO SignupDetails (name,age,gender,username,email,phone_no,user_password,date_joined) VALUES(%s,%s,%s,%s,%s,%s,%s,%s)",
            (   name, age, gender, u_sername, email, user_phone_no, hashed_password, date.today()),
        )
            db.commit()
            cursor.close()
            flash("Registration successful!", "success")
            return render_template("Login.html")


@app.route("/dailyentrypage", methods=["GET", "POST"])
def daily_user_entry():
    if request.method == "GET":
        username = session.get("username", None)
        print(username)
        
        if username:    
            return render_template("daily_entry.html")
        else:

            return redirect(url_for('login'))
           
    else:
        username = session.get("username", None)
        if not username:
            return "Please log in first"

        cursor = db.cursor()
        cursor.execute("SELECT id FROM SignupDetails WHERE username = %s", (username,))
        id = cursor.fetchone()
        user_id = id["id"]
        

        # Get form data
        vehicle_type = request.form.get("vehicle")
        distance_travelled = request.form.get("distance")
        fuel_type = request.form.get("fuel")
        years = request.form.get("years_owned")
        diet_type = request.form.get("diet")
        meals_per_day = request.form.get("meals")
        food_source = request.form.get("food_source")
        electricity_consume = request.form.get("electric_consumption")
        water_consume = request.form.get("water_consumption")
        gas_consume = request.form.get("gas_consumption")
        plastic = request.form.get("plastic_items")
        alcohol_consume = request.form.get("alcohol_consumption")
        smoking = request.form.get("smoking")
        gym_hours = request.form.get("gym")

        # Insert into detail tables and get the LAST INSERT IDs
        cursor.execute(
            "INSERT INTO TransportDetails(tt_id,mode_of_transport,distance_travelled,fuel_type,years_owned) VALUES(%s,%s,%s,%s,%s)",
            (user_id, vehicle_type, distance_travelled, fuel_type, years),
        )
        transport_id = cursor.lastrowid  # Get the ID of the just-inserted record

        cursor.execute(
            "INSERT INTO DietDetails(diet_ref_id,diet_type,meals_per_day,food_source)VALUES(%s,%s,%s,%s)",
            (user_id, diet_type, meals_per_day, food_source),
        )
        diet_id = cursor.lastrowid

        cursor.execute(
            "INSERT INTO UtilityUsage(ut_ref_id,electricity_consumption,water_consumption,gas_usage) VALUES(%s,%s,%s,%s)",
            (user_id, electricity_consume, water_consume, gas_consume),
        )
        utility_id = cursor.lastrowid

        cursor.execute(
            "INSERT INTO LifestyleHabits(life_ref_id,plastic_item_used,alcohol_consume,smoking,gym_hours) VALUES(%s,%s,%s,%s,%s)",
            (user_id, plastic, alcohol_consume, smoking, gym_hours),
        )
        lifestyle_id = cursor.lastrowid

        # Calculate carbon score (you should implement proper calculation logic)
        carbon = round(random.uniform(5.0, 50.0), 2)

        # Insert into DailyEntry using the specific IDs from this entry
        cursor.execute(
            "INSERT INTO DailyEntry(user_id,transport_ref_id,diet_ref_id,utility_ref_id,lifestyle_ref_id,carbon_score,date_of_entry) VALUES(%s,%s,%s,%s,%s,%s,%s)",
            (
                user_id,
                transport_id,
                diet_id,
                utility_id,
                lifestyle_id,
                carbon,
                date.today(),
            ),
        )

        db.commit()
        cursor.close()
        return render_template("daily_entry_status.html", name=username)


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
        user = cursor.fetchone()  # returns dict because of DictCursor
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
            "SELECT daily_id,carbon_score,date_of_entry FROM DailyEntry WHERE user_id = %s ORDER BY date_of_entry DESC",
            (user_id,),
        )
        entries = cursor.fetchall()
        cursor.close()

    return render_template("entries_overview.html", entries=entries)


@app.route("/entry/<int:entry_id>")
def view_single_entry(entry_id):
    cursor = db.cursor()
    cursor.execute(
        "SELECT d.*,t.mode_of_transport,t.distance_travelled,t.fuel_type,t.years_owned,di.diet_type,di.meals_per_day,di.food_source,l.plastic_item_used,l.alcohol_consume,l.smoking,l.gym_hours,u.electricity_consumption,u.water_consumption,u.gas_usage FROM DailyEntry d JOIN "
        "TransportDetails t ON d.transport_ref_id = t.transport_id JOIN DietDetails di ON d.diet_ref_id = di.diet_id JOIN UtilityUsage u ON d.utility_ref_id = u.utility_id JOIN LifestyleHabits l ON d.lifestyle_ref_id = l.lifestyle_id  WHERE d.daily_id = %s",
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
    cursor.execute("DELETE FROM DailyEntry WHERE daily_id = %s", (entry_id,))
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
    cursor.execute(
        "DELETE FROM UtilityUsage WHERE utility_id = %s",
        (daily_dict["utility_ref_id"],),
    )
    db.commit()
    cursor.close()

    return redirect(url_for("entries_overview"))



@app.route("/entry/edit/<int:entry_id>",methods=["GET","POST"])
def edit_entry(entry_id):
    username=session.get("username",None)
    if not username:
        return render_template("Login.html")
    
    try:
        cursor = db.cursor()

        cursor.execute("SELECT id FROM SignupDetails WHERE username = %s",(username,))
        a=cursor.fetchone()
        user_id=a["id"]
        cursor.execute(
        "SELECT d.*,t.mode_of_transport,t.distance_travelled,t.fuel_type,t.years_owned,di.diet_type,di.meals_per_day,di.food_source,l.plastic_item_used,l.alcohol_consume,l.smoking,l.gym_hours,u.electricity_consumption,u.water_consumption,u.gas_usage FROM DailyEntry d JOIN "
        "TransportDetails t ON d.transport_ref_id = t.transport_id JOIN DietDetails di ON d.diet_ref_id = di.diet_id JOIN UtilityUsage u ON d.utility_ref_id = u.utility_id JOIN LifestyleHabits l ON d.lifestyle_ref_id = l.lifestyle_id  WHERE d.daily_id = %s",
        (entry_id,),
    )
        entry = cursor.fetchone()
        if not entry:
            flash("Entry not found or access denied")
            return redirect(url_for('entries_overview'))
        if request.method == 'GET':
            return render_template("edit_entry.html",entry=entry)
        form_data = {
            'vehicle_type': request.form.get("vehicle"),
            'distance_travelled': float(request.form.get("distance", 0) or 0),
            'fuel_type': request.form.get("fuel"),
            'years_owned': float(request.form.get("years_owned", 0) or 0),
            'diet_type': request.form.get("diet"),
            'meals_per_day': float(request.form.get("meals", 0) or 0),
            'food_source': request.form.get("food_source"),
            'electricity_consume': float(request.form.get("electric_consumption", 0) or 0),
            'water_consume': float(request.form.get("water_consumption", 0) or 0),
            'gas_consume': float(request.form.get("gas_consumption", 0) or 0),
            'plastic': float(request.form.get("plastic_items", 0) or 0),
            'alcohol_consume': float(request.form.get("alcohol_consumption", 0) or 0),
            'smoking': float(request.form.get("smoking", 0) or 0),
            'gym_hours': float(request.form.get("gym", 0) or 0)
        }
        cursor.execute(
            "UPDATE TransportDetails SET mode_of_transport=%s, distance_travelled=%s, fuel_type=%s, years_owned=%s WHERE transport_id=%s",
            (form_data['vehicle_type'], form_data['distance_travelled'], 
             form_data['fuel_type'], form_data['years_owned'], entry['transport_ref_id'])
        )
        
        cursor.execute(
            "UPDATE DietDetails SET diet_type=%s, meals_per_day=%s, food_source=%s WHERE diet_id=%s",
            (form_data['diet_type'], form_data['meals_per_day'], 
             form_data['food_source'], entry['diet_ref_id'])
        )
        
        cursor.execute(
            "UPDATE UtilityUsage SET electricity_consumption=%s, water_consumption=%s, gas_usage=%s WHERE utility_id=%s",
            (form_data['electricity_consume'], form_data['water_consume'], 
             form_data['gas_consume'], entry['utility_ref_id'])
        )
        
        cursor.execute(
            "UPDATE LifestyleHabits SET plastic_item_used=%s, alcohol_consume=%s, smoking=%s, gym_hours=%s WHERE lifestyle_id=%s",
            (form_data['plastic'], form_data['alcohol_consume'], 
             form_data['smoking'], form_data['gym_hours'], entry['lifestyle_ref_id'])
        )
        cursor.execute(
            "UPDATE DailyEntry SET carbon_score=%s WHERE daily_id=%s",
            (entry["carbon_score"], entry_id)
        )
        db.commit()
        cursor.close()
        # flash("Entry updated successfully!","success")

        return redirect(url_for('view_single_entry',entry_id=entry_id))
    except Exception as e:
        db.rollback()
        flash("Failed to update entry","error")

        return redirect(url_for('entries_overview'))

       
@app.route("/update_profile",methods=["POST"])
def update_user_profile():
    username= session.get("username",None)
    if not username:
        return redirect(url_for('login'))
    
    name = request.form.get('name')
    age = request.form.get('age')
    gender = request.form.get('gender')
    phone_no = request.form.get('phone_no')
    email = request.form.get('email')
    password=request.form.get('password')
    

    try:
        cursor=db.cursor()
        cursor.execute("SELECT id FROM SignupDetails WHERE username = %s",(username,))
        a=cursor.fetchone()
        user_id=a["id"]
        cursor.execute("UPDATE SignupDetails SET name = %s,age = %s,gender = %s,phone_no = %s,email = %s,user_password = %s WHERE  id = %s",(name ,age,gender,phone_no,email,password,user_id))
        db.commit()
        cursor.close()
        flash("Profile updated successfully!","success")

    except Exception as e:
        db.rollback()
        flash("Error updating profile","error")
    
    
    return redirect(url_for('profile'))


@app.route("/delete_profile",methods = ['POST'])
def delete_user_profile():
    username= session.get("username",None)
    if not username:
        return redirect(url_for('login'))
    try:
        cursor=db.cursor()
        cursor.execute("SELECT id FROM SignupDetails WHERE username = %s",(username,))
        a=cursor.fetchone()
        user_id=a["id"]
        cursor.execute("DELETE FROM SignupDetails WHERE  id = %s",(user_id,))
        db.commit()
        cursor.close()
        session.clear()
        flash("Account deleted successfully!","success")
        return redirect(url_for('login'))

    except Exception as e:
        db.rollback()
        flash("Error deleteing profile","error")
        return redirect(url_for('profile'))
    
    
@app.route("/logout")
def logout():
    session.clear()
    return render_template("Login.html")

    


if __name__ == "__main__":
    app.run(debug=True)
