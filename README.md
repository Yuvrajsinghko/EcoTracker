<div align="center">

<img src="https://readme-typing-svg.demolab.com?font=Fira+Code&weight=800&size=38&pause=1000&color=22C55E&center=true&vCenter=true&width=750&lines=🌍+EcoTracker;Carbon+Footprint+Calculator;Track+It.+Reduce+It.+Own+It." alt="Typing SVG" />

<br/>

<img src="https://img.shields.io/badge/Python-3776AB?style=for-the-badge&logo=python&logoColor=white"/>
<img src="https://img.shields.io/badge/Flask-000000?style=for-the-badge&logo=flask&logoColor=white"/>
<img src="https://img.shields.io/badge/MySQL-4479A1?style=for-the-badge&logo=mysql&logoColor=white"/>
<img src="https://img.shields.io/badge/HTML5-E34F26?style=for-the-badge&logo=html5&logoColor=white"/>
<img src="https://img.shields.io/badge/CSS3-1572B6?style=for-the-badge&logo=css3&logoColor=white"/>
<img src="https://img.shields.io/badge/JavaScript-F7DF1E?style=for-the-badge&logo=javascript&logoColor=black"/>

<br/><br/>

> 🌱 *"You can't improve what you don't measure. Start measuring."*
>
> **EcoTracker** is a full-stack web application that helps users track, analyze, and reduce  
> their daily carbon footprint — with green points, insights, reports, and a live leaderboard.

<br/>

![GitHub repo size](https://img.shields.io/github/repo-size/Yuvrajsinghko/EcoTracker?color=22C55E&style=flat-square)
![GitHub last commit](https://img.shields.io/github/last-commit/Yuvrajsinghko/EcoTracker?color=16a34a&style=flat-square)
![Commits](https://img.shields.io/badge/commits-50%2B-brightgreen?style=flat-square)
![Python](https://img.shields.io/badge/Python-18.1%25-3776AB?style=flat-square&logo=python&logoColor=white)

</div>

---

## 🌍 What Is EcoTracker?

**EcoTracker** is a full-stack carbon footprint tracking platform built with **Python Flask** and **MySQL**. Users log their daily work commute, diet choices, digital habits, and more — the app calculates a real-time **carbon score**, awards **green points**, and ranks users on a **live leaderboard**.

This isn't just a calculator. It's a complete ecosystem — with secure authentication, session management, CRUD entries, monthly reports, eco-tips, and a competitive leaderboard that makes going green actually fun.

---

## ✨ Features at a Glance

| Feature | Description |
|---------|-------------|
| 🔐 **Secure Auth** | Signup/Login with hashed passwords, single-session enforcement & inactivity timeout |
| 📊 **Carbon Calculator** | Real-time score based on commute, diet, work location, digital & printing habits |
| 🌟 **Green Points** | Earn reward points daily based on how eco-friendly your choices are |
| 📅 **Daily Entry** | Log activities every day — full CRUD (create, view, edit, delete) |
| 📈 **Insights** | 30-day personal stats — avg carbon, best/worst day, total distance & tips |
| 📋 **Monthly Report** | Summary report with your rank among all users |
| 🏆 **Leaderboard** | Paginated global leaderboard with top-3 podium & your live stats |
| 👤 **Profile Management** | View & edit profile details, change password |
| ⚡ **Smart Caching** | Flask-Caching on insights & leaderboard for performance |

---

## 🗂️ Project Structure

```
EcoTracker/
│
├── app.py                  → Flask app — all routes, business logic & carbon engine
├── database.py             → MySQL connection pool setup
├── session_cleanup.py      → Background session cleanup utility
├── requirements.txt        → Python dependencies
│
├── templates/              → Jinja2 HTML templates
│   ├── landing.html        → Public landing page
│   ├── Login.html          → Login page
│   ├── Signup.html         → Registration page
│   ├── success.html        → Dashboard after login
│   ├── daily_entry.html    → Daily activity form
│   ├── daily_entry_status.html → Submission confirmation
│   ├── entries_overview.html   → All past entries list
│   ├── view_entry.html     → Single entry detail view
│   ├── edit_entry.html     → Edit a past entry
│   ├── simple_insights.html    → Personal 30-day insights
│   ├── simple_report.html  → Monthly report with rank
│   ├── leaderboard.html    → Global leaderboard (paginated)
│   └── profile.html        → User profile page
│
└── static/                 → CSS, JS & static assets
```

---

## 🧮 How The Carbon Score Works

The app calculates your **daily carbon score (kg CO₂)** across 6 categories:

```
🚗 Commute         → Mode × Distance
                     Car: 0.2/km | Bike: 0.1/km | Public: 0.08/km
                     Train: 0.04/km | Flight: 0.15/km + 50 base

🏢 Work Location   → Home: +1 | Office: +3 | Travel: +5

🥗 Diet            → Vegan: +1.5 | Vegetarian: +2.5
                     Pescatarian: +3.5 | Non-Veg: +4.8

🍱 Meal Source     → Home-Packed: +1 | Cafeteria: +2
                     Restaurant: +3 | Food Delivery: +4

💻 Digital Habits  → Light: +0.5 | Moderate: +1 | Heavy: +2 | Intensive: +3

🖨️ Printing        → Minimal: +0.5 | Moderate: +1 | Heavy: +2
```

### 🌟 Green Points Earned

| Carbon Score | Green Points | Rating |
|---|---|---|
| ≤ 10 kg | 🟢 **100 pts** | Excellent |
| 11–20 kg | 🔵 **75 pts** | Good |
| 21–40 kg | 🟡 **50 pts** | Average |
| > 40 kg | 🔴 **25 pts** | Needs Improvement |

---

## 🔐 Authentication & Security

- ✅ Passwords hashed with **PBKDF2-SHA256** + 16-byte salt (via Werkzeug)
- ✅ **Single-session enforcement** — logging in on a new device logs out the old one
- ✅ **Inactivity timeout** — auto logout after 5 minutes of inactivity
- ✅ `session_token` stored in DB and validated on every request
- ✅ Input validation — Email regex, Indian phone regex, password strength checks
- ✅ Age (18–90), username (8–12 chars), name (4–16 chars) all enforced

---

## 🗄️ Database Schema

```
SignupDetails         → User accounts (id, name, email, phone, username, password, session)
    │
    ├── DailyEntry    → Master log (links all sub-tables + carbon_score + date)
    │       ├── TransportDetails   → mode, distance, work_location
    │       ├── DietDetails        → diet_type, food_source
    │       ├── LifestyleHabits    → digital_footprint, printing_today
    │       └── EmployeePoints     → points_earned, date_earned
```

---

## 🌐 Application Routes

| Route | Method | Description |
|-------|--------|-------------|
| `/` | GET | Landing page |
| `/signup` | GET | Registration form |
| `/register` | POST | Process signup |
| `/login` | GET | Login form |
| `/submit` | POST | Process login |
| `/success` | GET | User dashboard |
| `/dailyentrypage` | GET/POST | Log daily activity |
| `/entries_overview` | GET | All past entries |
| `/entry/<id>` | GET | View single entry |
| `/entry/edit/<id>` | GET/POST | Edit entry |
| `/entry/delete/<id>` | GET | Delete entry |
| `/insights` | GET | 30-day insights + tips |
| `/simple_report` | GET | Monthly report + rank |
| `/leaderboard` | GET | Global leaderboard |
| `/profile` | GET | User profile |
| `/update_profile` | POST | Edit profile |
| `/change_password` | POST | Update password |

---

## ⚙️ Getting Started

### 1. Prerequisites

```bash
python --version    # 3.9+ recommended
mysql --version     # MySQL 8+
```

### 2. Clone the Repo

```bash
git clone https://github.com/Yuvrajsinghko/EcoTracker.git
cd EcoTracker
```

### 3. Install Dependencies

```bash
pip install -r requirements.txt
```

### 4. Set Up the Database

```sql
CREATE DATABASE ecotracker;
-- Then run your schema SQL to create all tables
```

Update `database.py` with your MySQL credentials.

### 5. Run the App

```bash
python app.py
```

Open **http://localhost:5000** in your browser 🌍

---

## 🛠️ Tech Stack

| Technology | Role |
|-----------|------|
| ![Flask](https://img.shields.io/badge/Flask-000000?style=flat&logo=flask&logoColor=white) | Web framework & routing |
| ![Python](https://img.shields.io/badge/Python-3776AB?style=flat&logo=python&logoColor=white) | Backend logic & carbon engine |
| ![MySQL](https://img.shields.io/badge/MySQL-4479A1?style=flat&logo=mysql&logoColor=white) | Relational database |
| ![Werkzeug](https://img.shields.io/badge/Werkzeug-grey?style=flat) | Password hashing & security |
| ![Flask-Caching](https://img.shields.io/badge/Flask--Caching-green?style=flat) | Performance caching |
| ![HTML5](https://img.shields.io/badge/HTML5-E34F26?style=flat&logo=html5&logoColor=white) | Templates (Jinja2) |
| ![CSS3](https://img.shields.io/badge/CSS3-1572B6?style=flat&logo=css3&logoColor=white) | Styling |
| ![JavaScript](https://img.shields.io/badge/JavaScript-F7DF1E?style=flat&logo=javascript&logoColor=black) | Frontend interactivity |

---

## 📊 Language Breakdown

```
HTML        ████████████████████░░░░   80.3%
Python      █████░░░░░░░░░░░░░░░░░░░   18.1%
CSS         █░░░░░░░░░░░░░░░░░░░░░░░    1.6%
```

---

## 🚀 What I Learned Building This

- Full-stack web development with **Flask** and **Jinja2 templating**
- **Relational database design** with normalized tables & JOIN queries
- **Session security** — single-device enforcement, inactivity timeouts, token validation
- **Password security** — PBKDF2 hashing, salt, strength validation via regex
- **Carbon footprint domain knowledge** — emission factors per transport mode & lifestyle
- **Caching strategies** with Flask-Caching to reduce DB load
- **Pagination** on the leaderboard with proper offset/limit SQL

---

## 🤝 Contributing

This is a personal project, but issues and suggestions are always welcome!

---

## 📬 Connect With Me

<div align="center">

[![GitHub](https://img.shields.io/badge/GitHub-Yuvrajsinghko-181717?style=for-the-badge&logo=github)](https://github.com/Yuvrajsinghko)

</div>

---

<div align="center">

**The planet doesn't need a few people doing sustainability perfectly.**  
**It needs millions doing it imperfectly. Start tracking. 🌍**

*If this project inspired you, drop a ⭐ — it genuinely means a lot!*

<img src="https://capsule-render.vercel.app/api?type=waving&color=22C55E&height=100&section=footer" width="100%"/>

</div>
