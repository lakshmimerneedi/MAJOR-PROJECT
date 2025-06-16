from flask import Flask, render_template, redirect, url_for, session, request, flash
from flask_dance.contrib.google import make_google_blueprint, google
from flask_dance.consumer import oauth_authorized
import pickle
import os
import json
import pytz
from datetime import datetime
from dateutil import parser  # for parsing ISO datetime strings

app = Flask(__name__)
app.secret_key = 'farm_secret'

# Allow insecure HTTP for local testing (remove in production)
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

# Files to store data persistently
FARMERS_FILE = 'farmers.json'
PREDICTIONS_FILE = 'predictions.json'

def load_farmers():
    if os.path.exists(FARMERS_FILE):
        with open(FARMERS_FILE, 'r') as f:
            return json.load(f)
    return []

def save_farmers():
    with open(FARMERS_FILE, 'w') as f:
        json.dump(farmers, f)

def load_predictions():
    if os.path.exists(PREDICTIONS_FILE):
        with open(PREDICTIONS_FILE, 'r') as f:
            preds = json.load(f)
            # Convert 'created_at' string back to datetime object
            for p in preds:
                if 'created_at' in p:
                    p['created_at'] = parser.isoparse(p['created_at'])
            return preds
    return []

def save_predictions():
    # Before saving, convert datetime objects to ISO strings
    preds_copy = []
    for p in predictions:
        p_copy = p.copy()
        if 'created_at' in p_copy and isinstance(p_copy['created_at'], datetime):
            p_copy['created_at'] = p_copy['created_at'].isoformat()
        preds_copy.append(p_copy)
    with open(PREDICTIONS_FILE, 'w') as f:
        json.dump(preds_copy, f)

# Load ML model
model = pickle.load(open('rfmodel.pkl', 'rb'))

# Google OAuth blueprint setup
google_bp = make_google_blueprint(
    client_id="695075020518-jc0r3ds0jqu6b4vt1lrmmp5iv73b5onn.apps.googleusercontent.com",
    client_secret="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",
    scope=[
        "openid",
        "https://www.googleapis.com/auth/userinfo.email",
        "https://www.googleapis.com/auth/userinfo.profile"
    ],
    redirect_to="dashboard"
)

app.register_blueprint(google_bp, url_prefix="/login")

@oauth_authorized.connect_via(google_bp)
def log_redirect_uri(blueprint, token):
    print("Redirect URI used:", blueprint.redirect_url)

farmers = load_farmers()
predictions = load_predictions()

@app.route('/')
def home():
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if 'user' in session:
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        email = request.form['email']
        if any(f['email'] == email for f in farmers):
            return "Email already registered. Please login.", 400

        data = {
            'name': request.form['fname'],
            'surname': request.form['surname'],
            'phone': request.form['phone'],
            'age': int(request.form['age']),
            'experience': int(request.form['exp']),
            'acres': float(request.form['acres']),
            'last_crop': request.form['crop'],
            'email': email,
            'password': request.form['password']
        }
        farmers.append(data)
        save_farmers()
        flash("Registration successful! Please login.")
        return redirect(url_for('login'))

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        user = next((f for f in farmers if f['email'] == email and f['password'] == password), None)
        if user:
            session['user'] = {
                'name': user['name'],
                'surname': user['surname'],
                'email': user['email']
            }
            flash('Login successful!')
            return render_template('login.html', success=True)
        else:
            flash('Invalid email or password.')
            return redirect(url_for('login'))

    return render_template('login.html')

@app.route('/dashboard')
def dashboard():
    if not google.authorized and 'user' not in session:
        return redirect(url_for('login'))

    if google.authorized and 'user' not in session:
        resp = google.get("/oauth2/v2/userinfo")
        if not resp.ok:
            return "Failed to fetch user info from Google.", 400
        info = resp.json()
        email = info.get('email', '')
        name = info.get('given_name', '')
        surname = info.get('family_name', '')

        if not any(f['email'] == email for f in farmers):
            farmers.append({
                'name': name,
                'surname': surname,
                'phone': '',
                'age': 0,
                'experience': 0,
                'acres': 0.0,
                'last_crop': '',
                'email': email,
                'password': ''
            })
            save_farmers()

        session['user'] = {
            'name': name,
            'surname': surname,
            'email': email
        }
        flash("Login successful!")

    user_data = session.get('user', {})
    return render_template('dashboard.html', user=user_data)

@app.route('/predict', methods=['GET', 'POST'])
def predict():
    if not google.authorized and 'user' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        try:
            data = [
                float(request.form['N']),
                float(request.form['P']),
                float(request.form['K']),
                float(request.form['temperature']),
                float(request.form['humidity']),
                float(request.form['ph']),
                float(request.form['rainfall'])
            ]
            pred = model.predict([data])[0]

            # Add current timestamp (UTC)
            now_utc = datetime.now(pytz.utc)

            predictions.append({
                'farmer': session['user']['email'],
                'inputs': data,
                'crop': pred,
                'created_at': now_utc  # store as datetime object here; will convert on save
            })
            save_predictions()
            return render_template('result.html', predicted_crop=pred)
        except Exception as e:
            return f"Error: {str(e)}", 400

    return render_template('predict.html')


@app.route('/history')
def history():
    if 'user' not in session:
        return redirect(url_for('login'))
    
    user_email = session['user']['email']
    farmer = next((f for f in farmers if f['email'] == user_email), None)
    user_predictions = [p for p in predictions if p['farmer'] == user_email]
    
    # Timezones
    local_tz = pytz.timezone('Asia/Kolkata')

    for p in user_predictions:
        if 'created_at' in p:
            dt = p['created_at']  # datetime object
            dt_local = dt.astimezone(local_tz)
            p['timestamp'] = dt_local.strftime("%Y-%m-%d %H:%M:%S %Z%z")
        else:
            p['timestamp'] = "N/A"
    
    return render_template('history.html', farmer=farmer, predictions=user_predictions)


@app.route('/remove/<int:index>', methods=['POST'])
def remove_prediction(index):
    if 'user' not in session:
        return redirect(url_for('login'))
    
    user_email = session['user']['email']
    user_predictions = [p for p in predictions if p['farmer'] == user_email]

    if 0 <= index < len(user_predictions):
        predictions.remove(user_predictions[index])
        save_predictions()
    return redirect(url_for('history'))


@app.route('/update/<int:index>', methods=['GET', 'POST'])
def update_prediction(index):
    if 'user' not in session:
        return redirect(url_for('login'))

    user_email = session['user']['email']
    user_predictions = [p for p in predictions if p['farmer'] == user_email]

    if 0 <= index < len(user_predictions):
        if request.method == 'POST':
            try:
                new_data = [
                    float(request.form['N']),
                    float(request.form['P']),
                    float(request.form['K']),
                    float(request.form['temperature']),
                    float(request.form['humidity']),
                    float(request.form['ph']),
                    float(request.form['rainfall'])
                ]
                new_crop = model.predict([new_data])[0]
                user_predictions[index]['inputs'] = new_data
                user_predictions[index]['crop'] = new_crop

                # Update timestamp on update
                user_predictions[index]['created_at'] = datetime.now(pytz.utc)

                save_predictions()
                return redirect(url_for('history'))
            except Exception as e:
                return f"Update Error: {e}", 400

        prediction = user_predictions[index]
        return redirect(url_for('predict'))

    return redirect(url_for('history'))
@app.route("/")
def index():
    google_info = None
    current_user_email = ""
    if google.authorized:
        resp = google.get("/oauth2/v2/userinfo")
        google_info = resp.json()
        current_user_email = google_info.get("email", "")
    return render_template("index.html", google_info=google_info, current_user_email=current_user_email)


@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/blogs')
def blog():
    return render_template('blogs.html')

if __name__ == "__main__":
    app.run(host='localhost', port=5000, debug=True)
