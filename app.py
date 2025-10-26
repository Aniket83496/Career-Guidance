
from dotenv import load_dotenv
load_dotenv()

import os
import logging
from flask import Flask, render_template, redirect, url_for, request, flash, jsonify
from flask_bcrypt import Bcrypt
from flask_login import (
	LoginManager,
	login_user,
	login_required,
	logout_user,
	current_user,
)
from models import db, User, Course, seed_courses
from utils import ensure_data_dir
from config import Config
import openai
try:
	from authlib.integrations.flask_client import OAuth
	AUTHLIB_AVAILABLE = True
except ImportError:
	OAuth = None  # type: ignore
	AUTHLIB_AVAILABLE = False
	# don't raise here; we'll show a helpful message at runtime if OAuth is used

oauth = None


app = Flask(__name__)
app.config.from_object(Config)


bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

logger = logging.getLogger(__name__)


db.init_app(app)
openai.api_key = app.config.get('OPENAI_API_KEY')
if not openai.api_key:
	logger.warning('OPENAI_API_KEY is not set — /api/ask will return an error until configured')

# OAuth setup (Google)
if AUTHLIB_AVAILABLE:
	oauth = OAuth()
	oauth.init_app(app)
	google_client_id = app.config.get('GOOGLE_CLIENT_ID')
	google_client_secret = app.config.get('GOOGLE_CLIENT_SECRET')
	if google_client_id and google_client_secret:
		oauth.register(
			name='google',
			client_id=google_client_id,
			client_secret=google_client_secret,
			server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
			client_kwargs={'scope': 'openid email profile'},
		)
	else:
		logger.info('Google OAuth not configured (GOOGLE_CLIENT_ID/SECRET missing)')
else:
	logger.warning('Authlib is not installed; Google OAuth routes are disabled. Install authlib or run inside the project venv.')


@app.context_processor
def inject_oauth_flags():
	"""Provide templates with a flag indicating whether Google OAuth is enabled."""
	enabled = bool(AUTHLIB_AVAILABLE and oauth is not None and 'google' in getattr(oauth, '_clients', {}))
	return {'oauth_enabled': enabled}

# Create data directory and initialize database once inside an app context.
# Some Flask versions may not expose `before_first_request` in this env, so do
# initialization here to ensure DB and seed data exist when the app starts.
with app.app_context():
	# Ensure the data directory inside the project is created (use BASE_DIR so
	# the directory matches the path used in Config.SQLALCHEMY_DATABASE_URI).
	project_data_dir = os.path.join(Config.BASE_DIR, 'data')
	ensure_data_dir(project_data_dir)
	db_uri = app.config.get('SQLALCHEMY_DATABASE_URI')
	try:
		logger.info('Initializing database', extra={'db_uri': db_uri, 'cwd': os.getcwd()})
	except Exception:
		# logger.extra may not be supported in simple configs; fallback
		logger.info(f'Initializing database: db_uri={db_uri} cwd={os.getcwd()}')

	# Also print to stdout so we always see the diagnostic when run from terminal
	print(f'Initializing database: db_uri={db_uri} cwd={os.getcwd()}')

	try:
		# Log both the current working directory 'data' and the project data
		# directory so we can see mismatches that cause sqlite problems.
		cwd_data_path = os.path.join(os.getcwd(), 'data')
		logger.info(f"cwd data dir exists={os.path.exists(cwd_data_path)}; path={cwd_data_path}")
		print(f"cwd data dir exists={os.path.exists(cwd_data_path)}; path={cwd_data_path}")
		logger.info(f"project data dir exists={os.path.exists(project_data_dir)}; path={project_data_dir}")
		print(f"project data dir exists={os.path.exists(project_data_dir)}; path={project_data_dir}")
		if os.path.exists(project_data_dir):
			try:
				st = os.stat(project_data_dir)
				logger.info(f"project data stat: {st}")
				print(f"project data stat: {st}")
			except Exception:
				logger.exception('stat(project_data_dir) failed')

		# If DB file exists but schema is missing new columns, try adding them
		db_file = os.path.join(project_data_dir, 'career.db')
		if os.path.exists(db_file):
			try:
				import sqlite3
				conn = sqlite3.connect(db_file)
				cur = conn.cursor()
				cur.execute("PRAGMA table_info(courses)")
				existing = [r[1] for r in cur.fetchall()]
				if 'field' not in existing:
					try:
						cur.execute("ALTER TABLE courses ADD COLUMN field TEXT")
						print('Added missing column: field')
					except Exception:
						print('Could not add column field')
				if 'description' not in existing:
					try:
						cur.execute("ALTER TABLE courses ADD COLUMN description TEXT")
						print('Added missing column: description')
					except Exception:
						print('Could not add column description')
				conn.commit()
				conn.close()
			except Exception:
				logger.exception('Failed to ALTER TABLE to add columns')

		# Create any missing tables and seed data
		db.create_all()
		seed_courses(app)
	except Exception:
		# Log but don't stop the app from starting — allow routes to run and
		# surface DB errors when they are used. This avoids startup failure
		# caused by environment-specific sqlite issues.
		logger.exception('Database initialization failed')
		print('WARNING: database initialization failed; the app will continue but DB operations may error.')


@login_manager.user_loader
def load_user(user_id):
	return User.query.get(int(user_id))



@app.route('/')
def index():
	courses_india = Course.query.filter_by(country_type='India').all()
	courses_intl = Course.query.filter_by(country_type='International').all()
	return render_template('index.html', india=courses_india, intl=courses_intl)


@app.route('/register', methods=['GET', 'POST'])
def register():
	if request.method == 'POST':
		username = request.form.get('username')
		email = request.form.get('email')
		password = request.form.get('password')
		if not username or not email or not password:
			flash('Please fill all fields', 'warning')
			return redirect(url_for('register'))
		# check existing user
		existing = User.query.filter((User.username == username) | (User.email == email)).first()
		if existing:
			flash('A user with that username or email already exists.', 'warning')
			return redirect(url_for('register'))
		pw_hash = bcrypt.generate_password_hash(password).decode('utf-8')
		user = User(username=username, email=email, password_hash=pw_hash)
		db.session.add(user)
		db.session.commit()
		flash('Registration successful. Please log in.', 'success')
		return redirect(url_for('login'))
	return render_template('register.html')


@app.route('/login', methods=['GET','POST'])
def login():
	if request.method == 'POST':
		username = (request.form.get('username') or '').strip()
		password = request.form.get('password')
		# Allow login with username OR email
		user = User.query.filter((User.username == username) | (User.email == username)).first()
		if user and bcrypt.check_password_hash(user.password_hash, password):
			login_user(user)
			flash('Logged in successfully.', 'success')
			return redirect(url_for('index'))
		flash('Invalid username or password.', 'warning')
		return redirect(url_for('login'))
	return render_template('login.html')


@app.route('/login/google')
def google_login():
	if not AUTHLIB_AVAILABLE or oauth is None or 'google' not in getattr(oauth, '_clients', {}):
		flash('Google OAuth is not configured on the server.', 'warning')
		return redirect(url_for('login'))
	redirect_uri = url_for('google_auth', _external=True)
	return oauth.google.authorize_redirect(redirect_uri)


@app.route('/auth/google/callback')
def google_auth():
	if not AUTHLIB_AVAILABLE or oauth is None or 'google' not in getattr(oauth, '_clients', {}):
		flash('Google OAuth is not configured on the server.', 'warning')
		return redirect(url_for('login'))
	try:
		token = oauth.google.authorize_access_token()
	except Exception as e:
		logger.exception('Google authorize_access_token failed')
		flash('Google login failed.', 'danger')
		return redirect(url_for('login'))

	# Try to parse id_token (OpenID) or fetch userinfo
	userinfo = None
	try:
		userinfo = oauth.google.parse_id_token(token)
	except Exception:
		try:
			resp = oauth.google.get('userinfo')
			userinfo = resp.json()
		except Exception:
			userinfo = None

	if not userinfo:
		flash('Could not fetch your Google profile.', 'danger')
		return redirect(url_for('login'))

	email = userinfo.get('email')
	name = userinfo.get('name') or email.split('@')[0]

	# Create or get local user
	with app.app_context():
		user = User.query.filter_by(email=email).first()
		if not user:
			# create a user with a random password hash (OAuth users don't use it)
			pw_hash = bcrypt.generate_password_hash(os.urandom(24)).decode('utf-8')
			username_base = email.split('@')[0]
			username = username_base
			# ensure unique username
			i = 1
			while User.query.filter_by(username=username).first():
				username = f"{username_base}{i}"
				i += 1
			user = User(username=username, email=email, password_hash=pw_hash)
			db.session.add(user)
			db.session.commit()
		login_user(user)
		flash('Logged in with Google.', 'success')
		return redirect(url_for('index'))

@app.route('/logout')
@login_required
def logout():
	logout_user()
	flash('Logged out', 'info')
	return redirect(url_for('index'))

@app.route('/dashboard')
@login_required
def dashboard():
	return render_template('dashboard.html')

@app.route('/courses')
def courses():
	india = Course.query.filter_by(country_type='India').all()
	intl = Course.query.filter_by(country_type='International').all()
	return render_template('courses.html', india=india, intl=intl)


@app.route('/ai_chat')
@login_required
def ai_chat():
	return render_template('ai_chat.html')

# AI chat endpoint
def generate_mock_answer(question: str) -> str:
	"""Return a simple, helpful fallback answer for career guidance.

	This is intentionally lightweight and deterministic — meant only as a
	development fallback when OpenAI is unavailable or rate-limited.
	"""
	q = (question or '').lower()
	parts = []
	parts.append("Here are practical steps you can start with:")
	parts.append("1) Clarify interests: identify subjects you enjoy (math, biology, computers, business, arts) and your strengths.")
	parts.append("2) Shortlist course types: for engineering — B.Tech/B.E., for CS — B.Sc/BCA, for commerce — B.Com/BBA, for medicine/allied — MBBS/BPT/B.Pharm/B.Sc Nursing, for arts — B.A./BFA.")
	parts.append("3) Entrance & eligibility: check 12th stream requirements and common entrance tests (JEE for engineering, NEET for medicine, college-specific tests for others).")
	parts.append("4) Next steps: talk to teachers, attend college open days, try small online courses (e.g., programming, accounting), and prepare for entrance tests early.")
	# Suggest courses related to keywords
	suggestions = []
	if 'computer' in q or 'program' in q or 'coding' in q or 'software' in q:
		suggestions = ["B.Tech / B.E. in Computer Science", "B.Sc. Computer Science", "BCA (Bachelor of Computer Applications)"]
	elif 'engineering' in q or 'mechanical' in q or 'civil' in q or 'elect' in q:
		suggestions = ["B.Tech / B.E. in preferred branch (CSE, ECE, Mechanical, Civil)"]
	elif 'commerce' in q or 'account' in q or 'finance' in q or 'tax' in q:
		suggestions = ["B.Com (Honours)", "BBA (Business Administration)"]
	elif 'medicine' in q or 'doctor' in q or 'neat' in q or 'mbbs' in q:
		suggestions = ["MBBS (if eligible via NEET)", "BPT / B.Sc Nursing / B.Pharm as allied options"]
	elif 'arts' in q or 'history' in q or 'languages' in q:
		suggestions = ["B.A. in your chosen subject (History, English, Economics, etc.)"]
	else:
		suggestions = ["B.Sc (Computer/Mathematics)", "B.Tech (Engineering)", "BBA / B.Com"]

	parts.append("Suggested courses based on your question:")
	for s in suggestions:
		parts.append(f"- {s}")

	parts.append("If you want, I can provide a study plan or list of entrance tests for any course above.")
	return '\n'.join(parts)


@app.route('/api/ask', methods=['POST'])
@login_required
def ask_ai():
	data = request.json or {}
	question = data.get('question')
	if not question:
		return jsonify({'error': 'No question provided'}), 400
	# Forward to OpenAI — simple chat completion
	if not openai.api_key:
		# If OpenAI is not configured but mock fallback is enabled, return a
		# local answer so the UI remains functional in development.
		if app.config.get('MOCK_AI_ON_FAILURE'):
			return jsonify({'fallback': True, 'answer': generate_mock_answer(question), 'error': 'OpenAI API key not configured; returned a local fallback answer.'}), 200
		return jsonify({'error': 'OpenAI API key not configured on server'}), 503

	try:
		# Support both old and new openai.py client APIs.
		if hasattr(openai, 'OpenAI'):
			client = openai.OpenAI()
			resp = client.chat.completions.create(
				model='gpt-4o-mini',
				messages=[
					{'role': 'system', 'content': ('You are a career guidance assistant for Indian 12th class students. Be concise, give options, suggest courses and next steps.')},
					{'role': 'user', 'content': question},
				],
				max_tokens=500,
				temperature=0.2,
			)
			choices = resp.get('choices') or []
			if not choices:
				return jsonify({'error': 'No answer from OpenAI'}), 502
			answer = choices[0].get('message', {}).get('content', '')
		else:
			resp = openai.ChatCompletion.create(
				model='gpt-4o-mini',
				messages=[
					{'role': 'system', 'content': ('You are a career guidance assistant for Indian 12th class students. Be concise, give options, suggest courses and next steps.')},
					{'role': 'user', 'content': question},
				],
				max_tokens=500,
				temperature=0.2,
			)
			choices = resp.get('choices') or []
			if not choices:
				return jsonify({'error': 'No answer from OpenAI'}), 502
			answer = choices[0].get('message', {}).get('content', '')
	except Exception as e:
		try:
			OpenAIRate = getattr(openai, 'RateLimitError', None)
		except Exception:
			OpenAIRate = None
		logger.exception('OpenAI request failed')
		if app.config.get('MOCK_AI_ON_FAILURE'):
			mock = generate_mock_answer(question)
			note = 'OpenAI unavailable or quota exceeded — returned a local fallback answer.'
			return jsonify({'error': note, 'fallback': True, 'answer': mock}), 200
		if OpenAIRate and isinstance(e, OpenAIRate):
			return jsonify({'error': 'OpenAI rate limit or quota exceeded: ' + str(e)}), 429
		return jsonify({'error': str(e)}), 502
	return jsonify({'answer': answer})

if __name__ == '__main__':
	app.run(debug=True)