import json
from flask import render_template, url_for, flash, redirect, request, abort, session, jsonify
from main import app, db, bcrypt, mail
from main.models import User, SavedJob
from main.forms import RegistrationForm, LoginForm, UpdateAccountForm, RequestRestForm, ResetPasswordForm
from flask_login import login_user, current_user, logout_user, login_required
from flask_mail import Message
import requests
from functools import wraps
import ast

# Custom decorator
def custom_login_required_for_save(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated:
            if request.method == 'POST':
                pending_data = {
                    'job_id': request.form.get('job_id'),
                    'api_used': request.form.get('api_used')
                }
                api_used = request.form.get('api_used')
                job_data_from_form = request.form.get('job_data')

                if api_used == 'adzuna':
                    # For Adzuna, only store minimal data if job_data_from_form is present
                    if job_data_from_form:
                        try:
                            # Try to parse it to extract key fields safely
                            temp_job_data = json.loads(job_data_from_form) 
                        except json.JSONDecodeError:
                             try:
                                # Fallback to ast.literal_eval if direct JSON fails
                                temp_job_data = ast.literal_eval(job_data_from_form)
                             except:
                                temp_job_data = None # Could not parse
                        
                        if isinstance(temp_job_data, dict):
                            pending_data['title'] = temp_job_data.get('title')
                            pending_data['company_display_name'] = temp_job_data.get('company', {}).get('display_name')
                            pending_data['location_display_name'] = temp_job_data.get('location', {}).get('display_name')
                            pending_data['redirect_url'] = temp_job_data.get('redirect_url')
                            flash(f'DEBUG custom_login (adzuna): Storing minimal data: {pending_data}', 'debug')
                        else:
                            flash(f'DEBUG custom_login (adzuna): Could not parse job_data_from_form to extract minimal fields. Storing only ID/API. Data: {job_data_from_form[:100]}', 'warning')
                    else:
                        flash('DEBUG custom_login (adzuna): job_data_from_form is None/empty. Storing only ID/API.', 'warning')
                elif api_used == 'usajobs':
                    # For USAJobs, store the full job_data as it's generally smaller/structured
                    pending_data['job_data'] = job_data_from_form
                    flash(f'DEBUG custom_login (usajobs): Storing job_data: {job_data_from_form[:100] if job_data_from_form else "None"}', 'debug')
                
                session['pending_save_job'] = pending_data
                session.modified = True
            
            next_destination_endpoint = request.url_rule.endpoint if request.url_rule else url_for('home')
            flash(f'DEBUG custom_login: Intending to redirect to login with next={next_destination_endpoint}', 'debug')
            flash('You need to be logged in to save jobs.', 'info')
            return redirect(url_for('login', next=next_destination_endpoint))
        return f(*args, **kwargs)
    return decorated_function

# Adzuna credentials
ADZUNA_APP_ID  = "07a9048c"
ADZUNA_APP_KEY = "1b7efef5faefcc8872d8c643702eb631"
ADZUNA_COUNTRY = "us"

@app.route('/', methods=['GET', 'POST'])
def home():
    jobs = []
    error_message = None
    page       = request.args.get('page', 1, type=int)
    per_page   = 10
    total_jobs = 0
    total_pages = 0
    keyword  = ""
    location = ""
    job_type = ""
    search_performed = False

    if request.method == 'POST':
        keyword  = request.form.get('query', "")
        location = request.form.get('location', "")
        job_type = request.form.get('job_type', "")
        search_performed = True
    elif request.args.get('keyword'):
        keyword  = request.args.get('keyword', "")
        location = request.args.get('location', "")
        job_type = request.args.get('job_type', "")
        search_performed = True

    if search_performed:
        batch_page = 1
        url = f"https://api.adzuna.com/v1/api/jobs/{ADZUNA_COUNTRY}/search/{batch_page}"
        params = {
            "app_id": ADZUNA_APP_ID,
            "app_key": ADZUNA_APP_KEY,
            "what": keyword,
            "where": location,
            "results_per_page": 30,
            "content-type": "application/json"
        }
        try:
            resp = requests.get(url, params=params)
            resp.raise_for_status()
            data = resp.json()
            all_jobs   = data.get("results", [])
            total_jobs = data.get("count", 0)
            if job_type:
                jt = job_type.lower()
                if jt in ("full_time", "part_time"):
                    all_jobs = [j for j in all_jobs if j.get("contract_time", "") == jt]
                elif jt == "remote":
                    all_jobs = [j for j in all_jobs if "Remote" in j.get('location', "").get('area', [])]
                total_jobs = len(all_jobs)
            total_pages = (total_jobs + per_page - 1) // per_page
            start_idx   = (page - 1) * per_page
            end_idx     = start_idx + per_page
            jobs        = all_jobs[start_idx:end_idx]
        except requests.HTTPError as e:
            error_message = f"Adzuna API error: {e.response.status_code} – {e.response.text}"
        except Exception as e:
            error_message = "Unable to fetch jobs. Please try again later."
            app.logger.exception(e)

    return render_template(
        'home.html', jobs=jobs, error_message=error_message, api_used='adzuna',
        page=page, total_pages=total_pages, total_jobs=total_jobs,
        keyword=keyword, location=location, job_type=job_type
    )

@app.route('/about')
def about():
    return render_template('about.html', title='About')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user = User(username=form.username.data, email=form.email.data, password=hashed_password)
        db.session.add(user)
        db.session.commit()
        flash(f'Account created for {form.username.data}! You are now able to log in', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', title='Register', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user, remember=form.remember.data)
            session.modified = True # Explicitly mark session as modified

            next_page_url = request.args.get('next')
            # If 'next' points to a view function name (e.g. 'save_job') from our custom decorator
            if next_page_url and next_page_url == 'save_job': # We stored the endpoint name
                 flash('Login successful! Completing pending action...', 'success')
                 return redirect(url_for(next_page_url))
            elif next_page_url: # if next_page_url is a full path
                 flash('Login successful!', 'success')
                 return redirect(next_page_url)
            else:
                 flash('Login successful!', 'success')
                 return redirect(url_for('home'))
        else:
            flash("Login Unsuccessful. Please check your email and password", 'danger')
    return render_template('login.html', title='Login', form=form)

@app.route('/logout')
def logout():
    logout_user()
    # Clear any pending actions if user logs out
    session.pop('pending_save_job', None)
    session.modified = True
    return redirect(url_for('home'))

@app.route('/account', methods=['GET', 'POST'])
@login_required
def account():
    form = UpdateAccountForm()
    if form.validate_on_submit():
        current_user.username = form.username.data
        current_user.email = form.email.data
        db.session.commit()
        flash('Your account has been updated!', 'success')
        return redirect(url_for('account'))
    elif request.method == 'GET':
        form.username.data = current_user.username
        form.email.data = current_user.email
    return render_template('account.html', title='Account', form=form)

@app.route('/save_job', methods=['GET', 'POST'])
@custom_login_required_for_save
def save_job():
    job_id, api_used, job_data_str, job_data = None, None, None, None
    source = ""
    is_ajax = request.headers.get('X-Requested-With') == 'XMLHttpRequest'

    if request.method == 'POST':
        job_id = request.form.get('job_id')
        api_used = request.form.get('api_used')
        job_data_str = request.form.get('job_data')
        source = "POST request"
        if job_data_str:
            try:
                job_data = json.loads(job_data_str)
            except json.JSONDecodeError:
                try: 
                    job_data = ast.literal_eval(job_data_str)
                except Exception as e_parse:
                    if is_ajax:
                        return jsonify({"status": "error", "message": f"Error parsing job_data from POST form: {e_parse}"}), 400
                    flash('Error parsing job_data from POST form.', 'danger')
                    return redirect(request.referrer or url_for('home'))
        else:
            if is_ajax:
                return jsonify({"status": "error", "message": "job_data missing from POST form."}), 400
            flash('job_data missing from POST form.', 'danger')
            return redirect(request.referrer or url_for('home'))

    elif request.method == 'GET' and 'pending_save_job' in session:
        pending_data = session.pop('pending_save_job')
        session.modified = True
        job_id = pending_data.get('job_id')
        api_used = pending_data.get('api_used')
        source = "session (after login)"

        if api_used == 'adzuna':
            # For Adzuna, construct a minimal job_data from stored pending_data
            # This avoids re-fetching or storing large objects in session
            job_data = {
                'id': job_id, # Adzuna ID for consistency if needed later
                'title': pending_data.get('title', 'N/A'),
                'company': {'display_name': pending_data.get('company_display_name', 'N/A')},
                'location': {'display_name': pending_data.get('location_display_name', 'N/A')},
                'redirect_url': pending_data.get('redirect_url', '#') # Important for apply link
                # Add other essential small fields if needed
            }
            flash(f'Reconstructed minimal Adzuna job_data from session: {job_data}', 'debug')
        elif api_used == 'usajobs':
            job_data_str = pending_data.get('job_data')
            if job_data_str:
                try:
                    job_data = json.loads(job_data_str)
                except json.JSONDecodeError:
                    try: # Fallback for session if data is dict-like string
                        job_data = ast.literal_eval(job_data_str)
                    except:
                        flash('Error parsing USAJobs job_data from session.', 'danger')
                        return redirect(request.referrer or url_for('home'))
            else:
                flash('USAJobs job_data missing from session pending_data.', 'danger')
                return redirect(request.referrer or url_for('home'))
    else:
        if is_ajax:
            return jsonify({"status": "error", "message": "Invalid request method or no pending data."}), 405 
        return redirect(url_for('home'))

    if not job_id or not api_used:
        if is_ajax:
            return jsonify({"status": "error", "message": f'Missing critical job information (ID or API used) (source: {source}).'}), 400
        flash(f'Missing critical job information (ID or API used) (source: {source}).', 'danger')
        return redirect(request.referrer or url_for('home'))

    if not job_data:
        if is_ajax:
            return jsonify({"status": "error", "message": f'Failed to prepare job_data for saving (source: {source}).'}), 500
        flash(f'Failed to prepare job_data for saving (source: {source}).', 'danger')
        return redirect(request.referrer or url_for('home'))

    existing = SavedJob.query.filter_by(user_id=current_user.id, job_id=job_id).first()
    if existing:
        if is_ajax:
            return jsonify({"status": "info", "message": "Job already saved!", "job_id": job_id, "saved": True})
        flash('Job already saved!', 'info')
    else:
        sj = SavedJob(user_id=current_user.id, job_id=job_id, job_data=job_data, api_used=api_used)
        db.session.add(sj)
        db.session.commit()
        if is_ajax:
            return jsonify({"status": "success", "message": "Job saved!", "job_id": job_id, "saved": True})
        flash(f'Job saved successfully (from {source})!', 'success')
    
    referrer = request.referrer
    if referrer and url_for('save_job') in referrer:
        return redirect(url_for('home'))
    return redirect(referrer or url_for('home'))

@app.route('/saved_jobs')
@login_required
def saved_jobs():
    saved_jobs_list = SavedJob.query.filter_by(user_id=current_user.id).order_by(SavedJob.saved_at.desc()).all()
    return render_template('saved_jobs.html', title='Saved Jobs', saved_jobs=saved_jobs_list)

@app.route('/unsave_job', methods=['POST'])
@login_required
def unsave_job():
    # Ensure this uses 'saved_job_id' from the form as in your template, not 'job_id'
    saved_job_db_id = request.form.get('saved_job_id') 
    if not saved_job_db_id:
        flash('No job specified to unsave.', 'danger')
        return redirect(url_for('saved_jobs'))

    sj = SavedJob.query.get(saved_job_db_id) # Use .get() for primary key lookup
    if not sj:
        abort(404) # Job not found

    if sj.user_id != current_user.id:
        abort(403) # User doesn't own this saved job
    
    db.session.delete(sj)
    db.session.commit()
    flash('Job removed from your saved list!', 'warning')
    return redirect(request.referrer or url_for('saved_jobs'))

def send_reset_email(user):
    token =user.get_reset_token()
    msg = Message('Password Reset Request', sender='noreply@demo.com', recipients=[user.email])
    msg.body = (f'''To reset your password, visit the following link:
{url_for('reset_token', token=token, _external=True)} 
If you did not make this request then simply ignore this email and no changes will be made.''')
    mail.send(msg)

@app.route('/reset_password', methods=['GET', 'POST'])
def reset_request():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = RequestRestForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user:
            send_reset_email(user)
            flash('An email has been sent with instructions to reset your password', 'info')
            return redirect(url_for('login'))
        else:
             flash('Email not found. You may need to register first.', 'warning') # Added feedback for non-existent email
    return render_template('reset_request.html', title='Reset Password', form=form)

@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_token(token):
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    user = User.verify_reset_token(token)
    if user is None:
        flash('That is an invalid or expired token', 'warning')
        return redirect(url_for('reset_request'))
    form = ResetPasswordForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user.password = hashed_password
        db.session.commit()
        flash(f'Your password has been updated! You are now able to log in.', 'success')
        return redirect(url_for('login'))
    return render_template('reset_token.html', title='Reset Password', form=form)