from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import os

app = Flask(__name__, template_folder='../public')
app.config['SECRET_KEY'] = 'your-secret-key-here'
# Ensure the database path is correct for Vercel or local execution.
# For Vercel, ephemeral filesystem might mean the DB is reset on each deploy.
# Using /tmp is a common practice for temporary storage on serverless platforms.
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:////tmp/brainclinic.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# 모델 정의
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128))
    bio = db.Column(db.Text)
    interests = db.Column(db.String(200))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # 관계
    group_memberships = db.relationship('GroupMember', backref='user', lazy='dynamic')
    posts = db.relationship('Post', backref='author', lazy='dynamic')
    # Added relationship for comments
    comments = db.relationship('Comment', backref='author', lazy='dynamic')


class StudyGroup(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text)
    category = db.Column(db.String(50))  # AI, Art, Physics, Politics, Mathematics
    created_by_user_id = db.Column(db.Integer, db.ForeignKey('user.id')) # Renamed for clarity
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_active = db.Column(db.Boolean, default=True)
    
    # 관계
    creator = db.relationship('User', backref='created_groups') # Relationship to User who created
    members = db.relationship('GroupMember', backref='group', lazy='dynamic')
    sessions = db.relationship('StudySession', backref='group', lazy='dynamic')
    posts = db.relationship('Post', backref='group', lazy='dynamic')

class GroupMember(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    group_id = db.Column(db.Integer, db.ForeignKey('study_group.id'))
    role = db.Column(db.String(20), default='member')  # admin, moderator, member
    joined_at = db.Column(db.DateTime, default=datetime.utcnow)

class StudySession(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text)
    group_id = db.Column(db.Integer, db.ForeignKey('study_group.id'))
    scheduled_time = db.Column(db.DateTime)
    location = db.Column(db.String(200))
    max_participants = db.Column(db.Integer)
    created_by_user_id = db.Column(db.Integer, db.ForeignKey('user.id')) # Renamed for clarity
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    # Relationship to User who created
    creator = db.relationship('User', backref='created_sessions')


class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    content = db.Column(db.Text, nullable=False)
    author_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    group_id = db.Column(db.Integer, db.ForeignKey('study_group.id')) # Optional: A post might not belong to a group
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow) # Added onupdate

    # Relationship for comments
    comments = db.relationship('Comment', backref='post', lazy='dynamic', cascade="all, delete-orphan")


# Comment Model (to be added as per plan step 2, but included here for completeness of app.py)
class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    post_id = db.Column(db.Integer, db.ForeignKey('post.id'), nullable=False)
    author_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    # No backref for author here, it's already in User.comments
    # No backref for post here, it's already in Post.comments

class Contact(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), nullable=False)
    message = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_read = db.Column(db.Boolean, default=False)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# 라우트들
@app.route('/')
def home():
    recent_groups = StudyGroup.query.filter_by(is_active=True).order_by(StudyGroup.created_at.desc()).limit(6).all()
    return render_template('brain.html', groups=recent_groups)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        interests = request.form.get('interests', '')
        
        if User.query.filter_by(username=username).first():
            flash('Username already exists', 'danger')
            return redirect(url_for('register'))
        
        if User.query.filter_by(email=email).first():
            flash('Email already exists', 'danger')
            return redirect(url_for('register'))
        
        user = User(
            username=username,
            email=email,
            password_hash=generate_password_hash(password, method='pbkdf2:sha256'), # Stronger hashing
            interests=interests
        )
        db.session.add(user)
        db.session.commit()
        
        login_user(user)
        flash('Registration successful! Welcome.', 'success')
        return redirect(url_for('dashboard'))
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    if request.method == 'POST':
        username = request.form['username'] # Or email, if you want to allow login with email
        password = request.form['password']
        
        user = User.query.filter_by(username=username).first()
        # Optionally, allow login with email:
        # if not user:
        #    user = User.query.filter_by(email=username).first()

        if user and check_password_hash(user.password_hash, password):
            login_user(user)
            next_page = request.args.get('next')
            flash('Login successful!', 'success')
            return redirect(next_page or url_for('dashboard'))
        else:
            flash('Invalid username or password.', 'danger')
    
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('home'))

@app.route('/dashboard')
@login_required
def dashboard():
    user_groups = db.session.query(StudyGroup).join(GroupMember).filter(
        GroupMember.user_id == current_user.id
    ).all()
    
    upcoming_sessions = db.session.query(StudySession).join(StudyGroup).join(GroupMember).filter(
        GroupMember.user_id == current_user.id,
        StudySession.scheduled_time > datetime.utcnow()
    ).order_by(StudySession.scheduled_time).limit(5).all()
    
    return render_template('dashboard.html', 
                         user_groups=user_groups, # Renamed for clarity in template
                         upcoming_sessions=upcoming_sessions)

@app.route('/groups')
def groups():
    category = request.args.get('category')
    page = request.args.get('page', 1, type=int)
    
    query = StudyGroup.query.filter_by(is_active=True)
    if category:
        query = query.filter_by(category=category)
    
    groups_pagination = query.order_by(StudyGroup.name).paginate(page=page, per_page=10) # Added pagination
    
    # Fetch distinct categories for filter dropdown
    categories_from_db = db.session.query(StudyGroup.category).distinct().all()
    categories = sorted([cat[0] for cat in categories_from_db if cat[0]]) # Ensure category is not None

    return render_template('groups.html', 
                           groups_pagination=groups_pagination, # Pass pagination object
                           categories=categories, 
                           selected_category=category)

@app.route('/group/<int:group_id>')
def group_detail(group_id):
    group = StudyGroup.query.get_or_404(group_id)
    
    members = db.session.query(User).join(GroupMember).filter(
        GroupMember.group_id == group_id
    ).all()
    
    # Paginate posts
    page = request.args.get('page', 1, type=int)
    posts_pagination = Post.query.filter_by(group_id=group_id).order_by(
        Post.created_at.desc()
    ).paginate(page=page, per_page=5) # Paginate posts

    upcoming_sessions = StudySession.query.filter_by(group_id=group_id).filter(
        StudySession.scheduled_time > datetime.utcnow()
    ).order_by(StudySession.scheduled_time).all()
    
    is_member = False
    if current_user.is_authenticated:
        is_member = GroupMember.query.filter_by(
            user_id=current_user.id, 
            group_id=group_id
        ).first() is not None
    
    return render_template('group_detail.html', 
                         group=group, 
                         members=members, 
                         posts_pagination=posts_pagination, # Pass pagination object
                         sessions=upcoming_sessions,
                         is_member=is_member)

@app.route('/join_group/<int:group_id>', methods=['POST']) # Changed to POST for better practice
@login_required
def join_group(group_id):
    group = StudyGroup.query.get_or_404(group_id)
    
    existing_membership = GroupMember.query.filter_by(
        user_id=current_user.id, 
        group_id=group_id
    ).first()
    
    if not existing_membership:
        membership = GroupMember(user_id=current_user.id, group_id=group_id)
        db.session.add(membership)
        db.session.commit()
        flash(f'Successfully joined {group.name}!', 'success')
    else:
        flash('You are already a member of this group.', 'info')
    
    return redirect(url_for('group_detail', group_id=group_id))

@app.route('/leave_group/<int:group_id>', methods=['POST'])
@login_required
def leave_group(group_id):
    group = StudyGroup.query.get_or_404(group_id)
    membership = GroupMember.query.filter_by(user_id=current_user.id, group_id=group_id).first()
    if membership:
        # Add logic: group creator cannot leave? Or transfer ownership?
        # For now, allow leaving.
        db.session.delete(membership)
        db.session.commit()
        flash(f'You have left {group.name}.', 'success')
    else:
        flash('You are not a member of this group.', 'warning')
    return redirect(url_for('group_detail', group_id=group_id))


@app.route('/contact', methods=['GET', 'POST'])
def contact():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        message = request.form['message']
        
        contact_msg = Contact(name=name, email=email, message=message)
        db.session.add(contact_msg)
        db.session.commit()
        
        flash('Thank you for your message! We will get back to you soon.', 'success')
        return redirect(url_for('home')) # Or a dedicated thank you page
    
    return render_template('contact.html')

@app.route('/admin')
@login_required
def admin():
    # This needs proper admin role checking
    # For now, just require login
    # Example: if not current_user.is_admin: abort(403)
    
    contacts = Contact.query.order_by(Contact.created_at.desc()).all()
    users_count = User.query.count()
    groups_count = StudyGroup.query.count()
    
    return render_template('admin.html', 
                         contacts=contacts,
                         users_count=users_count,
                         groups_count=groups_count)

# API 엔드포인트들 (example)
@app.route('/api/groups')
def api_groups():
    groups = StudyGroup.query.filter_by(is_active=True).all()
    return {
        'groups': [{
            'id': g.id,
            'name': g.name,
            'description': g.description,
            'category': g.category,
            'member_count': g.members.count() # Be careful with performance on large member counts
        } for g in groups]
    }

# Helper function to create tables and initial data
def create_tables_and_seed_data():
    with app.app_context():
        db.create_all()
        
        if StudyGroup.query.count() == 0:
            categories = [
                ('AI', 'Artificial Intelligence study group focusing on latest developments in AI and machine learning'),
                ('Art', 'Exploring creativity, art theory, and the intersection of art with technology'),
                ('Physics', 'Understanding fundamental laws of universe and their practical applications'),
                ('Politics', 'Analyzing current political landscapes and their global impact'),
                ('Mathematics', 'Discovering mathematical concepts and their real-world applications')
            ]
            
            # Create a default user if it doesn't exist, to be the creator of default groups
            default_user = User.query.filter_by(username='admin_user').first()
            if not default_user:
                default_user = User(username='admin_user', email='admin@example.com', password_hash=generate_password_hash('adminpass', method='pbkdf2:sha256'))
                db.session.add(default_user)
                db.session.commit() # Commit user first to get ID

            for cat, desc in categories:
                group = StudyGroup(
                    name=f"{cat} Study Group", 
                    description=desc, 
                    category=cat,
                    created_by_user_id=default_user.id # Assign creator
                )
                db.session.add(group)
            
            db.session.commit()
            print("Database initialized and default study groups created.")

# This check is important for Vercel.
# Vercel runs the app by importing 'app' from this file.
# The __name__ == '__main__' block won't run in Vercel's environment.
# Database initialization needs to be handled differently for serverless.
# For now, we can call it manually or via a separate script for local dev.
if __name__ == '__main__':
    create_tables_and_seed_data() # Call the helper function
    app.run(debug=True)

# Expose the Flask app instance for Vercel
application = app

@app.route('/user/<username>')
@login_required # Or remove if profiles can be public
def user_profile(username):
    user = User.query.filter_by(username=username).first_or_404()
    # Fetch groups the user is a member of
    user_groups = StudyGroup.query.join(GroupMember).filter(GroupMember.user_id == user.id).all()
    return render_template('user_profile.html', user=user, user_groups=user_groups)

@app.route('/create_group', methods=['GET', 'POST'])
@login_required
def create_group():
    if request.method == 'POST':
        name = request.form.get('name')
        description = request.form.get('description')
        category = request.form.get('category')

        if not name or not category:
            flash('Group name and category are required.', 'danger')
            return render_template('create_group.html')

        # Check if group with the same name already exists (optional, but good practice)
        if StudyGroup.query.filter_by(name=name).first():
            flash(f'A group named "{name}" already exists. Please choose a different name.', 'warning')
            return render_template('create_group.html', name=name, description=description, category=category)

        new_group = StudyGroup(
            name=name,
            description=description,
            category=category,
            created_by_user_id=current_user.id  # Correctly assign creator
        )
        db.session.add(new_group)
        db.session.commit() # Commit to get new_group.id

        # Add creator as a member (e.g., admin)
        admin_membership = GroupMember(
            user_id=current_user.id,
            group_id=new_group.id,
            role='admin'
        )
        db.session.add(admin_membership)
        db.session.commit()

        flash(f'Study group "{name}" created successfully!', 'success')
        return redirect(url_for('group_detail', group_id=new_group.id))
    
    # Pre-populate categories for the form, similar to the groups page
    categories_from_db = db.session.query(StudyGroup.category).distinct().all()
    defined_categories = ['AI', 'Art', 'Physics', 'Politics', 'Mathematics'] # Default/expected
    current_categories = sorted(list(set(defined_categories + [cat[0] for cat in categories_from_db if cat[0]])))

    return render_template('create_group.html', categories=current_categories)

@app.route('/group/<int:group_id>/post/create', methods=['POST'])
@login_required
def create_post(group_id):
    group = StudyGroup.query.get_or_404(group_id)
    is_member = GroupMember.query.filter_by(user_id=current_user.id, group_id=group.id).first()

    if not is_member:
        flash('You must be a member of the group to create a post.', 'danger')
        return redirect(url_for('group_detail', group_id=group_id))

    title = request.form.get('title')
    content = request.form.get('content')

    if not title or not content:
        flash('Post title and content are required.', 'danger')
        return redirect(url_for('group_detail', group_id=group_id)) # Or render with error

    new_post = Post(
        title=title,
        content=content,
        author_id=current_user.id,
        group_id=group_id
    )
    db.session.add(new_post)
    db.session.commit()

    flash('Post created successfully!', 'success')
    return redirect(url_for('post_detail', post_id=new_post.id)) # Redirect to the new post's page

@app.route('/post/<int:post_id>')
def post_detail(post_id):
    post = Post.query.get_or_404(post_id)
    # Paginate comments if you expect many, for now, load all
    comments = Comment.query.filter_by(post_id=post.id).order_by(Comment.created_at.asc()).all()
    return render_template('post_detail.html', post=post, comments=comments)

@app.route('/post/<int:post_id>/comment/create', methods=['POST'])
@login_required
def create_comment(post_id):
    post = Post.query.get_or_404(post_id) # Ensure post exists
    content = request.form.get('content')

    if not content:
        flash('Comment content cannot be empty.', 'danger')
        return redirect(url_for('post_detail', post_id=post_id))

    new_comment = Comment(
        content=content,
        post_id=post_id,
        author_id=current_user.id
    )
    db.session.add(new_comment)
    db.session.commit()

    flash('Comment added successfully!', 'success')
    return redirect(url_for('post_detail', post_id=post_id))
