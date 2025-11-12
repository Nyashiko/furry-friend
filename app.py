# app.py
from flask import Flask, render_template, request, redirect, url_for, flash, session, send_from_directory
from werkzeug.utils import secure_filename
from azure.storage.blob import BlobServiceClient
from azure.identity import DefaultAzureCredential
from sqlalchemy import create_engine, Column, Integer, String, ForeignKey, Text
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, relationship, joinedload
from sqlalchemy.exc import SQLAlchemyError
import os
from PIL import Image
import io
import bcrypt
import traceback

app = Flask(__name__, template_folder='templates')
app.secret_key = 'your-secret-key-change-in-production'

# Azure Configuration
try:
    connect_str = os.getenv('AZURE_STORAGE_CONNECTION_STRING')
    if connect_str:
        blob_service_client = BlobServiceClient.from_connection_string(connect_str)
        print("Using connection string for Azure Storage")
    else:
        credential = DefaultAzureCredential()
        blob_service_client = BlobServiceClient(
            account_url="https://furryfriendsstorage.blob.core.windows.net",
            credential=credential
        )
        print("Using DefaultAzureCredential for Azure Storage")

    container_client_original = blob_service_client.get_container_client("originals")
    container_client_thumb = blob_service_client.get_container_client("thumbnails")
    print("Azure Storage clients initialized successfully")
    
except Exception as e:
    print(f"Azure Storage initialization failed: {str(e)}")
    blob_service_client = None
    container_client_original = None
    container_client_thumb = None

# Database Configuration - FIXED: Force SQL Authentication
SQL_CONNECTION_STRING = 'mssql+pyodbc:///?odbc_connect=' + \
    'Driver={ODBC Driver 18 for SQL Server};' + \
    'Server=tcp:friend.database.windows.net,1433;' + \
    'Database=friend;' + \
    'Uid=adminuser;' + \
    'Pwd=Password123;' + \
    'Encrypt=yes;' + \
    'TrustServerCertificate=no;' + \
    'Connection Timeout=30;'

print("Using SQL Authentication with username/password")
try:
    engine = create_engine(SQL_CONNECTION_STRING, pool_pre_ping=True)
    SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    Base = declarative_base()
    print("Database engine created successfully with SQL auth")
except Exception as e:
    print(f"Database connection failed: {e}")
    engine = None
    SessionLocal = None

# Database Models
class User(Base):
    __tablename__ = 'Users'
    userID = Column(Integer, primary_key=True)
    username = Column(String(50), unique=True, nullable=False)
    hashed_password = Column(String(255), nullable=False)
    images = relationship("Image", back_populates="owner")

class Image(Base):
    __tablename__ = 'Images'
    imageID = Column(Integer, primary_key=True)
    caption = Column(Text)
    ownerUserID = Column(Integer, ForeignKey('Users.userID'))
    originalURL = Column(String(500))
    thumbnailURL = Column(String(500))
    owner = relationship("User", back_populates="images")

# Create tables
try:
    if engine:
        Base.metadata.create_all(bind=engine)
        print("Database tables created/verified successfully")
    else:
        print("Cannot create tables - engine is None")
except Exception as e:
    print(f"Table creation failed: {str(e)}")

# Helper Functions
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in {'png', 'jpg', 'jpeg', 'gif'}

def create_thumbnail(image_data, size=(150, 150)):
    try:
        img = Image.open(io.BytesIO(image_data))
        img.thumbnail(size)
        output = io.BytesIO()
        img.save(output, format='JPEG', quality=85)
        return output.getvalue()
    except Exception as e:
        print(f"Thumbnail creation failed: {str(e)}")
        raise

# Error handler
@app.errorhandler(500)
def internal_error(error):
    return "Internal Server Error - Check server logs for details", 500

@app.errorhandler(404)
def not_found_error(error):
    return "Page not found", 404

# Routes
@app.route('/')
def index():
    try:
        if not SessionLocal:
            flash('Database connection unavailable.', 'danger')
            return render_template('index.html', images=[])
            
        db = SessionLocal()
        # Use joinedload to avoid lazy loading issues
        images = db.query(Image).options(joinedload(Image.owner)).order_by(Image.imageID.desc()).all()
        db.close()
        return render_template('index.html', images=images)
    except Exception as e:
        print(f"Error in index route: {str(e)}")
        flash('Error loading images.', 'danger')
        return render_template('index.html', images=[])

@app.route('/gallery')
def gallery():
    try:
        if not SessionLocal:
            flash('Database connection unavailable.', 'danger')
            return render_template('gallery.html', images=[], users_count=0)
            
        db = SessionLocal()
        images = db.query(Image).options(joinedload(Image.owner)).order_by(Image.imageID.desc()).all()
        users_count = db.query(User).count()
        db.close()
        return render_template('gallery.html', images=images, users_count=users_count)
    except Exception as e:
        print(f"Error in gallery route: {str(e)}")
        flash('Error loading gallery.', 'danger')
        return render_template('gallery.html', images=[], users_count=0)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        if not SessionLocal:
            flash('Database connection unavailable.', 'danger')
            return redirect(url_for('register'))
            
        try:
            hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
            
            db = SessionLocal()
            new_user = User(username=username, hashed_password=hashed)
            db.add(new_user)
            db.commit()
            db.close()
            
            flash('Registration successful! Please login.', 'success')
            return redirect(url_for('login'))
            
        except SQLAlchemyError as e:
            if db:
                db.rollback()
            print(f"Registration error: {str(e)}")
            flash('Username already exists.', 'danger')
        except Exception as e:
            if db:
                db.rollback()
            print(f"Unexpected registration error: {str(e)}")
            flash('Registration failed.', 'danger')
        finally:
            if 'db' in locals():
                db.close()
                
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        if not SessionLocal:
            flash('Database connection unavailable.', 'danger')
            return redirect(url_for('login'))
            
        try:
            db = SessionLocal()
            user = db.query(User).filter(User.username == username).first()
            
            if user and bcrypt.checkpw(password.encode('utf-8'), user.hashed_password.encode('utf-8')):
                session['user_id'] = user.userID
                session['username'] = user.username
                flash('Login successful!', 'success')
                return redirect(url_for('index'))
            else:
                flash('Invalid username or password.', 'danger')
                
        except Exception as e:
            print(f"Login error: {str(e)}")
            flash('Login failed.', 'danger')
        finally:
            if 'db' in locals():
                db.close()
                
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('index'))

@app.route('/upload', methods=['GET', 'POST'])
def upload():
    if 'user_id' not in session:
        flash('Please login first.', 'warning')
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        if not container_client_original or not container_client_thumb:
            flash('Storage service unavailable.', 'danger')
            return redirect(request.url)
            
        if 'file' not in request.files:
            flash('No file selected.', 'danger')
            return redirect(request.url)
            
        file = request.files['file']
        caption = request.form.get('caption', '')
        
        if file.filename == '':
            flash('No file selected.', 'danger')
            return redirect(request.url)
            
        if file and allowed_file(file.filename):
            try:
                filename = secure_filename(file.filename)
                file_data = file.read()
                
                # Upload original image
                blob_client = container_client_original.get_blob_client(filename)
                blob_client.upload_blob(file_data, overwrite=True)
                original_url = f"https://furryfriendsstorage.blob.core.windows.net/originals/{filename}"
                
                # Generate and upload thumbnail
                thumb_data = create_thumbnail(file_data)
                thumb_filename = f"thumb_{filename}"
                thumb_client = container_client_thumb.get_blob_client(thumb_filename)
                thumb_client.upload_blob(thumb_data, overwrite=True)
                thumb_url = f"https://furryfriendsstorage.blob.core.windows.net/thumbnails/{thumb_filename}"
                
                # Save to database
                if not SessionLocal:
                    flash('Database connection unavailable.', 'danger')
                    return redirect(request.url)
                    
                db = SessionLocal()
                new_image = Image(
                    caption=caption,
                    ownerUserID=session['user_id'],
                    originalURL=original_url,
                    thumbnailURL=thumb_url
                )
                db.add(new_image)
                db.commit()
                db.close()
                
                flash('Upload successful!', 'success')
                return redirect(url_for('index'))
                
            except Exception as e:
                print(f"Upload error: {str(e)}")
                traceback.print_exc()
                flash('Upload failed.', 'danger')
        else:
            flash('Unsupported file format.', 'danger')
    
    return render_template('upload.html')

# Health check endpoint
@app.route('/health')
def health_check():
    status = {
        'database': 'ok' if SessionLocal else 'failed',
        'azure_storage': 'ok' if blob_service_client else 'failed',
        'session': 'ok' if session else 'failed'
    }
    return status

# Debug endpoint
@app.route('/debug')
def debug_page():
    return render_template('debug.html')

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)