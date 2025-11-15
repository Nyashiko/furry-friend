# app.py
from flask import Flask, render_template, request, redirect, url_for, flash, session, send_from_directory
from werkzeug.utils import secure_filename
from azure.storage.blob import BlobServiceClient
from azure.identity import DefaultAzureCredential
from sqlalchemy import create_engine, Column, Integer, String, ForeignKey, Text
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, relationship, joinedload
import os
import bcrypt


app = Flask(__name__, template_folder='templates')
app.secret_key = 'your-secret-key-change-in-production'

connect_str = os.getenv('AZURE_STORAGE_CONNECTION_STRING')
if connect_str:
    blob_service_client = BlobServiceClient.from_connection_string(connect_str)
    print("Using connection string for Azure Storage")
else:
    from azure.identity import DefaultAzureCredential
    credential = DefaultAzureCredential()
    blob_service_client = BlobServiceClient(
        account_url="https://friend01.blob.core.windows.net",
        credential=credential
    )
    print("Using DefaultAzureCredential for Azure Storage")

container_client_original = blob_service_client.get_container_client("originals")
container_client_thumb = blob_service_client.get_container_client("thumbnails")

SQL_CONNECTION_STRING = os.getenv('SQL_CONNECTION_STRING',
    'mssql+pyodbc://adminuser:Password123@friend.database.windows.net:1433/friend?driver=ODBC+Driver+18+for+SQL+Server&Encrypt=yes&TrustServerCertificate=no&Connection+Timeout=30'
)

print("Using SQL Authentication")

engine = create_engine(SQL_CONNECTION_STRING, pool_pre_ping=True)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

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

Base.metadata.create_all(bind=engine)

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in {'png', 'jpg', 'jpeg', 'gif'}

@app.route('/images/<path:filename>')
def custom_static(filename):
    return send_from_directory('images', filename)

@app.route('/')
def index():
    db = SessionLocal()
    try:
        images = db.query(Image).options(joinedload(Image.owner)).order_by(Image.imageID.desc()).limit(12).all()
        
        for image in images:
            if not image.thumbnailURL:
                image.display_url = image.originalURL
            else:
                image.display_url = image.thumbnailURL
                
        return render_template('index.html', images=images)
    finally:
        db.close()

@app.route('/gallery')
def gallery():
    db = SessionLocal()
    try:
        page = request.args.get('page', 1, type=int)
        per_page = 20
        
        images = db.query(Image).options(joinedload(Image.owner)).order_by(Image.imageID.desc()).offset((page-1)*per_page).limit(per_page).all()
        
        for image in images:
            if not image.thumbnailURL:
                image.display_url = image.originalURL
            else:
                image.display_url = image.thumbnailURL
        
        total_images = db.query(Image).count()
        total_pages = (total_images + per_page - 1) // per_page
        
        return render_template('gallery.html', images=images, page=page, total_pages=total_pages)
    finally:
        db.close()

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        
        db = SessionLocal()
        try:
            new_user = User(username=username, hashed_password=hashed)
            db.add(new_user)
            db.commit()
            flash('Registration successful! Please login.', 'success')
            return redirect(url_for('login'))
        except:
            db.rollback()
            flash('Username already exists.', 'danger')
        finally:
            db.close()
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        db = SessionLocal()
        user = db.query(User).filter(User.username == username).first()
        db.close()
        
        if user and bcrypt.checkpw(password.encode('utf-8'), user.hashed_password.encode('utf-8')):
            session['user_id'] = user.userID
            session['username'] = user.username
            flash('Login successful!', 'success')
            return redirect(url_for('index'))
        else:
            flash('Invalid username or password.', 'danger')
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
        try:
            if 'file' not in request.files:
                flash('No file selected.', 'danger')
                return redirect(request.url)
            file = request.files['file']
            caption = request.form.get('caption', '')
            
            if file.filename == '':
                flash('No file selected.', 'danger')
                return redirect(request.url)
                
            if file and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                file_data = file.read()
                
                if len(file_data) == 0:
                    flash('File is empty.', 'danger')
                    return redirect(request.url)
                
                blob_client = container_client_original.get_blob_client(filename)
                blob_client.upload_blob(file_data, overwrite=True)
                original_url = f"https://friend01.blob.core.windows.net/originals/{filename}"
                
                db = SessionLocal()
                try:
                    new_image = Image(
                        caption=caption,
                        ownerUserID=session['user_id'],
                        originalURL=original_url,
                        thumbnailURL=""
                    )
                    db.add(new_image)
                    db.commit()
                    flash('Upload successful! Thumbnail will be generated shortly.', 'success')
                    return redirect(url_for('gallery'))
                except Exception as e:
                    db.rollback()
                    flash(f'Database error: {str(e)}', 'danger')
                    return redirect(request.url)
                finally:
                    db.close()
            else:
                flash('Unsupported file format. Please upload JPG, JPEG, PNG, or GIF.', 'danger')
                
        except Exception as e:
            flash(f'Upload failed: {str(e)}', 'danger')
            return redirect(request.url)
    
    return render_template('upload.html')

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)