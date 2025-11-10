# app.py
from flask import Flask, render_template, request, redirect, url_for, flash, session, send_from_directory
from werkzeug.utils import secure_filename
from azure.storage.blob import BlobServiceClient
from azure.identity import DefaultAzureCredential
from sqlalchemy import create_engine, Column, Integer, String, ForeignKey, Text
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, relationship
import os
from PIL import Image
import io
import bcrypt

app = Flask(__name__, template_folder='templates')
app.secret_key = 'your-secret-key-change-in-production'  # 生产环境改强密钥

# ==================== Azure 配置 ====================
# 从环境变量读取（VM 和本地都支持）
connect_str = os.getenv('AZURE_STORAGE_CONNECTION_STRING')
if connect_str:
    blob_service_client = BlobServiceClient.from_connection_string(connect_str)
else:
    # 本地开发用托管身份（或模拟）
    credential = DefaultAzureCredential()
    blob_service_client = BlobServiceClient(
        account_url="https://furryfriendsstorage.blob.core.windows.net",
        credential=credential
    )

container_client_original = blob_service_client.get_container_client("originals")
container_client_thumb = blob_service_client.get_container_client("thumbnails")

# === 本地开发用密码，Azure VM 用托管身份 ===
SQL_CONNECTION_STRING = os.getenv('SQL_CONNECTION_STRING',
    # 本地默认：用 SQL 密码
    'mssql+pyodbc:///?odbc_connect=Driver={ODBC Driver 18 for SQL Server};'
    'Server=tcp:friend.database.windows.net,1433;Database=friend;'
    'Uid=adminuser;Pwd=Password123;Encrypt=yes;TrustServerCertificate=no;'
    'Connection Timeout=30;'
)
# 如果环境变量有值（VM 上），优先使用
if 'Authentication=ActiveDirectoryMSI' in SQL_CONNECTION_STRING:
    print("Using Azure Managed Identity (VM)")
else:
    print("Using SQL Authentication (Local)")

engine = create_engine(SQL_CONNECTION_STRING, pool_pre_ping=True)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# ==================== 数据库模型 ====================
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

# ==================== 辅助函数 ====================
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in {'png', 'jpg', 'jpeg', 'gif'}

def create_thumbnail(image_data, size=(150, 150)):
    img = Image.open(io.BytesIO(image_data))
    img.thumbnail(size)
    output = io.BytesIO()
    img.save(output, format='JPEG', quality=85)
    return output.getvalue()

# ==================== 路由 ====================
@app.route('/images/<path:filename>')
def custom_static(filename):
    return send_from_directory('images', filename)

@app.route('/')
def index():
    db = SessionLocal()
    images = db.query(Image).order_by(Image.imageID.desc()).all()
    db.close()
    return render_template('index.html', images=images)

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
            flash('注册成功！请登录', 'success')
            return redirect(url_for('login'))
        except:
            db.rollback()
            flash('用户名已存在', 'danger')
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
            flash('登录成功！', 'success')
            return redirect(url_for('index'))
        else:
            flash('用户名或密码错误', 'danger')
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('已退出登录', 'info')
    return redirect(url_for('index'))

@app.route('/upload', methods=['GET', 'POST'])
def upload():
    if 'user_id' not in session:
        flash('请先登录', 'warning')
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        if 'file' not in request.files:
            flash('没有选择文件', 'danger')
            return redirect(request.url)
        file = request.files['file']
        caption = request.form.get('caption', '')
        
        if file.filename == '':
            flash('没有选择文件', 'danger')
            return redirect(request.url)
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file_data = file.read()
            
            # 上传原图
            blob_client = container_client_original.get_blob_client(filename)
            blob_client.upload_blob(file_data, overwrite=True)
            original_url = f"https://furryfriendsstorage.blob.core.windows.net/originals/{filename}"
            
            # 生成缩略图
            thumb_data = create_thumbnail(file_data)
            thumb_filename = f"thumb_{filename}"
            thumb_client = container_client_thumb.get_blob_client(thumb_filename)
            thumb_client.upload_blob(thumb_data, overwrite=True)
            thumb_url = f"https://furryfriendsstorage.blob.core.windows.net/thumbnails/{thumb_filename}"
            
            # 保存到数据库
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
            
            flash('上传成功！', 'success')
            return redirect(url_for('index'))
        else:
            flash('不支持的文件格式', 'danger')
    
    return render_template('upload.html')

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)