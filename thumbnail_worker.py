# thumbnail_worker.py
import os
import io
from azure.storage.blob import BlobServiceClient
from azure.identity import DefaultAzureCredential
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy import Column, Integer, String, ForeignKey, Text
from PIL import Image as PILImage

connect_str = os.getenv('AZURE_STORAGE_CONNECTION_STRING')
if connect_str:
    blob_service_client = BlobServiceClient.from_connection_string(connect_str)
    print("Using connection string for Azure Storage")
else:
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

engine = create_engine(SQL_CONNECTION_STRING, pool_pre_ping=True)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

class Image(Base):
    __tablename__ = 'Images'
    imageID = Column(Integer, primary_key=True)
    caption = Column(Text)
    ownerUserID = Column(Integer, ForeignKey('Users.userID'))
    originalURL = Column(String(500))
    thumbnailURL = Column(String(500))

def create_thumbnail(image_data, size=(150, 150)):
    try:
        img = PILImage.open(io.BytesIO(image_data))

        max_dimension = 2000
        if max(img.size) > max_dimension:
            ratio = max_dimension / max(img.size)
            new_size = (int(img.size[0] * ratio), int(img.size[1] * ratio))
            img = img.resize(new_size, PILImage.Resampling.LANCZOS)

        if img.mode in ('RGBA', 'LA', 'P'):
            img = img.convert('RGB')

        img.thumbnail(size, PILImage.Resampling.LANCZOS)

        output = io.BytesIO()
        img.save(output, format='JPEG', quality=80, optimize=True)
        return output.getvalue()

    except Exception as e:
        print(f"Thumbnail generation failed: {e}")
        return None

def process_pending_thumbnails():
    db = SessionLocal()
    try:
        pending_images = db.query(Image).filter(Image.thumbnailURL == "").all()
        
        print(f"Found {len(pending_images)} images needing thumbnails")
        
        for image in pending_images:
            try:
                filename = image.originalURL.split('/')[-1]
                
                blob_client = container_client_original.get_blob_client(filename)
                if not blob_client.exists():
                    print(f"Original image not found: {filename}")
                    continue
                    
                image_data = blob_client.download_blob().readall()
                
                thumb_data = create_thumbnail(image_data)
                if thumb_data is None:
                    print(f"Failed to generate thumbnail for {filename}")
                    continue
                
                thumb_filename = f"thumb_{filename}"
                thumb_client = container_client_thumb.get_blob_client(thumb_filename)
                thumb_client.upload_blob(thumb_data, overwrite=True)
                thumb_url = f"https://friend01.blob.core.windows.net/thumbnails/{thumb_filename}"
                
                image.thumbnailURL = thumb_url
                db.commit()
                
                print(f"Successfully processed thumbnail for {filename}")
                
            except Exception as e:
                print(f"Error processing image {image.imageID}: {e}")
                db.rollback()
                continue
                
    except Exception as e:
        print(f"Error in process_pending_thumbnails: {e}")
    finally:
        db.close()

if __name__ == '__main__':
    print("Starting thumbnail worker...")
    process_pending_thumbnails()
    print("Thumbnail worker completed.")