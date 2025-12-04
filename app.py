import os
import time
import mimetypes
import logging
import threading
import uuid
import hashlib
import io
import subprocess
import json
import re
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from xml.etree import ElementTree as ET

from flask import Flask, render_template, request, jsonify, send_file, abort
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import text, Index
from sqlalchemy.dialects.postgresql import JSONB
from werkzeug.utils import secure_filename
from dotenv import load_dotenv

# --- METADATA LIBRARIES ---
try:
    from PIL import Image, ExifTags
    Image.MAX_IMAGE_PIXELS = None 
    from hachoir.parser import createParser
    from hachoir.metadata import extractMetadata
except ImportError:
    print("Warning: Pillow or Hachoir not installed.")

try:
    import openpyxl
except ImportError:
    print("Warning: openpyxl not installed. Excel metadata will be skipped.")

try:
    from pypdf import PdfReader
except ImportError:
    print("Warning: pypdf not installed. PDF content will not be indexed.")

load_dotenv()

IGNORED_FOLDERS = {
    '$RECYCLE.BIN', 'System Volume Information', '#recycle', '@eaDir', '__pycache__', '.git'
}

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL', 'postgresql://nas_user:ben@localhost:5432/netdrive_db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'lan_secret_key_123')

app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
    'pool_size': 20,
    'max_overflow': 40,
    'pool_recycle': 1800
}

NETWORK_DRIVE_ROOT = os.getenv('NETWORK_DRIVE_ROOT', 'D:/') 

# --- FFMPEG CONFIGURATION (Option 2 Implementation) ---
# Defaults to just 'ffmpeg' if not found in .env
FFMPEG_EXE = os.getenv('FFMPEG_PATH', 'ffmpeg')

db = SQLAlchemy(app)
logger = logging.getLogger('NetDrive')
logging.basicConfig(level=logging.INFO)

scan_lock = threading.Lock()
scan_status = {"running": False, "progress": "", "session_id": None}

# --- DATABASE MODELS ---

class TimestampMixin(object):
    created_at = db.Column(db.DateTime, server_default=db.func.now(), nullable=False)
    updated_at = db.Column(db.DateTime, server_default=db.func.now(), onupdate=db.func.now(), nullable=False)

class FileAsset(db.Model, TimestampMixin):
    __tablename__ = 'file_assets'
    
    id = db.Column(db.String(64), primary_key=True) 
    name = db.Column(db.Text, nullable=False)
    rel_path = db.Column(db.Text, nullable=False, index=True)
    parent_path = db.Column(db.Text, index=True)
    is_folder = db.Column(db.Boolean, default=False)
    size_bytes = db.Column(db.BigInteger, default=0)
    mime_type = db.Column(db.String(100))
    last_modified = db.Column(db.DateTime)
    meta_data = db.Column(JSONB, default={})
    last_scan_session = db.Column(db.String(36), index=True)
    has_thumbnail = db.Column(db.Boolean, default=False)

    __table_args__ = (
        Index('idx_meta_gin', meta_data, postgresql_using='gin'),
        Index('idx_name_trigram', name, postgresql_ops={"name": "gin_trgm_ops"}, postgresql_using='gin'),
    )

    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'path': self.rel_path,
            'is_folder': self.is_folder,
            'size': self.size_bytes,
            'modified': self.last_modified.strftime('%Y-%m-%d') if self.last_modified else '',
            'mime': self.mime_type,
            'meta': self.meta_data,
            'has_thumbnail': self.has_thumbnail
        }

class FileThumbnail(db.Model):
    __tablename__ = 'file_thumbnails'
    id = db.Column(db.String(64), primary_key=True)
    small_blob = db.Column(db.LargeBinary)
    large_blob = db.Column(db.LargeBinary)

# --- HELPER: XMP PARSER ---

def extract_xmp_data(full_path):
    """
    Scans file binary for XMP packet and extracts DigiKam/Face tags.
    """
    xmp_meta = {}
    try:
        # Read the first 128KB to find the XMP packet (Standard locations)
        with open(full_path, 'rb') as f:
            raw_data = f.read(131072)
            
        # Look for XMP Start/End tags
        start_pattern = b'<x:xmpmeta'
        end_pattern = b'</x:xmpmeta>'
        
        start_idx = raw_data.find(start_pattern)
        if start_idx == -1:
            # Fallback: look for generic packet wrapper
            start_pattern = b'<?xpacket begin='
            end_pattern = b'<?xpacket end='
            start_idx = raw_data.find(start_pattern)
            
        if start_idx != -1:
            end_idx = raw_data.find(end_pattern, start_idx)
            if end_idx != -1:
                xmp_bytes = raw_data[start_idx:end_idx + len(end_pattern)]
                xmp_str = xmp_bytes.decode('utf-8', errors='ignore')
                
                # Parse XML: Strip namespaces for simpler parsing
                xmp_str = re.sub(r'\sxmlns:[\w]+="[^"]+"', '', xmp_str)
                xmp_str = re.sub(r'[\w]+:([\w]+)=', r'\1=', xmp_str) 
                xmp_str = re.sub(r'<(\/?)[\w]+:([\w]+)', r'<\1\2', xmp_str) 
                
                root = ET.fromstring(xmp_str)
                
                keywords = set()
                
                # 1. Dublin Core Subjects (Standard Tags)
                for subject in root.findall(".//subject/Bag/li"):
                    if subject.text: keywords.add(subject.text.strip())

                # 2. DigiKam Tags List
                for tag in root.findall(".//TagsList/Seq/li"):
                    if tag.text: keywords.add(tag.text.strip())

                # 3. Microsoft Keywords
                for tag in root.findall(".//LastKeywordXMP/Bag/li"):
                    if tag.text: keywords.add(tag.text.strip())
                
                # 4. People / Faces (IPTC Extension)
                people = set()
                for person in root.findall(".//PersonInImage/Bag/li"):
                    if person.text: people.add(person.text.strip())
                
                if keywords: xmp_meta['xmp_tags'] = list(keywords)
                if people: xmp_meta['xmp_people'] = list(people)
                
    except Exception as e:
        pass
        
    return xmp_meta

# --- THUMBNAIL ENGINE ---

def generate_binary_thumbnails(full_path, mime):
    def img_to_bytes(img_obj, size):
        img_copy = img_obj.copy()
        img_copy.thumbnail(size)
        buf = io.BytesIO()
        if img_copy.mode in ("RGBA", "P"): img_copy = img_copy.convert("RGB")
        img_copy.save(buf, format="JPEG", quality=70)
        return buf.getvalue()

    try:
        if mime.startswith('image'):
            with Image.open(full_path) as img:
                b_small = img_to_bytes(img, (300, 300))
                b_large = img_to_bytes(img, (800, 800))
                return b_small, b_large

        elif mime.startswith('video'):
            # UPDATED: Use FFMPEG_EXE from .env
            cmd = [
                FFMPEG_EXE, '-ss', '00:00:03', '-i', full_path, 
                '-vframes', '1', '-f', 'image2pipe', '-vcodec', 'png', '-'
            ]
            process = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=10)
            if process.stdout:
                with Image.open(io.BytesIO(process.stdout)) as img:
                    b_small = img_to_bytes(img, (300, 300))
                    b_large = img_to_bytes(img, (800, 800))
                    return b_small, b_large

    except Exception:
        pass
    return None, None

# --- METADATA EXTRACTION ENGINE ---

def extract_file_metadata(full_path, mime):
    meta = {}
    if not mime: return meta

    try:
        # 1. IMAGES (Windows XP Tags + XMP + EXIF)
        if mime.startswith('image'):
            try:
                xmp_data = extract_xmp_data(full_path)
                meta.update(xmp_data)

                with Image.open(full_path) as img:
                    meta['res'] = f"{img.width}x{img.height}"
                    exif = img._getexif()
                    if exif:
                        xp_tags = {
                            40091: 'Title', 40092: 'Comment', 
                            40093: 'Author', 40094: 'Keywords', 40095: 'Subject'
                        }
                        for tag_id, val in exif.items():
                            tag_name = ExifTags.TAGS.get(tag_id, tag_id)
                            
                            if tag_id in xp_tags and isinstance(val, bytes):
                                try:
                                    decoded_val = val.decode('utf-16le').replace('\x00', '').strip()
                                    if decoded_val: meta[xp_tags[tag_id]] = decoded_val
                                except: pass
                            elif tag_name in ['Model', 'Make', 'DateTimeOriginal', 'ImageDescription']:
                                if isinstance(val, bytes):
                                    try: meta[tag_name] = val.decode()
                                    except: pass
                                else:
                                    meta[tag_name] = str(val).strip()
            except Exception: pass

        # 2. VIDEOS (FFmpeg Metadata)
        elif mime.startswith('video'):
            try:
                # UPDATED: Use FFMPEG_EXE from .env
                cmd = [FFMPEG_EXE, '-i', full_path, '-f', 'ffmetadata', '-']
                res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=5)
                if res.stdout:
                    text_data = res.stdout.decode(errors='ignore')
                    for line in text_data.split('\n'):
                        if '=' in line:
                            k, v = line.split('=', 1)
                            k = k.lower().strip()
                            if k in ['title', 'comment', 'description', 'album', 'artist', 'date']:
                                meta[k] = v.strip()
            except Exception: pass

        # 3. EXCEL (OpenPyXL)
        elif 'spreadsheet' in mime or mime.endswith('xlsx'):
            try:
                wb = openpyxl.load_workbook(full_path, read_only=True)
                props = wb.properties
                if props.keywords: meta['keywords'] = props.keywords
                if props.title: meta['title'] = props.title
                if props.description: meta['description'] = props.description
                wb.close()
            except Exception: pass

        # 4. PDF CONTENT INDEXING
        elif mime == 'application/pdf':
            try:
                reader = PdfReader(full_path)
                text_content = ""
                for i, page in enumerate(reader.pages):
                    if i >= 5: break
                    extracted = page.extract_text()
                    if extracted: text_content += extracted + " "
                
                if text_content:
                    meta['content'] = text_content[:5000].strip()
                    meta['pages'] = len(reader.pages)
            except Exception: pass

        # 5. TEXT FILES
        elif mime.startswith('text') or mime.endswith('txt') or mime.endswith('md'):
            try:
                with open(full_path, 'r', encoding='utf-8', errors='ignore') as f:
                    snippet = f.read(2048)
                    if snippet: meta['content'] = snippet
            except Exception: pass

    except Exception as e:
        logger.error(f"Meta error {full_path}: {e}")
    
    return meta

# --- SCANNING LOGIC ---

def get_path_hash(path):
    return hashlib.sha256(path.encode('utf-8')).hexdigest()

def process_file_node(root, filename, rel_parent, session_id):
    full_path = os.path.join(root, filename)
    rel_path = os.path.join(rel_parent, filename).replace("\\", "/")
    path_id = get_path_hash(rel_path)
    
    try:
        stats = os.stat(full_path)
        mtime = datetime.fromtimestamp(stats.st_mtime)
        mime, _ = mimetypes.guess_type(filename)
        if not mime: mime = ""
        
        meta = extract_file_metadata(full_path, mime)
        thumb_small, thumb_large = generate_binary_thumbnails(full_path, mime)
        has_thumb = (thumb_small is not None)

        asset_data = {
            'id': path_id, 'name': filename, 'rel_path': rel_path, 'parent_path': rel_parent,
            'is_folder': False, 'size_bytes': stats.st_size, 'last_modified': mtime,
            'mime_type': mime, 'meta_data': meta, 'last_scan_session': session_id,
            'has_thumbnail': has_thumb
        }

        thumb_data = None
        if has_thumb:
            thumb_data = {'id': path_id, 'small_blob': thumb_small, 'large_blob': thumb_large}

        return asset_data, thumb_data

    except Exception as e:
        logger.error(f"Error processing {filename}: {e}")
        return None, None

def background_scanner(app_context, session_id):
    global scan_status
    logger.info(f"Starting Scan: {session_id}")
    
    # Register Types
    mimetypes.add_type('image/x-canon-cr3', '.cr3')
    mimetypes.add_type('image/heic', '.heic')
    mimetypes.add_type('application/vnd.openxmlformats-officedocument.spreadsheetml.sheet', '.xlsx')
    
    with app_context:
        from sqlalchemy.dialects.postgresql import insert
        BATCH_SIZE = 50
        pending_assets = []
        pending_thumbs = []
        
        def flush_batch():
            if not pending_assets: return
            stmt = insert(FileAsset).values(pending_assets)
            stmt = stmt.on_conflict_do_update(
                index_elements=['id'],
                set_={
                    'size_bytes': stmt.excluded.size_bytes,
                    'last_modified': stmt.excluded.last_modified,
                    'mime_type': stmt.excluded.mime_type,
                    'meta_data': stmt.excluded.meta_data,
                    'last_scan_session': stmt.excluded.last_scan_session,
                    'has_thumbnail': stmt.excluded.has_thumbnail
                }
            )
            db.session.execute(stmt)

            if pending_thumbs:
                t_stmt = insert(FileThumbnail).values(pending_thumbs)
                t_stmt = t_stmt.on_conflict_do_update(
                    index_elements=['id'],
                    set_={'small_blob': t_stmt.excluded.small_blob, 'large_blob': t_stmt.excluded.large_blob}
                )
                db.session.execute(t_stmt)

            db.session.commit()
            pending_assets.clear()
            pending_thumbs.clear()

        with ThreadPoolExecutor(max_workers=4) as executor:
            futures = []
            for root, dirs, files in os.walk(NETWORK_DRIVE_ROOT):
                dirs[:] = [d for d in dirs if d not in IGNORED_FOLDERS and not d.startswith('.')]
                rel_root = os.path.relpath(root, NETWORK_DRIVE_ROOT).replace("\\", "/")
                if rel_root == ".": rel_root = ""
                
                scan_status["progress"] = f"Scanning: {rel_root}"
                
                for d in dirs:
                    r_path = os.path.join(rel_root, d).replace("\\", "/")
                    p_path = os.path.dirname(r_path).replace("\\", "/")
                    pid = get_path_hash(r_path)
                    pending_assets.append({
                        'id': pid, 'name': d, 'rel_path': r_path, 'parent_path': p_path, 
                        'is_folder': True, 'last_scan_session': session_id,
                        'size_bytes': 0, 'mime_type': None, 'last_modified': None, 'meta_data': {}, 'has_thumbnail': False
                    })

                for f in files:
                    futures.append(executor.submit(process_file_node, root, f, rel_root, session_id))
                
                done_indices = []
                for i, f in enumerate(futures):
                    if f.done():
                        asset, thumb = f.result()
                        if asset: pending_assets.append(asset)
                        if thumb: pending_thumbs.append(thumb)
                        done_indices.append(i)
                for i in sorted(done_indices, reverse=True): del futures[i]
                if len(pending_assets) >= BATCH_SIZE: flush_batch()
            
            for f in as_completed(futures):
                asset, thumb = f.result()
                if asset: pending_assets.append(asset)
                if thumb: pending_thumbs.append(thumb)
            flush_batch()

        db.session.execute(text("DELETE FROM file_assets WHERE last_scan_session != :sid"), {"sid": session_id})
        db.session.commit()
        
        scan_status["running"] = False
        scan_status["progress"] = "Idle"

# --- ROUTES ---

@app.route('/')
def index(): return render_template('index.html')

@app.route('/api/thumb/<file_id>/<size>')
def serve_db_thumbnail(file_id, size):
    column = "small_blob" if size == 'small' else "large_blob"
    sql = text(f"SELECT {column} FROM file_thumbnails WHERE id = :id")
    result = db.session.execute(sql, {"id": file_id}).fetchone()
    if result and result[0]: return send_file(io.BytesIO(result[0]), mimetype='image/jpeg')
    return abort(404)

@app.route('/api/preview')
def preview_file():
    path = request.args.get('path')
    safe_path = os.path.normpath(os.path.join(NETWORK_DRIVE_ROOT, path))
    if not safe_path.startswith(os.path.abspath(NETWORK_DRIVE_ROOT)): return abort(403)
    mime, _ = mimetypes.guess_type(safe_path)
    return send_file(safe_path, mimetype=mime, as_attachment=False)

@app.route('/api/files')
def list_files():
    search = request.args.get('q', '').strip()
    path = request.args.get('path', '')
    query = FileAsset.query
    if search:
        term = f"%{search}%"
        # Search includes filenames, XMP tags, People, and PDF content
        query = query.filter((FileAsset.name.ilike(term)) | (FileAsset.meta_data.cast(db.Text).ilike(term)))
    else:
        query = query.filter_by(parent_path=path)
    results = query.order_by(FileAsset.is_folder.desc(), FileAsset.name).limit(500).all()
    return jsonify([f.to_dict() for f in results])

@app.route('/api/scan', methods=['POST'])
def trigger_scan():
    global scan_status
    if scan_status["running"]: return jsonify({'status': 'error', 'message': 'Scan running'})
    session_id = str(uuid.uuid4())
    scan_status["running"] = True
    scan_status["session_id"] = session_id
    scan_status["progress"] = "Starting..."
    thread = threading.Thread(target=background_scanner, args=(app.app_context(), session_id))
    thread.daemon = True
    thread.start()
    return jsonify({'status': 'started'})

@app.route('/api/scan/status')
def get_scan_status(): return jsonify(scan_status)

@app.route('/api/download')
def download_file():
    path = request.args.get('path')
    safe_path = os.path.normpath(os.path.join(NETWORK_DRIVE_ROOT, path))
    if not safe_path.startswith(os.path.abspath(NETWORK_DRIVE_ROOT)): return abort(403)
    return send_file(safe_path, as_attachment=True)

with app.app_context():
    db.create_all()
    try:
        db.session.execute(text("CREATE EXTENSION IF NOT EXISTS pg_trgm"))
        db.session.commit()
    except Exception: pass

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True, threaded=True)