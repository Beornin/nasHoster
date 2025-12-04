
# LAN Drive Indexer & Viewer

A robust, self-hosted web application to index, search, and view files on a local network drive. This application scans a specified directory, extracts rich metadata (EXIF, XMP, PDF text, Excel properties), generates thumbnails for images and videos, and stores everything in a PostgreSQL database for high-performance searching and retrieval.

## 🚀 Features

  * **High-Performance UI:** Responsive grid layout with dynamic thumbnail resizing (via slider).
  * **Rich Metadata Extraction:**
      * **Images:** Index EXIF data, Windows XP Keywords, DigiKam tags, and XMP Face tags.
      * **Videos:** Extract technical metadata (duration, resolution) and generate poster frames.
      * **Documents:** Index content from PDFs (first 5 pages) and properties from Excel files.
  * **Deep Search:** Full-text search capabilities across filenames, image tags, and document content.
  * **Optimized Database Storage:**
      * Metadata is stored in a `JSONB` column for flexible querying.
      * Thumbnails (Small & Large) are stored as BLOBs in a separate table (`file_thumbnails`) to keep directory listings fast.
  * **Media Previews:** Built-in modal for viewing images and playing videos directly in the browser.
  * **Background Scanning:** Non-blocking threaded scanner to process thousands of files without freezing the UI.

## 🛠 Tech Stack

  * **Backend:** Python (Flask), SQLAlchemy
  * **Database:** PostgreSQL (with `pg_trgm` extension for text search)
  * **Frontend:** HTML5, Vanilla JavaScript, Tailwind CSS
  * **Processing:**
      * `Pillow`: Image processing.
      * `FFmpeg`: Video thumbnail generation and metadata.
      * `pypdf` & `openpyxl`: Document parsing.

## 📋 Prerequisites

1.  **Python 3.8+**
2.  **PostgreSQL Database** installed and running.
3.  **FFmpeg** installed on the system (required for video processing).

## ⚙️ Installation

### 1\. Clone & Setup

Download the codebase to a folder. Open a terminal in that folder.

```bash
# Create a virtual environment
python -m venv venv

# Activate it (Windows)
venv\Scripts\activate

# Activate it (Mac/Linux)
source venv/bin/activate
```

### 2\. Install Dependencies

Create a file named `requirements.txt` with the contents below, then install:

```txt
Flask
Flask-SQLAlchemy
psycopg2-binary
python-dotenv
Pillow
hachoir
openpyxl
pypdf
```

```bash
pip install -r requirements.txt
```

### 3\. Database Setup

Create a PostgreSQL user and database (or use your existing credentials).

```sql
CREATE USER nas_user WITH PASSWORD 'ben';
CREATE DATABASE netdrive_db OWNER nas_user;
-- Optional: Grant superuser if extensions need to be installed manually
ALTER USER nas_user WITH SUPERUSER;
```

### 4\. FFmpeg Setup

You must have `ffmpeg.exe` on your system.

1.  Download FFmpeg from [gyan.dev](https://www.gyan.dev/ffmpeg/builds/).
2.  Extract it to a permanent location (e.g., `C:/ffmpeg/`).
3.  Note the full path to the executable (e.g., `C:/ffmpeg/bin/ffmpeg.exe`).

### 5\. Configuration (.env)

Create a `.env` file in the root directory. This configures the app without changing the code.

```ini
# Database Connection String
DATABASE_URL=postgresql://nas_user:ben@localhost:5432/netdrive_db

# Security Key for Flask Sessions
SECRET_KEY=super_secret_key_change_this

# The Root Folder you want to scan
NETWORK_DRIVE_ROOT=D:/MyPictures

# Path to FFmpeg executable (Use forward slashes / even on Windows)
FFMPEG_PATH=C:/ffmpeg/bin/ffmpeg.exe
```

## 🏃‍♂️ Running the Application

Once configured, run the Flask application:

```bash
python app.py
```

  * The server will start at `http://localhost:5000`.
  * The database tables will be created automatically on the first run.

## 📖 Usage Guide

1.  **Scanning:**

      * Click the **Refresh/Sync Icon** (arrows) in the top right.
      * This triggers a background job. A status bar will appear at the bottom showing progress (e.g., "Scanning: /2023/Holidays").
      * **Note:** The first scan will take time as it generates thumbnails and indexes text.

2.  **Viewing:**

      * Navigate folders by clicking cards.
      * Use the **Breadcrumbs** at the top to go back.
      * **Size Slider:** Drag the slider in the header to resize thumbnails from small grid to large preview cards instantly.

3.  **Searching:**

      * Type in the search bar and hit Enter.
      * **What it finds:**
          * File names (e.g., "IMG\_2023").
          * EXIF/XMP Tags (e.g., "Family", "Vacation").
          * People Tags (from DigiKam/Windows).
          * PDF Content (text inside documents).
          * Excel Metadata (Title, Subject).

## 🏗 Architecture Notes

### Database Schema

We use a **Split-Table Design** for performance:

1.  **`file_assets` table:**

      * Contains lightweight metadata (Name, Path, Size, MimeType, JSON Metadata).
      * Used for listing files and searching. It is fast to query.
      * Has a boolean flag `has_thumbnail`.

2.  **`file_thumbnails` table:**

      * Contains heavy Binary Data (`BYTEA`).
      * Stores `small_blob` (\~300px) and `large_blob` (\~800px).
      * Only accessed when the browser specifically requests an image via `/api/thumb/...`.

### Metadata Logic

  * **XMP Parsing:** The app manually scans the first 128KB of image files to find XMP packets, allowing it to read hierarchical tags from DigiKam and Microsoft Photo Gallery without external C++ libraries.
  * **PDFs:** Uses `pypdf` to read the first 5 pages of any PDF to make the content searchable without bloating the database with entire books.
