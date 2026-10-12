from flask import Flask, render_template, request, redirect, url_for, session, flash
import sqlite3, os, time
from functools import wraps
import werkzeug
from werkzeug.security import generate_password_hash, check_password_hash
import secrets

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY") or secrets.token_hex(32)
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = os.environ.get("COOKIE_SECURE", "false").lower() == "true"
app.config["MAX_CONTENT_LENGTH"] = 100 * 1024 * 1024  # 100 MB upload limit
ALLOWED_VIDEO_EXTENSIONS = {".mp4", ".webm", ".mov", ".m4v", ".avi"}
DB_FILE = "buzz.db"

UPLOAD_FOLDER = "static/uploads"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER

def get_db():
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    cur = conn.cursor()

    # Users
    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            premium INTEGER DEFAULT 0
        )
    """)

    # Videos
    cur.execute("""
        CREATE TABLE IF NOT EXISTS videos (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            uploader TEXT NOT NULL,
            filepath TEXT,
            likes INTEGER DEFAULT 0
        )
    """)

    # Likes
    cur.execute("""
        CREATE TABLE IF NOT EXISTS likes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            video_id INTEGER,
            user TEXT,
            UNIQUE(video_id, user)
        )
    """)

    # Comments
    cur.execute("""
        CREATE TABLE IF NOT EXISTS comments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            video_id INTEGER,
            user TEXT,
            text TEXT
        )
    """)

    # Messages (Publichat)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user TEXT,
            message TEXT
        )
    """)

    # Reports (Admin)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS reports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            reporter TEXT,
            reported_user TEXT,
            reason TEXT,
            status TEXT DEFAULT 'pending'
        )
    """)

    # Follows
    cur.execute("""
        CREATE TABLE IF NOT EXISTS follows (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            follower TEXT,
            following TEXT
        )
    """)

    conn.commit()
    conn.close()

# Initialize DB at startup
init_db()

# Premium decorator
def premium_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "user" not in session:
            flash("You must log in first.", "warning")
            return redirect(url_for("login"))

        conn = get_db()
        cur = conn.cursor()
        cur.execute("SELECT premium FROM users WHERE username=?", (session["user"],))
        user = cur.fetchone()
        conn.close()

        if not user:
            session.clear()
            flash("Your account no longer exists. Please sign up again.", "danger")
            return redirect(url_for("signup"))

        if user["premium"] == 0:
            start = session.get("login_time", 0)
            now = int(time.time())
            if now - start > 600:  # 10 minutes
                session.clear()
                flash("Your free 10‑minute session expired. Upgrade to premium!", "danger")
                return redirect(url_for("login"))

        return f(*args, **kwargs)
    return decorated_function
@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        if not username or len(username) > 40 or len(password) < 8:
            flash("Enter a username (up to 40 characters) and a password of at least 8 characters.", "danger")
            return render_template("signup.html")

        conn = get_db()
        cur = conn.cursor()
        try:
            cur.execute("INSERT INTO users (username, password, premium) VALUES (?, ?, ?)",
                        (username, generate_password_hash(password), 0))
            conn.commit()
            flash("Signup successful! Please log in.", "success")
            return redirect(url_for("login"))
        except sqlite3.IntegrityError:
            flash("Username already exists.", "danger")
        finally:
            conn.close()
    return render_template("signup.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        conn = get_db()
        cur = conn.cursor()
        cur.execute("SELECT * FROM users WHERE username=?", (username,))
        user = cur.fetchone()

        valid_password = False
        if user:
            stored_password = user["password"] or ""
            if stored_password.startswith(("scrypt:", "pbkdf2:")):
                try:
                    valid_password = check_password_hash(stored_password, password)
                except (ValueError, TypeError):
                    valid_password = False
            else:
                # Migrate legacy plaintext passwords after a successful login.
                valid_password = secrets.compare_digest(stored_password, password)
                if valid_password:
                    cur.execute("UPDATE users SET password=? WHERE username=?",
                                (generate_password_hash(password), username))
                    conn.commit()
        conn.close()

        if user and valid_password:
            session.clear()
            session["user"] = user["username"]
            session["admin"] = (user["username"] == "admin")
            session["login_time"] = int(time.time())
            flash("Login successful!", "success")
            return redirect(url_for("home"))
        else:
            flash("Invalid credentials.", "danger")

    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    flash("Logged out successfully.", "info")
    return redirect(url_for("login"))


@app.route("/")
@premium_required
def home():
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT * FROM videos ORDER BY id DESC")
    videos = cur.fetchall()

    premium = 0
    cur.execute("SELECT premium FROM users WHERE username=?", (session["user"],))
    user = cur.fetchone()
    if user:
        premium = user["premium"]

    conn.close()
    return render_template("home.html", videos=videos, premium=premium)

@app.route("/video/<int:id>", methods=["GET", "POST"])
@premium_required
def video(id):
    conn = get_db()
    cur = conn.cursor()

    if request.method == "POST":
        text = request.form["text"]
        cur.execute("INSERT INTO comments (video_id, user, text) VALUES (?, ?, ?)",
                    (id, session["user"], text))
        conn.commit()

    cur.execute("SELECT * FROM videos WHERE id=?", (id,))
    v = cur.fetchone()
    cur.execute("SELECT * FROM comments WHERE video_id=?", (id,))
    comments = cur.fetchall()

    cur.execute("SELECT premium FROM users WHERE username=?", (session["user"],))
    user = cur.fetchone()
    conn.close()

    premium = user["premium"] if user else 0
    return render_template("video.html", v=v, comments=comments, premium=premium)


@app.route("/upload", methods=["GET", "POST"])
@premium_required
def upload():
    if request.method == "POST":
        title = request.form["title"]
        file = request.files.get("file")

        if not file or file.filename == "":
            flash("No file selected.", "danger")
            return redirect(url_for("upload"))

        original_name = werkzeug.utils.secure_filename(file.filename)
        extension = os.path.splitext(original_name)[1].lower()
        if extension not in ALLOWED_VIDEO_EXTENSIONS:
            flash("Unsupported file type. Upload an MP4, WebM, MOV, M4V, or AVI video.", "danger")
            return redirect(url_for("upload"))

        # A random stored name prevents collisions and avoids trusting user-supplied paths.
        filename = f"{secrets.token_hex(16)}{extension}"
        save_path = os.path.join(app.config["UPLOAD_FOLDER"], filename)
        file.save(save_path)

        web_path = url_for("static", filename=f"uploads/{filename}")

        conn = get_db()
        cur = conn.cursor()
        cur.execute("INSERT INTO videos (title, uploader, filepath) VALUES (?, ?, ?)",
                    (title, session["user"], web_path))
        conn.commit()
        conn.close()

        flash("Video uploaded successfully!", "success")
        return redirect(url_for("home"))

    return render_template("upload.html")


@app.route("/leaderboard")
@premium_required
def leaderboard():
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT title, likes FROM videos ORDER BY likes DESC LIMIT 5")
    videos = cur.fetchall()
    conn.close()

    titles = [v["title"] for v in videos]
    likes = [v["likes"] for v in videos]

    return render_template("leaderboard.html", titles=titles, likes=likes, videos=videos)


@app.route("/publichat", methods=["GET", "POST"])
@premium_required
def publichat():
    conn = get_db()
    cur = conn.cursor()

    if request.method == "POST":
        msg = request.form["message"]
        cur.execute("INSERT INTO messages (user, message) VALUES (?, ?)",
                    (session["user"], msg))
        conn.commit()

    cur.execute("SELECT * FROM messages ORDER BY id DESC LIMIT 20")
    messages = cur.fetchall()
    conn.close()

    return render_template("publichat.html", messages=messages)


@app.route("/profile")
@premium_required
def profile():
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT * FROM videos WHERE uploader=?", (session["user"],))
    videos = cur.fetchall()
    cur.execute("SELECT * FROM users WHERE username=?", (session["user"],))
    user = cur.fetchone()
    cur.execute("SELECT following FROM follows WHERE follower=?", (session["user"],))
    subs = cur.fetchall()
    conn.close()

    return render_template("profile.html", user=user, videos=videos, subs=subs)


@app.route("/settings", methods=["GET", "POST"])
@premium_required
def settings():
    if request.method == "POST":
        flash("Settings updated!", "success")
        return redirect(url_for("profile"))
    return render_template("settings.html")
@app.route("/like/<int:id>", methods=["POST"])
@premium_required
def like_video(id):
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT * FROM videos WHERE id=?", (id,))
    video = cur.fetchone()
    if not video:
        conn.close()
        flash("Video not found.", "danger")
        return redirect(url_for("home"))

    # Prevent self-like
    if video["uploader"] == session["user"]:
        conn.close()
        flash("You cannot like your own video.", "warning")
        return redirect(url_for("video", id=id))

    # Check if user already liked
    cur.execute("SELECT * FROM likes WHERE video_id=? AND user=?", (id, session["user"]))
    existing = cur.fetchone()

    if existing:
        # Unlike
        cur.execute("DELETE FROM likes WHERE video_id=? AND user=?", (id, session["user"]))
        cur.execute("UPDATE videos SET likes = likes - 1 WHERE id=?", (id,))
        flash("You unliked the video.", "info")
    else:
        # Like
        cur.execute("INSERT INTO likes (video_id, user) VALUES (?, ?)", (id, session["user"]))
        cur.execute("UPDATE videos SET likes = likes + 1 WHERE id=?", (id,))
        flash("You liked the video!", "success")

    conn.commit()
    conn.close()
    return redirect(url_for("video", id=id))


@app.route("/follow/<string:username>", methods=["POST"])
@premium_required
def follow_user(username):
    conn = get_db()
    cur = conn.cursor()

    if username == session["user"]:
        conn.close()
        flash("You cannot follow yourself.", "warning")
        return redirect(url_for("profile"))

    cur.execute("SELECT * FROM follows WHERE follower=? AND following=?", (session["user"], username))
    existing = cur.fetchone()

    if existing:
        flash(f"You already follow {username}.", "info")
    else:
        cur.execute("INSERT INTO follows (follower, following) VALUES (?, ?)", (session["user"], username))
        conn.commit()
        flash(f"You are now following {username}!", "success")

    conn.close()
    return redirect(url_for("profile"))


@app.route("/admin")
def admin_dashboard():
    if not session.get("admin"):
        flash("Admin access required.", "danger")
        return redirect(url_for("home"))

    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT * FROM videos")
    videos = cur.fetchall()
    cur.execute("SELECT * FROM comments")
    comments = cur.fetchall()
    cur.execute("SELECT * FROM users")
    users = cur.fetchall()
    cur.execute("SELECT * FROM reports")
    reports = cur.fetchall()
    cur.execute("SELECT * FROM messages")
    messages = cur.fetchall()
    conn.close()

    return render_template("admin.html",
                           videos=videos,
                           comments=comments,
                           users=users,
                           reports=reports,
                           messages=messages)


@app.route("/admin/delete_video/<int:id>", methods=["POST"])
def admin_delete_video(id):
    if not session.get("admin"):
        return redirect(url_for("home"))
    conn = get_db()
    cur = conn.cursor()
    cur.execute("DELETE FROM videos WHERE id=?", (id,))
    conn.commit()
    conn.close()
    flash("Video deleted.", "info")
    return redirect(url_for("admin_dashboard"))


@app.route("/admin/delete_comment/<int:id>", methods=["POST"])
def admin_delete_comment(id):
    if not session.get("admin"):
        return redirect(url_for("home"))
    conn = get_db()
    cur = conn.cursor()
    cur.execute("DELETE FROM comments WHERE id=?", (id,))
    conn.commit()
    conn.close()
    flash("Comment deleted.", "info")
    return redirect(url_for("admin_dashboard"))


@app.route("/admin/delete_message/<int:id>", methods=["POST"])
def admin_delete_message(id):
    if not session.get("admin"):
        return redirect(url_for("home"))
    conn = get_db()
    cur = conn.cursor()
    cur.execute("DELETE FROM messages WHERE id=?", (id,))
    conn.commit()
    conn.close()
    flash("Message deleted.", "info")
    return redirect(url_for("admin_dashboard"))


@app.route("/admin/grant_premium/<int:id>", methods=["POST"])
def admin_grant_premium(id):
    if not session.get("admin"):
        return redirect(url_for("home"))
    conn = get_db()
    cur = conn.cursor()
    cur.execute("UPDATE users SET premium=1 WHERE id=?", (id,))
    conn.commit()
    conn.close()
    flash("Premium granted.", "success")
    return redirect(url_for("admin_dashboard"))


@app.route("/admin/kick_user/<int:id>", methods=["POST"])
def admin_kick_user(id):
    if not session.get("admin"):
        return redirect(url_for("home"))
    conn = get_db()
    cur = conn.cursor()
    cur.execute("DELETE FROM users WHERE id=?", (id,))
    conn.commit()
    conn.close()
    flash("User kicked.", "info")
    return redirect(url_for("admin_dashboard"))


@app.route("/admin/mark_report_reviewed/<int:id>", methods=["POST"])
def admin_mark_report_reviewed(id):
    if not session.get("admin"):
        return redirect(url_for("home"))
    conn = get_db()
    cur = conn.cursor()
    cur.execute("UPDATE reports SET status='reviewed' WHERE id=?", (id,))
    conn.commit()
    conn.close()
    flash("Report marked as reviewed.", "success")
    return redirect(url_for("admin_dashboard"))


if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=5000, debug=True)
