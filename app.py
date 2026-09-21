from flask import Flask, render_template, request, redirect, url_for, session, flash, send_from_directory, abort
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import sqlite3, os, re, secrets
from functools import wraps
from datetime import datetime

try:
    from PIL import Image
    PIL_AVAILABLE = True
except ImportError:
    PIL_AVAILABLE = False

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "change-this-secret-key")
app.config["MAX_CONTENT_LENGTH"] = 5 * 1024 * 1024  # 5 MB per request
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_DIR = os.path.join(BASE_DIR, "instance")
DB_PATH = os.path.join(DB_DIR, "lost_found.db")
UPLOAD_DIR = os.path.join(BASE_DIR, "uploads")
os.makedirs(DB_DIR, exist_ok=True)
os.makedirs(UPLOAD_DIR, exist_ok=True)

ALLOWED_EXTENSIONS = {"png","jpg","jpeg","gif","webp"}
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

def db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn

def init_db():
    conn=db()
    conn.executescript("""
    CREATE TABLE IF NOT EXISTS users(
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      email TEXT NOT NULL UNIQUE,
      phone TEXT DEFAULT '',
      password_hash TEXT NOT NULL,
      role TEXT NOT NULL DEFAULT 'student',
      created_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS items(
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER,
      item_type TEXT NOT NULL,
      name TEXT NOT NULL,
      category TEXT DEFAULT '',
      location TEXT DEFAULT '',
      description TEXT DEFAULT '',
      image TEXT DEFAULT '',
      item_date TEXT DEFAULT '',
      status TEXT NOT NULL DEFAULT 'Active',
      created_at TEXT NOT NULL,
      FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE SET NULL
    );
    CREATE TABLE IF NOT EXISTS claims(
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      item_id INTEGER NOT NULL,
      claimant_user_id INTEGER,
      claimant_name TEXT NOT NULL,
      claimant_email TEXT DEFAULT '',
      claimant_phone TEXT DEFAULT '',
      other_person_name TEXT DEFAULT '',
      other_person_email TEXT DEFAULT '',
      other_person_phone TEXT DEFAULT '',
      message TEXT DEFAULT '',
      status TEXT NOT NULL DEFAULT 'Pending',
      created_at TEXT NOT NULL,
      FOREIGN KEY(item_id) REFERENCES items(id) ON DELETE CASCADE,
      FOREIGN KEY(claimant_user_id) REFERENCES users(id) ON DELETE SET NULL
    );
    CREATE TABLE IF NOT EXISTS messages(
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      claim_id INTEGER NOT NULL,
      sender_id INTEGER,
      receiver_id INTEGER,
      body TEXT NOT NULL,
      created_at TEXT NOT NULL,
      is_read INTEGER NOT NULL DEFAULT 0,
      FOREIGN KEY(claim_id) REFERENCES claims(id) ON DELETE CASCADE,
      FOREIGN KEY(sender_id) REFERENCES users(id) ON DELETE SET NULL,
      FOREIGN KEY(receiver_id) REFERENCES users(id) ON DELETE SET NULL
    );
    """)
    admin=conn.execute("SELECT id FROM users WHERE role='admin' LIMIT 1").fetchone()
    if not admin:
        conn.execute("""INSERT INTO users(name,email,phone,password_hash,role,created_at)
                        VALUES(?,?,?,?,?,?)""",
                     ("Administrator","admin@campus.local","",generate_password_hash("admin123"),
                      "admin",datetime.now().isoformat(timespec="seconds")))
    conn.commit(); conn.close()

def login_required(f):
    @wraps(f)
    def wrapper(*a,**kw):
        if "user_id" not in session:
            flash("Please log in first.","warning")
            return redirect(url_for("login"))
        return f(*a,**kw)
    return wrapper

def admin_required(f):
    @wraps(f)
    def wrapper(*a,**kw):
        if session.get("role") != "admin":
            flash("Admin access required.","danger")
            return redirect(url_for("index"))
        return f(*a,**kw)
    return wrapper

def allowed_file(filename):
    return "." in filename and filename.rsplit(".",1)[1].lower() in ALLOWED_EXTENSIONS

def is_genuine_image(file_storage):
    """Verify the upload is actually a readable image, not just a file with
    a spoofed extension. Falls back to trusting the extension if Pillow
    isn't installed."""
    if not PIL_AVAILABLE:
        return True
    try:
        file_storage.stream.seek(0)
        Image.open(file_storage.stream).verify()
        file_storage.stream.seek(0)
        return True
    except Exception:
        file_storage.stream.seek(0)
        return False

def get_csrf_token():
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_hex(16)
    return session["csrf_token"]

@app.context_processor
def inject():
    unread = 0
    if session.get("user_id"):
        conn = db()
        unread = conn.execute(
            "SELECT COUNT(*) FROM messages WHERE receiver_id=? AND is_read=0",
            (session["user_id"],),
        ).fetchone()[0]
        conn.close()
    return {
        "current_user": session.get("name"),
        "current_role": session.get("role"),
        "csrf_token": get_csrf_token,
        "nav_unread": unread,
    }

@app.before_request
def csrf_protect():
    if request.method == "POST":
        token = session.get("csrf_token")
        sent = request.form.get("csrf_token")
        if not token or not sent or not secrets.compare_digest(token, sent):
            abort(400)

@app.errorhandler(400)
def bad_request(e):
    flash("Your session expired or the form was invalid. Please try again.", "danger")
    return redirect(request.referrer or url_for("index")), 400

@app.errorhandler(413)
def too_large(e):
    flash("That file is too large. Please upload an image under 5 MB.", "danger")
    return redirect(request.referrer or url_for("index")), 413

@app.route("/")
def index():
    conn=db()
    items=conn.execute("SELECT items.*, users.name AS reporter FROM items LEFT JOIN users ON users.id=items.user_id ORDER BY items.id DESC").fetchall()
    conn.close()
    return render_template("index.html",items=items)

@app.route("/register", methods=["GET","POST"])
def register():
    if request.method=="POST":
        name=request.form["name"].strip(); email=request.form["email"].strip().lower()
        phone=request.form.get("phone","").strip(); password=request.form["password"]
        errors=[]
        if len(name) < 2:
            errors.append("Please enter your full name.")
        if not EMAIL_RE.match(email):
            errors.append("Please enter a valid email address.")
        if len(password) < 6:
            errors.append("Password must be at least 6 characters.")
        if not errors:
            try:
                conn=db()
                conn.execute("INSERT INTO users(name,email,phone,password_hash,role,created_at) VALUES(?,?,?,?,?,?)",
                             (name,email,phone,generate_password_hash(password),"student",datetime.now().isoformat(timespec="seconds")))
                conn.commit(); conn.close()
                flash("Registration successful. Please log in.","success")
                return redirect(url_for("login"))
            except sqlite3.IntegrityError:
                errors.append("Email already exists.")
        for e in errors:
            flash(e,"danger")
    return render_template("register.html")

@app.route("/login", methods=["GET","POST"])
def login():
    if request.method=="POST":
        email=request.form["email"].strip().lower(); password=request.form["password"]
        conn=db(); user=conn.execute("SELECT * FROM users WHERE email=?",(email,)).fetchone(); conn.close()
        if user and check_password_hash(user["password_hash"],password):
            session.clear(); session["user_id"]=user["id"]; session["name"]=user["name"]; session["role"]=user["role"]
            return redirect(url_for("admin_dashboard") if user["role"]=="admin" else url_for("dashboard"))
        flash("Invalid email or password.","danger")
    return render_template("login.html")

@app.route("/logout")
def logout():
    session.clear(); return redirect(url_for("index"))

@app.route("/dashboard")
@login_required
def dashboard():
    conn=db()
    items=conn.execute("SELECT * FROM items WHERE user_id=? ORDER BY id DESC",(session["user_id"],)).fetchall()
    claims=conn.execute("""SELECT claims.*,items.name AS item_name FROM claims JOIN items ON items.id=claims.item_id
                           WHERE claims.claimant_user_id=? ORDER BY claims.id DESC""",(session["user_id"],)).fetchall()
    incoming=conn.execute("""SELECT claims.*,items.name AS item_name, users.name AS claimant_account_name
                            FROM claims JOIN items ON items.id=claims.item_id                            
                          
                            LEFT JOIN users ON users.id=claims.claimant_user_id
                            WHERE items.user_id=? ORDER BY claims.id DESC""",(session["user_id"],)).fetchall()
    unread=conn.execute("SELECT COUNT(*) FROM messages WHERE receiver_id=? AND is_read=0",(session["user_id"],)).fetchone()[0]
    conn.close()
    return render_template("dashboard.html",items=items,claims=claims,incoming=incoming,unread=unread)

@app.route("/report", methods=["GET","POST"])
@login_required
def report():
    if request.method=="POST":
        if len(request.form.get("name","").strip()) < 2:
            flash("Please enter the item's name.","danger"); return render_template("report.html")
        image=request.files.get("image"); filename=""
        if image and image.filename:
            if not allowed_file(image.filename):
                flash("Unsupported image type.","danger"); return render_template("report.html")
            if not is_genuine_image(image):
                flash("That file doesn't look like a valid image.","danger"); return render_template("report.html")
            filename=secure_filename(f"{datetime.now().strftime('%Y%m%d%H%M%S')}_{secrets.token_hex(4)}_{image.filename}")
            image.save(os.path.join(UPLOAD_DIR,filename))
        conn=db()
        conn.execute("""INSERT INTO items(user_id,item_type,name,category,location,description,image,item_date,status,created_at)
                        VALUES(?,?,?,?,?,?,?,?,?,?)""",
                     (session["user_id"],request.form["item_type"],request.form["name"],request.form.get("category",""),
                      request.form.get("location",""),request.form.get("description",""),filename,
                      request.form.get("item_date",""),"Active",datetime.now().isoformat(timespec="seconds")))
        conn.commit(); conn.close()
        flash("Item reported successfully.","success"); return redirect(url_for("dashboard"))
    return render_template("report.html")

@app.route("/claim/<int:item_id>", methods=["GET","POST"])
@login_required
def claim(item_id):
    conn=db(); item=conn.execute("SELECT * FROM items WHERE id=?",(item_id,)).fetchone(); conn.close()
    if not item: return "Item not found",404
    if item["user_id"] == session["user_id"]:
        flash("You can't claim your own report.","warning"); return redirect(url_for("index"))
    if item["status"] != "Active":
        flash("This item is no longer available for claims.","warning"); return redirect(url_for("index"))
    if request.method=="POST":
        conn=db()
        conn.execute("""INSERT INTO claims(item_id,claimant_user_id,claimant_name,claimant_email,claimant_phone,
                        other_person_name,other_person_email,other_person_phone,message,status,created_at)
                        VALUES(?,?,?,?,?,?,?,?,?,?,?)""",
                     (item_id,session["user_id"],request.form["claimant_name"],request.form.get("claimant_email",""),
                      request.form.get("claimant_phone",""),request.form.get("other_person_name",""),
                      request.form.get("other_person_email",""),request.form.get("other_person_phone",""),
                      request.form.get("message",""),"Pending",datetime.now().isoformat(timespec="seconds")))
        conn.commit(); conn.close()
        flash("Claim submitted to the administrator.","success"); return redirect(url_for("dashboard"))
    return render_template("claim.html",item=item)

@app.route("/conversation/<int:claim_id>", methods=["GET", "POST"])
@login_required
def conversation(claim_id):
    conn=db()
    claim=conn.execute("""SELECT claims.*, items.name AS item_name, items.item_type, items.user_id AS reporter_id,
                         reporter.name AS reporter_name, reporter.email AS reporter_email, reporter.phone AS reporter_phone,
                         claimant.name AS claimant_account_name, claimant.email AS claimant_account_email, claimant.phone AS claimant_account_phone
                         FROM claims JOIN items ON items.id=claims.item_id
                         LEFT JOIN users reporter ON reporter.id=items.user_id
                         LEFT JOIN users claimant ON claimant.id=claims.claimant_user_id
                         WHERE claims.id=?""",(claim_id,)).fetchone()
    if not claim:
        conn.close(); return "Conversation not found",404
    uid=session["user_id"]
    if uid not in {claim["reporter_id"], claim["claimant_user_id"]}:
        conn.close(); return "You are not a participant in this conversation",403
    other_id=claim["claimant_user_id"] if uid==claim["reporter_id"] else claim["reporter_id"]
    if request.method=="POST":
        body=request.form.get("body","").strip()
        if body:
            conn.execute("INSERT INTO messages(claim_id,sender_id,receiver_id,body,created_at) VALUES(?,?,?,?,?)",
                         (claim_id,uid,other_id,body,datetime.now().isoformat(timespec="seconds")))
            conn.commit()
        return redirect(url_for("conversation",claim_id=claim_id))
    conn.execute("UPDATE messages SET is_read=1 WHERE claim_id=? AND receiver_id=?",(claim_id,uid))
    messages=conn.execute("""SELECT messages.*, users.name AS sender_name FROM messages
                            LEFT JOIN users ON users.id=messages.sender_id
                            WHERE claim_id=? ORDER BY messages.id ASC""",(claim_id,)).fetchall()
    conn.commit(); conn.close()
    return render_template("conversation.html",claim=claim,messages=messages,other_id=other_id)

@app.route("/uploads/<path:filename>")
def uploads(filename):
    return send_from_directory(UPLOAD_DIR,filename)

# ---------------- ADMIN ----------------
@app.route("/admin")
@admin_required
def admin_dashboard():
    conn=db()
    counts={
      "users":conn.execute("SELECT COUNT(*) FROM users").fetchone()[0],
      "items":conn.execute("SELECT COUNT(*) FROM items").fetchone()[0],
      "claims":conn.execute("SELECT COUNT(*) FROM claims").fetchone()[0],
      "pending":conn.execute("SELECT COUNT(*) FROM claims WHERE status='Pending'").fetchone()[0],
      "messages":conn.execute("SELECT COUNT(*) FROM messages").fetchone()[0],
    }
    recent=conn.execute("""SELECT claims.*,items.name AS item_name FROM claims JOIN items ON items.id=claims.item_id
                           ORDER BY claims.id DESC LIMIT 8""").fetchall()
    conn.close()
    return render_template("admin_dashboard.html",counts=counts,recent=recent)

@app.route("/admin/users")
@admin_required
def admin_users():
    conn=db(); users=conn.execute("SELECT id,name,email,phone,role,created_at FROM users ORDER BY id DESC").fetchall(); conn.close()
    return render_template("admin_users.html",users=users)

@app.route("/admin/users/edit/<int:user_id>",methods=["GET","POST"])
@admin_required
def admin_user_edit(user_id):
    conn=db(); user=conn.execute("SELECT * FROM users WHERE id=?",(user_id,)).fetchone()
    if not user: conn.close(); return "User not found",404
    if request.method=="POST":
        name=request.form["name"].strip(); email=request.form["email"].strip().lower(); phone=request.form.get("phone","").strip()
        role=request.form["role"]; new_password=request.form.get("password","").strip()
        try:
            if new_password:
                conn.execute("UPDATE users SET name=?,email=?,phone=?,role=?,password_hash=? WHERE id=?",
                             (name,email,phone,role,generate_password_hash(new_password),user_id))
            else:
                conn.execute("UPDATE users SET name=?,email=?,phone=?,role=? WHERE id=?",(name,email,phone,role,user_id))
            conn.commit(); conn.close()
            if user_id==session["user_id"]:
                session["name"]=name; session["role"]=role
            flash("User updated.","success"); return redirect(url_for("admin_users"))
        except sqlite3.IntegrityError:
            flash("That email is already in use.","danger")
    conn.close(); return render_template("admin_user_edit.html",user=user)

@app.route("/admin/users/delete/<int:user_id>",methods=["POST"])
@admin_required
def admin_user_delete(user_id):
    if user_id==session["user_id"]:
        flash("You cannot delete your own admin account.","danger"); return redirect(url_for("admin_users"))
    conn=db(); conn.execute("DELETE FROM users WHERE id=?",(user_id,)); conn.commit(); conn.close()
    flash("User deleted.","success"); return redirect(url_for("admin_users"))

@app.route("/admin/items")
@admin_required
def admin_items():
    conn=db(); items=conn.execute("""SELECT items.*,users.name AS reporter,users.email AS reporter_email
                                     FROM items LEFT JOIN users ON users.id=items.user_id ORDER BY items.id DESC""").fetchall(); conn.close()
    return render_template("admin_items.html",items=items)

@app.route("/admin/items/edit/<int:item_id>",methods=["GET","POST"])
@admin_required
def admin_item_edit(item_id):
    conn=db(); item=conn.execute("SELECT * FROM items WHERE id=?",(item_id,)).fetchone()
    if not item: conn.close(); return "Item not found",404
    if request.method=="POST":
        conn.execute("""UPDATE items SET item_type=?,name=?,category=?,location=?,description=?,item_date=?,status=? WHERE id=?""",
                     (request.form["item_type"],request.form["name"],request.form.get("category",""),
                      request.form.get("location",""),request.form.get("description",""),request.form.get("item_date",""),
                      request.form["status"],item_id))
        conn.commit(); conn.close(); flash("Item updated.","success"); return redirect(url_for("admin_items"))
    conn.close(); return render_template("admin_item_edit.html",item=item)

@app.route("/admin/items/delete/<int:item_id>",methods=["POST"])
@admin_required
def admin_item_delete(item_id):
    conn=db(); item=conn.execute("SELECT image FROM items WHERE id=?",(item_id,)).fetchone()
    conn.execute("DELETE FROM items WHERE id=?",(item_id,)); conn.commit(); conn.close()
    if item and item["image"]:
        try: os.remove(os.path.join(UPLOAD_DIR,item["image"]))
        except OSError: pass
    flash("Item deleted.","success"); return redirect(url_for("admin_items"))

@app.route("/admin/claims")
@admin_required
def admin_claims():
    conn=db(); claims=conn.execute("""SELECT claims.*,items.name AS item_name,items.item_type,
                                      users.name AS account_name,users.email AS account_email
                                      FROM claims JOIN items ON items.id=claims.item_id
                                      LEFT JOIN users ON users.id=claims.claimant_user_id
                                      ORDER BY claims.id DESC""").fetchall(); conn.close()
    return render_template("admin_claims.html",claims=claims)

@app.route("/admin/claims/edit/<int:claim_id>",methods=["GET","POST"])
@admin_required
def admin_claim_edit(claim_id):
    conn=db(); claim=conn.execute("""SELECT claims.*,items.name AS item_name FROM claims JOIN items ON items.id=claims.item_id
                                     WHERE claims.id=?""",(claim_id,)).fetchone()
    if not claim: conn.close(); return "Claim not found",404
    if request.method=="POST":
        conn.execute("""UPDATE claims SET claimant_name=?,claimant_email=?,claimant_phone=?,
                        other_person_name=?,other_person_email=?,other_person_phone=?,message=?,status=? WHERE id=?""",
                     (request.form["claimant_name"],request.form.get("claimant_email",""),request.form.get("claimant_phone",""),
                      request.form.get("other_person_name",""),request.form.get("other_person_email",""),
                      request.form.get("other_person_phone",""),request.form.get("message",""),request.form["status"],claim_id))
        conn.commit(); conn.close(); flash("Claim updated.","success"); return redirect(url_for("admin_claims"))
    conn.close(); return render_template("admin_claim_edit.html",claim=claim)

@app.route("/admin/claims/status/<int:claim_id>/<status>",methods=["POST"])
@admin_required
def admin_claim_status(claim_id,status):
    if status not in {"Pending","Approved","Rejected","Completed"}: return "Invalid status",400
    conn=db(); conn.execute("UPDATE claims SET status=? WHERE id=?",(status,claim_id))
    if status=="Approved":
        claim=conn.execute("SELECT item_id FROM claims WHERE id=?",(claim_id,)).fetchone()
        if claim: conn.execute("UPDATE items SET status='Claimed' WHERE id=?",(claim["item_id"],))
    if status=="Completed":
        claim=conn.execute("SELECT item_id FROM claims WHERE id=?",(claim_id,)).fetchone()
        if claim: conn.execute("UPDATE items SET status='Returned' WHERE id=?",(claim["item_id"],))
    if status in ("Pending","Rejected"):
        # Reopen the item for other claimants if no claim on it is still active.
        claim=conn.execute("SELECT item_id FROM claims WHERE id=?",(claim_id,)).fetchone()
        if claim:
            still_active=conn.execute(
                "SELECT COUNT(*) FROM claims WHERE item_id=? AND status IN ('Approved','Completed')",
                (claim["item_id"],),
            ).fetchone()[0]
            if not still_active:
                conn.execute("UPDATE items SET status='Active' WHERE id=? AND status != 'Returned'",(claim["item_id"],))
    conn.commit(); conn.close(); flash(f"Claim marked {status}.","success"); return redirect(url_for("admin_claims"))

@app.route("/admin/claims/delete/<int:claim_id>",methods=["POST"])
@admin_required
def admin_claim_delete(claim_id):
    conn=db(); conn.execute("DELETE FROM claims WHERE id=?",(claim_id,)); conn.commit(); conn.close()
    flash("Claim deleted.","success"); return redirect(url_for("admin_claims"))

@app.route("/admin/messages")
@admin_required
def admin_messages():
    conn=db()
    rows=conn.execute("""SELECT messages.*, claims.status AS claim_status, items.name AS item_name,
                       sender.name AS sender_name, receiver.name AS receiver_name
                       FROM messages JOIN claims ON claims.id=messages.claim_id JOIN items ON items.id=claims.item_id
                       LEFT JOIN users sender ON sender.id=messages.sender_id
                       LEFT JOIN users receiver ON receiver.id=messages.receiver_id
                       ORDER BY messages.id DESC""").fetchall()
    conn.close(); return render_template("admin_messages.html",messages=rows)

@app.route("/admin/messages/delete/<int:message_id>",methods=["POST"])
@admin_required
def admin_message_delete(message_id):
    conn=db(); conn.execute("DELETE FROM messages WHERE id=?",(message_id,)); conn.commit(); conn.close()
    flash("Message deleted by admin.","success"); return redirect(url_for("admin_messages"))

@app.route("/admin/settings",methods=["GET","POST"])
@admin_required
def admin_settings():
    conn=db(); admin=conn.execute("SELECT * FROM users WHERE id=?",(session["user_id"],)).fetchone()
    if request.method=="POST":
        name=request.form["name"].strip(); email=request.form["email"].strip().lower(); phone=request.form.get("phone","").strip()
        password=request.form.get("password","").strip()
        try:
            if password:
                conn.execute("UPDATE users SET name=?,email=?,phone=?,password_hash=? WHERE id=?",
                             (name,email,phone,generate_password_hash(password),session["user_id"]))
            else:
                conn.execute("UPDATE users SET name=?,email=?,phone=? WHERE id=?",(name,email,phone,session["user_id"]))
            conn.commit(); conn.close()
            session["name"]=name
            flash("Admin credentials updated successfully.","success"); return redirect(url_for("admin_settings"))
        except sqlite3.IntegrityError:
            flash("That email is already in use.","danger")
    conn.close(); return render_template("admin_settings.html",admin=admin)

@app.errorhandler(404)
def not_found(e):
    return render_template("404.html"), 404

if __name__=="__main__":
    init_db()
    app.run(debug=True, host="127.0.0.1", port=5000)
