from flask import Flask, send_from_directory, request, jsonify, session, redirect
import os
import json
import time
import secrets
from typing import Optional
from werkzeug.security import check_password_hash, generate_password_hash
import random
import string

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

app = Flask(
    __name__,
    static_folder=BASE_DIR,
    static_url_path=''
)

# Required for server-side sessions (protects against localStorage tampering)
app.secret_key = os.environ.get('FLASK_SECRET_KEY', 'dev-secret-key-change-me')

DATA_FILE = os.path.join(BASE_DIR, 'data.json')

# Storage format: list of { "email": str, "pass": str (hashed) }
DEFAULT_LIST: list[dict] = []


def _read_users_list() -> list[dict]:
    try:
        if not os.path.exists(DATA_FILE) or os.path.getsize(DATA_FILE) == 0:
            return []
        with open(DATA_FILE, 'r', encoding='utf-8') as f:
            data = json.load(f)
            return data if isinstance(data, list) else []
    except Exception:
        return []


def _write_users_list(users: list[dict]):
    with open(DATA_FILE, 'w', encoding='utf-8') as f:
        json.dump(users, f, ensure_ascii=False, indent=2)


def _find_user(users: list[dict], email: str) -> Optional[dict]:
    for u in users:
        if isinstance(u, dict) and u.get('email') == email:
            return u
    return None



def _generate_unique_code(existing: set[str], length: int = 7) -> str:
    alphabet = string.ascii_letters + string.digits
    # Ensure first char is a letter to match sample like Ez34Als
    while True:
        first = random.choice(string.ascii_letters)
        rest = ''.join(random.choice(alphabet) for _ in range(length - 1))
        code = first + rest
        if code not in existing:
            return code



def _ensure_user_code(users: list[dict], user: dict) -> bool:
    """Assign a unique immutable code to user if missing. Returns True if modified."""
    if user is None:
        return False
    if user.get('code'):
        return False
    existing = {u.get('code') for u in users if isinstance(u, dict) and u.get('code')}
    user['code'] = _generate_unique_code(existing, length=7)
    return True



def _backfill_all_codes():
    try:
        users = _read_users_list()
        changed = False
        for u in users:
            if isinstance(u, dict) and _ensure_user_code(users, u):
                changed = True
        if changed:
            _write_users_list(users)
    except Exception:
        pass


# Backfill codes for existing users at startup (one-time, safe)
_backfill_all_codes()


@app.route('/')
def root():
    return redirect('/main')


@app.route('/index.html')
def index_alias():
    return redirect('/main')


@app.route('/main')
def main_page():
    return send_from_directory(BASE_DIR, 'index.html')


@app.route('/market.html')
def market_protected():
    # Server-side gate: only allow if authenticated in session
    try:
        if not session.get('user_email'):
            return redirect('/main?login_required=1')
    except Exception:
        return redirect('/main?login_required=1')
    return send_from_directory(BASE_DIR, 'market.html')


@app.route('/<path:path>')
def static_proxy(path: str):
    return send_from_directory(BASE_DIR, path)


# Security: disable raw users dump endpoint (was leaking credentials)
@app.get('/api/storage')
def api_get_storage():
    return jsonify({"ok": False, "error": "not allowed"}), 404


@app.post('/api/storage')
def api_post_storage():
    try:
        payload = request.get_json(silent=True) or {}
        email = (payload.get('email') or '').strip()
        password = (payload.get('pass') or '').strip()
        name = (payload.get('name') or '').strip()
        if not email or not password:
            return jsonify({"ok": False, "error": "email and pass are required"}), 400
        users = _read_users_list()
        # Security: do NOT allow overwriting existing accounts here.
        # If email already exists, return conflict. Use a dedicated, verified flow to change passwords.
        for u in users:
            if isinstance(u, dict) and u.get('email') == email:
                return jsonify({"ok": False, "error": "account exists"}), 409
        # Hash password before storing
        hashed = generate_password_hash(password)
        # Accept optional display name at creation time
        users.append({
            "email": email,
            "pass": hashed,
            "name": name,
            "email_changed": False,
            "name_changed": False,
            "code": None,
        })
        # Assign unique code
        _ensure_user_code(users, users[-1])
        _write_users_list(users)
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 400


@app.get('/api/account_exists')
def api_account_exists():
    email = (request.args.get('email') or '').strip()
    if not email:
        return jsonify({"exists": False})
    users = _read_users_list()
    exists = _find_user(users, email) is not None
    return jsonify({"exists": exists})


@app.post('/api/login')
def api_login():
    try:
        payload = request.get_json(silent=True) or {}
        email = (payload.get('email') or '').strip()
        password = (payload.get('pass') or '').strip()
        if not email or not password:
            return jsonify({"ok": False}), 400
        users = _read_users_list()
        u = _find_user(users, email)
        if not u:
            return jsonify({"ok": False}), 401
        # Backfill immutable code if missing
        if _ensure_user_code(users, u):
            _write_users_list(users)
        stored = u.get('pass') or ''
        # If legacy plaintext was stored, allow one-time login then upgrade on reset/change
        valid = False
        try:
            valid = check_password_hash(stored, password)
        except Exception:
            valid = (stored == password)
        if not valid:
            return jsonify({"ok": False}), 401
        # Establish server-side session
        session['user_email'] = email
        return jsonify({"ok": True})
    except Exception:
        return jsonify({"ok": False}), 400


# In-memory code store and verification tokens (single-process dev use)
CODE_STORE: dict[str, dict] = {}
VERIFIED_TOKENS: dict[str, dict] = {}
CODE_TTL_SECONDS = 5 * 60
TOKEN_TTL_SECONDS = 5 * 60

# Pending email change store: keyed by current session email
PENDING_EMAIL_CHANGES: dict[str, dict] = {}


def _purge_expired():
    now = time.time()
    for d in (CODE_STORE, VERIFIED_TOKENS):
        for k in list(d.keys()):
            if d[k].get('exp', 0) < now:
                del d[k]


@app.post('/api/request_code')
def api_request_code():
    # Client supplies a code that will be emailed via EmailJS from the frontend.
    try:
        data = request.get_json(silent=True) or {}
        email = (data.get('email') or '').strip()
        code = (data.get('code') or '').strip()
        if not email or not code or len(code) != 6 or not code.isdigit():
            return jsonify({"ok": False}), 400
        _purge_expired()
        CODE_STORE[email] = {"code": code, "exp": time.time() + CODE_TTL_SECONDS}
        return jsonify({"ok": True})
    except Exception:
        return jsonify({"ok": False}), 400


@app.post('/api/verify_code')
def api_verify_code():
    try:
        data = request.get_json(silent=True) or {}
        email = (data.get('email') or '').strip()
        code = (data.get('code') or '').strip()
        if not email or not code:
            return jsonify({"ok": False}), 400
        _purge_expired()
        entry = CODE_STORE.get(email)
        if not entry or entry.get('code') != code or entry.get('exp', 0) < time.time():
            return jsonify({"ok": False}), 400
        # Issue short-lived token and establish authenticated session
        token = secrets.token_urlsafe(24)
        VERIFIED_TOKENS[email] = {"token": token, "exp": time.time() + TOKEN_TTL_SECONDS}
        try:
            session['user_email'] = email
        except Exception:
            pass
        # Remove used code
        try:
            del CODE_STORE[email]
        except Exception:
            pass
        return jsonify({"ok": True, "token": token})
    except Exception:
        return jsonify({"ok": False}), 400


@app.post('/api/reset_password')
def api_reset_password():
    try:
        data = request.get_json(silent=True) or {}
        email = (data.get('email') or '').strip()
        new_pass = (data.get('new_pass') or '').strip()
        token = (data.get('token') or '').strip()
        if not email or not new_pass or not token:
            return jsonify({"ok": False}), 400
        _purge_expired()
        v = VERIFIED_TOKENS.get(email)
        if not v or v.get('token') != token or v.get('exp', 0) < time.time():
            return jsonify({"ok": False}), 400
        users = _read_users_list()
        u = _find_user(users, email)
        if not u:
            return jsonify({"ok": False}), 404
        u['pass'] = generate_password_hash(new_pass)
        _write_users_list(users)
        # Invalidate token
        try:
            del VERIFIED_TOKENS[email]
        except Exception:
            pass
        return jsonify({"ok": True})
    except Exception:
        return jsonify({"ok": False}), 400


@app.post('/api/request_email_change')
def api_request_email_change():
    """Start secure email change: client has emailed a 6-digit code to the NEW email via EmailJS.
    We store (new_email, code) temporarily for verification.
    """
    try:
        current_email = session.get('user_email')
        if not current_email:
            return jsonify({"ok": False}), 401
        data = request.get_json(silent=True) or {}
        new_email = (data.get('new_email') or '').strip()
        code = (data.get('code') or '').strip()
        if not new_email or not code or len(code) != 6 or not code.isdigit():
            return jsonify({"ok": False, "error": "invalid input"}), 400
        # Ensure new email is not already in use
        users = _read_users_list()
        if _find_user(users, new_email):
            return jsonify({"ok": False, "error": "email exists"}), 409
        _purge_expired()
        PENDING_EMAIL_CHANGES[current_email] = {
            "new_email": new_email,
            "code": code,
            "exp": time.time() + CODE_TTL_SECONDS,
        }
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 400


@app.post('/api/confirm_email_change')
def api_confirm_email_change():
    """Confirm email change with the code that was sent to the new email address."""
    try:
        current_email = session.get('user_email')
        if not current_email:
            return jsonify({"ok": False}), 401
        data = request.get_json(silent=True) or {}
        new_email = (data.get('new_email') or '').strip()
        code = (data.get('code') or '').strip()
        if not new_email or not code:
            return jsonify({"ok": False}), 400
        _purge_expired()
        entry = PENDING_EMAIL_CHANGES.get(current_email)
        if (not entry or entry.get('new_email') != new_email or
                entry.get('code') != code or entry.get('exp', 0) < time.time()):
            return jsonify({"ok": False, "error": "invalid_or_expired"}), 400

        users = _read_users_list()
        # Prevent collision
        if _find_user(users, new_email):
            return jsonify({"ok": False, "error": "email exists"}), 409
        user = _find_user(users, current_email)
        if not user:
            return jsonify({"ok": False}), 404
        # Update email and flags
        user['email'] = new_email
        user.setdefault('email_changed', False)
        user['email_changed'] = True
        _write_users_list(users)
        # Update session and cleanup
        session['user_email'] = new_email
        try:
            del PENDING_EMAIL_CHANGES[current_email]
        except Exception:
            pass
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 400


@app.post('/api/logout')
def api_logout():
    try:
        session.pop('user_email', None)
        return jsonify({"ok": True})
    except Exception:
        return jsonify({"ok": False}), 400


@app.get('/api/me')
def api_me():
    try:
        email = session.get('user_email')
        if not email:
            return jsonify({"ok": False}), 401
        users = _read_users_list()
        u = _find_user(users, email)
        # Backfill defaults for legacy entries
        name = (u or {}).get('name') or ''
        email_changed = bool((u or {}).get('email_changed'))
        name_changed = bool((u or {}).get('name_changed'))
        # Backfill code if missing
        modified = False
        if u and _ensure_user_code(users, u):
            modified = True
        if modified:
            _write_users_list(users)
        return jsonify({
            "ok": True,
            "email": email,
            "name": name,
            "email_changed": email_changed,
            "name_changed": name_changed,
            "code": (u or {}).get('code') or '',
        })
    except Exception:
        return jsonify({"ok": False}), 400


@app.post('/api/update_profile')
def api_update_profile():
    """Allow changing 'email' or 'name' exactly once each per account."""
    try:
        current_email = session.get('user_email')
        if not current_email:
            return jsonify({"ok": False}), 401
        payload = request.get_json(silent=True) or {}
        field = (payload.get('field') or '').strip()
        value = (payload.get('value') or '').strip()
        if field not in ('email', 'name') or not value:
            return jsonify({"ok": False, "error": "invalid input"}), 400

        users = _read_users_list()
        user = _find_user(users, current_email)
        if not user:
            return jsonify({"ok": False}), 404

        # Initialize flags for legacy users
        user.setdefault('name', '')
        user.setdefault('email_changed', False)
        user.setdefault('name_changed', False)

        if field == 'email':
            if user.get('email_changed'):
                return jsonify({"ok": False, "error": "email already changed"}), 403
            # Ensure unique email
            if _find_user(users, value) and value != current_email:
                return jsonify({"ok": False, "error": "email exists"}), 409
            user['email'] = value
            user['email_changed'] = True
            # Update session principal
            session['user_email'] = value
        else:
            # field == 'name'
            if user.get('name_changed'):
                return jsonify({"ok": False, "error": "name already changed"}), 403
            user['name'] = value
            user['name_changed'] = True

        _write_users_list(users)
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 400


# Google login helper: trust server to set session if account exists; create if not
@app.post('/api/login_google')
def api_login_google():
    try:
        data = request.get_json(silent=True) or {}
        email = (data.get('email') or '').strip()
        if not email:
            return jsonify({"ok": False}), 400
        users = _read_users_list()
        u = _find_user(users, email)
        if not u:
            # Create a new user with a random password
            rand_pass = secrets.token_urlsafe(12)
            users.append({"email": email, "pass": generate_password_hash(rand_pass)})
            _write_users_list(users)
        session['user_email'] = email
        return jsonify({"ok": True})
    except Exception:
        return jsonify({"ok": False}), 400


# ===== PRODUCT MANAGEMENT API =====
PRODUCTS_FILE = os.path.join(BASE_DIR, 'products.json')


def _read_products_list() -> list[dict]:
    """Read products from JSON file"""
    try:
        if not os.path.exists(PRODUCTS_FILE) or os.path.getsize(PRODUCTS_FILE) == 0:
            return []
        with open(PRODUCTS_FILE, 'r', encoding='utf-8') as f:
            data = json.load(f)
            return data if isinstance(data, list) else []
    except Exception:
        return []


def _write_products_list(products: list[dict]):
    """Write products to JSON file"""
    with open(PRODUCTS_FILE, 'w', encoding='utf-8') as f:
        json.dump(products, f, ensure_ascii=False, indent=2)


def _find_product(products: list[dict], product_id: str) -> Optional[dict]:
    """Find product by ID"""
    for p in products:
        if isinstance(p, dict) and p.get('id') == product_id:
            return p
    return None


@app.get('/api/products')
def api_get_products():
    """Get products filtered by category and subcategory"""
    try:
        cat = request.args.get('cat', '').strip()
        sub = request.args.get('sub', '').strip()
        
        products = _read_products_list()
        
        # Filter by category and subcategory if provided
        if cat or sub:
            filtered = []
            for p in products:
                if isinstance(p, dict):
                    p_cat = p.get('catTitle', '').strip()
                    p_sub = p.get('subTitle', '').strip()
                    
                    cat_match = not cat or p_cat == cat
                    sub_match = not sub or p_sub == sub
                    
                    if cat_match and sub_match:
                        filtered.append(p)
            products = filtered
        
        # Add computed fields for frontend
        for p in products:
            if isinstance(p, dict):
                # Add canDelete flag (user can delete their own products)
                current_email = session.get('user_email', '')
                p['canDelete'] = p.get('sellerEmail') == current_email
                
                # Ensure required fields exist
                p.setdefault('id', '')
                p.setdefault('name', '')
                p.setdefault('desc', '')
                p.setdefault('priceLabel', '')
                p.setdefault('contact', '')
                p.setdefault('image', '')
                p.setdefault('sellerName', 'مستخدم')
                p.setdefault('sellerCode', '')
                p.setdefault('sellerEmail', '')
                p.setdefault('created_at', int(time.time()))
        
        return jsonify({"ok": True, "items": products})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 400


@app.post('/api/products')
def api_create_product():
    """Create a new product"""
    try:
        current_email = session.get('user_email')
        if not current_email:
            return jsonify({"ok": False, "error": "not authenticated"}), 401
            
        data = request.get_json(silent=True) or {}
        name = (data.get('name') or '').strip()
        cat_title = (data.get('catTitle') or '').strip()
        sub_title = (data.get('subTitle') or '').strip()
        desc = (data.get('desc') or '').strip()
        contact = (data.get('contact') or '').strip()
        price_label = (data.get('priceLabel') or '').strip()
        image = (data.get('image') or '').strip()
        
        if not name:
            return jsonify({"ok": False, "error": "product name is required"}), 400
            
        # Get seller info from current user
        users = _read_users_list()
        user = _find_user(users, current_email)
        seller_name = 'مستخدم'
        seller_code = ''
        if user:
            seller_name = user.get('name') or (current_email.split('@')[0] if current_email else 'مستخدم')
            seller_code = user.get('code') or ''
        
        # Create product
        product_id = secrets.token_urlsafe(12)
        product = {
            "id": product_id,
            "name": name,
            "catTitle": cat_title,
            "subTitle": sub_title,
            "desc": desc,
            "contact": contact,
            "priceLabel": price_label,
            "image": image,
            "sellerName": seller_name,
            "sellerCode": seller_code,
            "sellerEmail": current_email,
            "created_at": int(time.time())
        }
        
        products = _read_products_list()
        products.append(product)
        _write_products_list(products)
        
        return jsonify({"ok": True, "id": product_id})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 400


@app.get('/api/products/<product_id>')
def api_get_product(product_id: str):
    """Get a specific product by ID"""
    try:
        products = _read_products_list()
        product = _find_product(products, product_id)
        
        if not product:
            return jsonify({"ok": False, "error": "product not found"}), 404
            
        # Add computed fields
        current_email = session.get('user_email', '')
        product['canDelete'] = product.get('sellerEmail') == current_email
        
        return jsonify({"ok": True, "item": product})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 400


@app.delete('/api/products/<product_id>')
def api_delete_product(product_id: str):
    """Delete a product (only by owner)"""
    try:
        current_email = session.get('user_email')
        if not current_email:
            return jsonify({"ok": False, "error": "not authenticated"}), 401
            
        products = _read_products_list()
        product = _find_product(products, product_id)
        
        if not product:
            return jsonify({"ok": False, "error": "product not found"}), 404
            
        # Check ownership
        if product.get('sellerEmail') != current_email:
            return jsonify({"ok": False, "error": "not authorized"}), 403
            
        # Remove product
        products = [p for p in products if p.get('id') != product_id]
        _write_products_list(products)
        
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 400


if __name__ == '__main__':
    port = int(os.environ.get('PORT', '8000'))
    host = os.environ.get('HOST', '0.0.0.0')
    app.run(host=host, port=port)


