"""Authentication routes — login / logout / change-password / me with cyberpunk HTML pages."""
import logging
from flask import Blueprint, request, jsonify, redirect, url_for, render_template_string
from flask_login import login_user, logout_user, login_required, current_user
from app.services.login_guard import retry_after, record_failure, clear
from app.services.auth_service import (
    get_user_by_username,
    verify_password,
    update_password,
    update_last_login,
)

log = logging.getLogger(__name__)
bp = Blueprint('auth', __name__)


def _client_ip():
    xff = request.headers.get('X-Forwarded-For', '')
    if xff:
        return xff.split(',')[0].strip()
    return request.remote_addr or '-'

LOGIN_HTML = '''<!DOCTYPE html>
<html lang="ro">
<head>
<meta charset="utf-8">
<title>FasterUp AI SOC — Autentificare</title>
<style>
* { box-sizing: border-box; margin: 0; padding: 0; }
body {
    font-family: 'Courier New', monospace;
    background: #050709;
    color: #00ff9c;
    min-height: 100vh;
    display: flex;
    align-items: center;
    justify-content: center;
    background-image: linear-gradient(rgba(0,255,156,0.04) 1px, transparent 1px),
                      linear-gradient(90deg, rgba(0,255,156,0.04) 1px, transparent 1px);
    background-size: 30px 30px;
}
.container { width: 420px; padding: 40px; border: 1px solid #00ff9c; box-shadow: 0 0 30px rgba(0,255,156,0.3); background: rgba(5,7,9,0.95); }
h1 { font-size: 22px; margin-bottom: 8px; text-shadow: 0 0 10px #00ff9c; }
h2 { font-size: 12px; color: #5a8a7a; margin-bottom: 30px; letter-spacing: 2px; }
.form-group { margin-bottom: 20px; }
label { display: block; font-size: 11px; margin-bottom: 8px; color: #00ff9c; letter-spacing: 1px; }
input { width: 100%; padding: 12px; background: #0a0e12; border: 1px solid #1a3a30; color: #00ff9c; font-family: 'Courier New', monospace; font-size: 14px; outline: none; }
input:focus { border-color: #00ff9c; box-shadow: 0 0 10px rgba(0,255,156,0.5); }
button { width: 100%; padding: 14px; background: #00ff9c; color: #050709; border: none; font-family: 'Courier New', monospace; font-size: 14px; font-weight: bold; letter-spacing: 2px; cursor: pointer; transition: all 0.2s; }
button:hover { background: #00cc7a; box-shadow: 0 0 20px #00ff9c; }
button:disabled { opacity: 0.5; cursor: not-allowed; }
.error { color: #ff4444; font-size: 13px; margin-top: 16px; padding: 10px; border: 1px solid #ff4444; background: rgba(255,68,68,0.1); display: none; }
.error.visible { display: block; }
.footer { margin-top: 30px; font-size: 10px; color: #3a5a50; text-align: center; letter-spacing: 1px; }

.login-mark { width: 60px; height: 60px; margin: 0 auto 20px; background: url("data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'><g fill='%23F40000'><rect x='44' y='15' width='12' height='70'/><rect x='15' y='44' width='70' height='12'/><rect x='36' y='13' width='28' height='6'/><rect x='36' y='81' width='28' height='6'/><rect x='13' y='36' width='6' height='28'/><rect x='81' y='36' width='6' height='28'/><rect x='27' y='22' width='6' height='16'/><rect x='22' y='27' width='16' height='6'/><rect x='67' y='22' width='6' height='16'/><rect x='62' y='27' width='16' height='6'/><rect x='27' y='62' width='6' height='16'/><rect x='22' y='67' width='16' height='6'/><rect x='67' y='62' width='6' height='16'/><rect x='62' y='67' width='16' height='6'/></g><circle cx='50' cy='50' r='47' fill='none' stroke='%23F40000' stroke-width='3'/></svg>") center/contain no-repeat; filter: drop-shadow(0 0 9px rgba(244,0,0,0.55)); animation: loginpulse 2s ease-in-out infinite; }
@keyframes loginpulse { 0%,100% { opacity: 1; transform: scale(1); } 50% { opacity: 0.55; transform: scale(0.85); } }
</style>
</head>
<body>
<div class="container">
<div class="login-mark"></div>
<h1>&gt; FASTERUP AI AUTONOMOUS</h1>
<h2>// AUTENTIFICARE ANALIST //</h2>
<form id="loginForm">
<div class="form-group">
<label>USERNAME</label>
<input type="text" id="username" autocomplete="username" required autofocus>
</div>
<div class="form-group">
<label>PAROLĂ</label>
<input type="password" id="password" autocomplete="current-password" required>
</div>
<button type="submit" id="submitBtn">AUTENTIFICARE</button>
<div id="errorMsg" class="error"></div>
</form>
<div class="footer">Sistem securizat. Acces controlat. Toate acțiunile sunt logate.</div>
</div>
<script>
document.getElementById('loginForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    const btn = document.getElementById('submitBtn');
    const err = document.getElementById('errorMsg');
    err.classList.remove('visible');
    btn.disabled = true;
    btn.textContent = 'AUTENTIFICARE...';
    try {
        const resp = await fetch('/api/auth/login', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            credentials: 'include',
            body: JSON.stringify({
                username: document.getElementById('username').value,
                password: document.getElementById('password').value
            })
        });
        const data = await resp.json();
        if (resp.ok && data.status === 'ok') {
            window.location.href = data.must_change_password ? '/change-password' : '/';
        } else {
            err.textContent = data.error === 'invalid_credentials' ? 'Username sau parolă incorecte.' : ('Eroare: ' + (data.error || 'unknown'));
            err.classList.add('visible');
            btn.disabled = false;
            btn.textContent = 'AUTENTIFICARE';
        }
    } catch (e) {
        err.textContent = 'Eroare de rețea. Reîncearcă.';
        err.classList.add('visible');
        btn.disabled = false;
        btn.textContent = 'AUTENTIFICARE';
    }
});
</script>
</body>
</html>'''


CHANGE_PASSWORD_HTML = '''<!DOCTYPE html>
<html lang="ro">
<head>
<meta charset="utf-8">
<title>FasterUp AI SOC — Schimbare parolă</title>
<style>
* { box-sizing: border-box; margin: 0; padding: 0; }
body {
    font-family: 'Courier New', monospace;
    background: #050709;
    color: #00ff9c;
    min-height: 100vh;
    display: flex;
    align-items: center;
    justify-content: center;
    background-image: linear-gradient(rgba(0,255,156,0.04) 1px, transparent 1px),
                      linear-gradient(90deg, rgba(0,255,156,0.04) 1px, transparent 1px);
    background-size: 30px 30px;
}
.container { width: 480px; padding: 40px; border: 1px solid #00ff9c; box-shadow: 0 0 30px rgba(0,255,156,0.3); background: rgba(5,7,9,0.95); }
h1 { font-size: 20px; margin-bottom: 8px; }
h2 { font-size: 11px; color: #ffb700; margin-bottom: 24px; letter-spacing: 1px; }
.warning { background: rgba(255,183,0,0.1); border: 1px solid #ffb700; padding: 12px; margin-bottom: 24px; font-size: 12px; color: #ffb700; line-height: 1.5; }
.form-group { margin-bottom: 18px; }
label { display: block; font-size: 11px; margin-bottom: 6px; letter-spacing: 1px; }
input { width: 100%; padding: 12px; background: #0a0e12; border: 1px solid #1a3a30; color: #00ff9c; font-family: 'Courier New', monospace; font-size: 14px; outline: none; }
input:focus { border-color: #00ff9c; box-shadow: 0 0 10px rgba(0,255,156,0.5); }
.requirements { font-size: 10px; color: #5a8a7a; margin-top: 4px; }
button { width: 100%; padding: 14px; background: #00ff9c; color: #050709; border: none; font-family: 'Courier New', monospace; font-size: 14px; font-weight: bold; letter-spacing: 2px; cursor: pointer; margin-top: 10px; }
button:hover { background: #00cc7a; box-shadow: 0 0 20px #00ff9c; }
button:disabled { opacity: 0.5; cursor: not-allowed; }
.error { color: #ff4444; font-size: 13px; margin-top: 16px; padding: 10px; border: 1px solid #ff4444; background: rgba(255,68,68,0.1); display: none; }
.error.visible { display: block; }
.success { color: #00ff9c; font-size: 13px; margin-top: 16px; padding: 10px; border: 1px solid #00ff9c; background: rgba(0,255,156,0.1); display: none; }
.success.visible { display: block; }
</style>
</head>
<body>
<div class="container">
<h1>&gt; SCHIMBARE PAROLĂ</h1>
<h2>// PRIMUL LOGIN — ACȚIUNE OBLIGATORIE //</h2>
<div class="warning">⚠ Trebuie să schimbi parola comună înainte de a accesa portalul. Alege o parolă personală pe care nu o vei împărtăși.</div>
<form id="changeForm">
<div class="form-group">
<label>PAROLA CURENTĂ</label>
<input type="password" id="oldPwd" required autofocus>
</div>
<div class="form-group">
<label>PAROLA NOUĂ</label>
<input type="password" id="newPwd" required>
<div class="requirements">Minim 10 caractere, diferită de cea curentă.</div>
</div>
<div class="form-group">
<label>CONFIRMĂ PAROLA NOUĂ</label>
<input type="password" id="confirmPwd" required>
</div>
<button type="submit" id="submitBtn">SCHIMBĂ PAROLA</button>
<div id="errorMsg" class="error"></div>
<div id="successMsg" class="success"></div>
</form>
</div>
<script>
document.getElementById('changeForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    const btn = document.getElementById('submitBtn');
    const err = document.getElementById('errorMsg');
    const ok = document.getElementById('successMsg');
    err.classList.remove('visible');
    ok.classList.remove('visible');
    const oldPwd = document.getElementById('oldPwd').value;
    const newPwd = document.getElementById('newPwd').value;
    const confirmPwd = document.getElementById('confirmPwd').value;
    if (newPwd !== confirmPwd) {
        err.textContent = 'Parola nouă și confirmarea nu coincid.';
        err.classList.add('visible');
        return;
    }
    if (newPwd.length < 10) {
        err.textContent = 'Parola nouă trebuie să aibă minim 10 caractere.';
        err.classList.add('visible');
        return;
    }
    btn.disabled = true;
    btn.textContent = 'PROCESARE...';
    try {
        const resp = await fetch('/api/auth/change-password', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            credentials: 'include',
            body: JSON.stringify({old_password: oldPwd, new_password: newPwd})
        });
        const data = await resp.json();
        if (resp.ok && data.status === 'ok') {
            ok.textContent = 'Parolă schimbată. Redirecționare...';
            ok.classList.add('visible');
            setTimeout(() => window.location.href = '/', 1500);
        } else {
            const msg = {
                'invalid_old_password': 'Parola curentă incorectă.',
                'password_too_short': 'Parolă nouă prea scurtă.',
                'new_password_must_differ': 'Parola nouă trebuie să fie diferită de cea curentă.'
            }[data.error] || ('Eroare: ' + (data.error || 'unknown'));
            err.textContent = msg;
            err.classList.add('visible');
            btn.disabled = false;
            btn.textContent = 'SCHIMBĂ PAROLA';
        }
    } catch (e) {
        err.textContent = 'Eroare de rețea.';
        err.classList.add('visible');
        btn.disabled = false;
        btn.textContent = 'SCHIMBĂ PAROLA';
    }
});
</script>
</body>
</html>'''


@bp.route('/login', methods=['GET'])
def login():
    if current_user.is_authenticated:
        return redirect('/')
    return LOGIN_HTML


@bp.route('/change-password', methods=['GET'])
@login_required
def change_password_page():
    return CHANGE_PASSWORD_HTML


@bp.route('/api/auth/login', methods=['POST'])
def api_login():
    data = request.get_json(silent=True) or {}
    username = (data.get('username') or '').strip()
    password = data.get('password') or ''
    if not username or not password:
        return jsonify({'error': 'username_and_password_required'}), 400
    ip = _client_ip()
    wait = retry_after(ip, username)
    if wait > 0:
        log.warning(f'Login blocked (rate-limited): {username} ip={ip} retry_after={wait}s')
        resp = jsonify({'error': 'too_many_attempts', 'retry_after': wait})
        resp.headers['Retry-After'] = str(wait)
        return resp, 429
    user, password_hash = get_user_by_username(username)
    if user is None:
        record_failure(ip, username)
        log.warning(f'Login failed (unknown user): {username} ip={ip}')
        return jsonify({'error': 'invalid_credentials'}), 401
    if not verify_password(password, password_hash):
        record_failure(ip, username)
        log.warning(f'Login failed (bad password): {username} ip={ip}')
        return jsonify({'error': 'invalid_credentials'}), 401
    clear(ip, username)
    login_user(user, remember=False)
    update_last_login(user.id)
    log.info(f'Login OK: {username} (role={user.role}, org={user.organization}) ip={ip}')
    return jsonify({
        'status': 'ok',
        'user': user.to_dict(),
        'must_change_password': user.must_change_password,
    })


@bp.route('/api/auth/logout', methods=['POST'])
@login_required
def api_logout():
    username = current_user.username
    logout_user()
    log.info(f'Logout: {username}')
    return jsonify({'status': 'ok'})


@bp.route('/api/auth/me', methods=['GET'])
@login_required
def api_me():
    return jsonify({'user': current_user.to_dict()})


@bp.route('/api/auth/change-password', methods=['POST'])
@login_required
def api_change_password():
    data = request.get_json(silent=True) or {}
    old_pw = data.get('old_password') or ''
    new_pw = data.get('new_password') or ''
    if not old_pw or not new_pw:
        return jsonify({'error': 'old_and_new_password_required'}), 400
    if len(new_pw) < 10:
        return jsonify({'error': 'password_too_short', 'min_length': 10}), 400
    if new_pw == old_pw:
        return jsonify({'error': 'new_password_must_differ'}), 400
    user, password_hash = get_user_by_username(current_user.username)
    if user is None or not verify_password(old_pw, password_hash):
        log.warning(f'Change-password rejected (bad old pw): {current_user.username}')
        return jsonify({'error': 'invalid_old_password'}), 401
    if not update_password(current_user.id, new_pw):
        return jsonify({'error': 'update_failed'}), 500
    log.info(f'Password changed: {current_user.username}')
    return jsonify({'status': 'ok'})
