from functools import wraps

from flask import Flask, render_template, request, jsonify, session
from killswitch import engine
import threading
import os
import time

app = Flask(__name__)
app.secret_key = os.environ.get('AEGIS_SECRET_KEY', 'aegis-demo-secret-key')
APP_PIN = os.environ.get('AEGIS_PIN', '2468')
FAILED_UNLOCKS = {}
LOCKED_UNTIL = {}

# Start engine in background when app starts
engine.start()

def login_required(route):
    @wraps(route)
    def wrapped(*args, **kwargs):
        if not session.get('aegis_unlocked'):
            return jsonify({"success": False, "message": "Aegis is locked."}), 401
        return route(*args, **kwargs)
    return wrapped

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/auth/status', methods=['GET'])
def auth_status():
    return jsonify({"unlocked": bool(session.get('aegis_unlocked'))})

@app.route('/api/auth/login', methods=['POST'])
def auth_login():
    data = request.get_json(silent=True) or {}
    client_id = request.remote_addr or 'local'
    now = time.time()
    if LOCKED_UNTIL.get(client_id, 0) > now:
        remaining = int(LOCKED_UNTIL[client_id] - now)
        engine.add_log(f"Dashboard unlock blocked by tamper protection for {remaining}s.")
        return jsonify({"success": False, "message": f"Too many failed attempts. Try again in {remaining}s."}), 429

    if str(data.get('pin', '')) != APP_PIN:
        FAILED_UNLOCKS[client_id] = FAILED_UNLOCKS.get(client_id, 0) + 1
        if FAILED_UNLOCKS[client_id] >= 3:
            LOCKED_UNTIL[client_id] = now + 30
            FAILED_UNLOCKS[client_id] = 0
            engine.add_log("Tamper protection triggered after repeated failed unlock attempts.")
            return jsonify({"success": False, "message": "Too many failed attempts. Locked for 30 seconds."}), 429
        engine.add_log("Dashboard unlock failed.")
        return jsonify({"success": False, "message": "Invalid PIN."}), 401
    FAILED_UNLOCKS[client_id] = 0
    session['aegis_unlocked'] = True
    engine.add_log("Dashboard unlocked.")
    return jsonify({"success": True, "message": "Dashboard unlocked."})

@app.route('/api/auth/logout', methods=['POST'])
def auth_logout():
    session.pop('aegis_unlocked', None)
    engine.add_log("Dashboard locked.")
    return jsonify({"success": True, "message": "Dashboard locked."})

@app.route('/api/rules', methods=['GET'])
@login_required
def get_rules():
    return jsonify(engine.get_rules())

@app.route('/api/status', methods=['GET'])
@login_required
def get_status():
    return jsonify(engine.get_status())

@app.route('/api/rules', methods=['POST'])
@login_required
def add_rule():
    data = request.get_json(silent=True) or {}
    target_type = data.get('target_type', 'domain')
    target = data.get('target') or data.get('domain')
    rule_type = data.get('type', 'always') # 'always', 'duration', 'scheduled'
    duration_minutes = data.get('duration_minutes', None)
    schedule_start = data.get('schedule_start', None)
    schedule_end = data.get('schedule_end', None)

    if not target:
        return jsonify({"success": False, "message": "Target is required"}), 400

    if rule_type == 'duration' and not duration_minutes:
         return jsonify({"success": False, "message": "Duration is required"}), 400

    if rule_type == 'scheduled' and (not schedule_start or not schedule_end):
         return jsonify({"success": False, "message": "Start and End time required"}), 400
         
    success, message = engine.add_rule(
        domain=target,
        target=target,
        target_type=target_type,
        rule_type=rule_type,
        duration_minutes=duration_minutes,
        start_time=schedule_start,
        end_time=schedule_end
    )
    
    return jsonify({"success": success, "message": message}), 200 if success else 400

@app.route('/api/rules/<int:rule_id>', methods=['DELETE'])
@login_required
def remove_rule(rule_id):
    success, message = engine.remove_rule(rule_id)
    return jsonify({"success": success, "message": message}), 200 if success else 404

@app.route('/api/logs', methods=['GET'])
@login_required
def get_logs():
    return jsonify(engine.get_logs())

if __name__ == '__main__':
    # Must be run as root to allow hosts-file edits, iptables and packet sniffing.
    host = os.environ.get('AEGIS_HOST', '127.0.0.1')
    port = int(os.environ.get('AEGIS_PORT', '5000'))
    print("WARNING: Make sure you run this script with sudo on Linux!")
    app.run(host=host, port=port, debug=False)
