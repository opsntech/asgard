from datetime import datetime, timedelta
from functools import wraps
from flask import Blueprint, request, jsonify, render_template, current_app, session, redirect, url_for
import requests
import secrets
import re

from app import db
from app.models import (
    Environment, Server, Session, AuditLog, Settings,
    MonitoredUser, VPNServer, VPNSession
)

main_bp = Blueprint('main', __name__)
api_bp = Blueprint('api', __name__)


# =============================================================================
# Security Helpers
# =============================================================================

def require_api_key(f):
    """Decorator to require API key for agent endpoints"""
    @wraps(f)
    def decorated(*args, **kwargs):
        api_key = request.headers.get('X-API-Key')
        if not api_key or not secrets.compare_digest(api_key, current_app.config['API_KEY']):
            return jsonify({'error': 'Invalid or missing API key'}), 401
        return f(*args, **kwargs)
    return decorated


def require_dashboard_auth(f):
    """Decorator to require authentication for dashboard pages"""
    @wraps(f)
    def decorated(*args, **kwargs):
        # Check if dashboard auth is enabled
        dashboard_password = current_app.config.get('DASHBOARD_PASSWORD')
        if not dashboard_password:
            return f(*args, **kwargs)

        if not session.get('authenticated'):
            return redirect(url_for('main.login'))
        return f(*args, **kwargs)
    return decorated


def get_int_param(name, default, min_val=0, max_val=10000):
    """Safely get integer parameter from request args"""
    try:
        value = int(request.args.get(name, default))
        return max(min_val, min(value, max_val))
    except (ValueError, TypeError):
        return default


def sanitize_string(value, max_length=255):
    """Sanitize string input"""
    if not value:
        return value
    # Remove any null bytes and control characters
    value = re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]', '', str(value))
    return value[:max_length]


def parse_timestamp(ts_string):
    """Safely parse timestamp string"""
    if not ts_string:
        return datetime.utcnow()
    try:
        # Handle various formats
        ts_string = ts_string.replace('Z', '+00:00')
        if '+' not in ts_string and ts_string.count(':') == 2:
            # No timezone, assume UTC
            return datetime.fromisoformat(ts_string)
        return datetime.fromisoformat(ts_string)
    except (ValueError, TypeError):
        return datetime.utcnow()


def send_slack_notification(event_type, session_data, server, environment):
    """Send consolidated Slack notification"""
    # Try environment-specific webhook first, then global
    webhook = None
    if environment and environment.slack_webhook:
        webhook = environment.slack_webhook
    elif current_app.config['SLACK_WEBHOOK']:
        webhook = current_app.config['SLACK_WEBHOOK']

    if not webhook:
        return

    if event_type == 'LOGIN':
        color = '#36A64F'
        emoji = '🔓'
    else:
        color = '#808080'
        emoji = '🔒'

    env_name = environment.name if environment else 'Unknown'

    try:
        requests.post(webhook, json={
            'attachments': [{
                'color': color,
                'text': f"{emoji} *SSH {event_type}*\n"
                       f"*Environment:* {env_name}\n"
                       f"*User:* {session_data['username']}\n"
                       f"*IP:* {session_data['source_ip']}\n"
                       f"*Server:* {server.hostname}\n"
                       f"*TTY:* {session_data['tty']}\n"
                       f"*Time:* {session_data['timestamp']}"
            }]
        }, timeout=5)
    except Exception:
        pass  # Don't fail on Slack errors


# =============================================================================
# Web Dashboard Routes
# =============================================================================

@main_bp.route('/login', methods=['GET', 'POST'])
def login():
    """Login page for dashboard"""
    if request.method == 'POST':
        password = request.form.get('password', '')
        dashboard_password = current_app.config.get('DASHBOARD_PASSWORD', '')

        if dashboard_password and secrets.compare_digest(password, dashboard_password):
            session['authenticated'] = True
            return redirect(url_for('main.dashboard'))
        return render_template('login.html', error='Invalid password')

    return render_template('login.html')


@main_bp.route('/logout')
def logout():
    """Logout from dashboard"""
    session.pop('authenticated', None)
    return redirect(url_for('main.login'))


@main_bp.route('/')
@require_dashboard_auth
def dashboard():
    """Main dashboard view"""
    return render_template('dashboard.html')


@main_bp.route('/sessions')
@require_dashboard_auth
def sessions_view():
    """Sessions list view"""
    return render_template('sessions.html')


@main_bp.route('/servers')
@require_dashboard_auth
def servers_view():
    """Servers list view"""
    return render_template('servers.html')


@main_bp.route('/alerts')
@require_dashboard_auth
def alerts_view():
    """Alerts settings view"""
    return render_template('alerts.html')


@main_bp.route('/vpn')
@require_dashboard_auth
def vpn_view():
    """VPN monitoring view"""
    return render_template('vpn.html')


# =============================================================================
# API Routes - Dashboard Data
# =============================================================================

@api_bp.route('/stats')
def get_stats():
    """Get dashboard statistics"""
    now = datetime.utcnow()
    today_start = now.replace(hour=0, minute=0, second=0, microsecond=0)

    active_sessions = Session.query.filter_by(logout_time=None).count()
    total_servers = Server.query.count()
    online_servers = Server.query.filter(
        Server.last_seen > now - timedelta(minutes=5)
    ).count()
    today_logins = Session.query.filter(Session.login_time >= today_start).count()

    # Sessions by environment
    env_stats = db.session.query(
        Environment.name,
        db.func.count(Session.id)
    ).select_from(Session).join(
        Server, Session.server_id == Server.id
    ).join(
        Environment, Server.environment_id == Environment.id
    ).filter(
        Session.logout_time.is_(None)
    ).group_by(Environment.name).all()

    return jsonify({
        'active_sessions': active_sessions,
        'total_servers': total_servers,
        'online_servers': online_servers,
        'today_logins': today_logins,
        'by_environment': dict(env_stats)
    })


@api_bp.route('/sessions')
def list_sessions():
    """List sessions with filtering"""
    # Query parameters with safe parsing
    active_only = request.args.get('active', 'false').lower() == 'true'
    environment = sanitize_string(request.args.get('environment'), 50)
    username = sanitize_string(request.args.get('username'), 100)
    server = sanitize_string(request.args.get('server'), 255)
    limit = get_int_param('limit', 100, 1, 1000)
    offset = get_int_param('offset', 0, 0, 100000)

    query = Session.query.join(Server)

    if active_only:
        query = query.filter(Session.logout_time.is_(None))

    if environment:
        query = query.join(Environment).filter(Environment.name == environment)

    if username:
        query = query.filter(Session.username.ilike(f'%{username}%'))

    if server:
        query = query.filter(Server.hostname.ilike(f'%{server}%'))

    total = query.count()
    sessions = query.order_by(Session.login_time.desc()).offset(offset).limit(limit).all()

    return jsonify({
        'total': total,
        'sessions': [s.to_dict() for s in sessions]
    })


@api_bp.route('/sessions/active')
def active_sessions():
    """Get all active sessions"""
    sessions = Session.query.filter_by(logout_time=None).join(Server).order_by(
        Session.login_time.desc()
    ).all()
    return jsonify([s.to_dict() for s in sessions])


@api_bp.route('/servers')
def list_servers():
    """List all servers"""
    servers = Server.query.order_by(Server.hostname).all()
    return jsonify([s.to_dict() for s in servers])


@api_bp.route('/environments')
def list_environments():
    """List all environments"""
    envs = Environment.query.order_by(Environment.name).all()
    return jsonify([e.to_dict() for e in envs])


@api_bp.route('/environments', methods=['POST'])
def create_environment():
    """Create a new environment"""
    data = request.get_json()

    # Check if environment already exists
    existing = Environment.query.filter_by(name=data['name']).first()
    if existing:
        return jsonify({'error': 'Environment already exists'}), 400

    env = Environment(
        name=data['name'],
        description=data.get('description', ''),
        slack_webhook=data.get('slack_webhook'),
        alerts_enabled=data.get('alerts_enabled', True)
    )
    db.session.add(env)
    db.session.commit()

    return jsonify(env.to_dict()), 201


@api_bp.route('/environments/<int:env_id>', methods=['PUT'])
def update_environment(env_id):
    """Update an environment"""
    env = Environment.query.get_or_404(env_id)
    data = request.get_json()

    if 'description' in data:
        env.description = data['description']
    if 'slack_webhook' in data:
        env.slack_webhook = data['slack_webhook'] or None
    if 'alerts_enabled' in data:
        env.alerts_enabled = data['alerts_enabled']

    db.session.commit()
    return jsonify(env.to_dict())


@api_bp.route('/environments/<int:env_id>', methods=['DELETE'])
def delete_environment(env_id):
    """Delete an environment"""
    env = Environment.query.get_or_404(env_id)

    # Don't delete if there are servers attached
    if env.servers.count() > 0:
        return jsonify({'error': 'Cannot delete environment with attached servers'}), 400

    db.session.delete(env)
    db.session.commit()
    return jsonify({'status': 'deleted'})


# =============================================================================
# API Routes - Settings
# =============================================================================

@api_bp.route('/settings')
def get_settings():
    """Get global settings"""
    return jsonify({
        'slack_webhook': Settings.get('slack_webhook', ''),
        'alerts_enabled': Settings.get('alerts_enabled', 'true') == 'true',
        'login_alerts': Settings.get('login_alerts', 'true') == 'true',
        'logout_alerts': Settings.get('logout_alerts', 'true') == 'true'
    })


@api_bp.route('/settings', methods=['POST'])
def update_settings():
    """Update global settings"""
    data = request.get_json()

    if 'slack_webhook' in data:
        Settings.set('slack_webhook', data['slack_webhook'])
    if 'alerts_enabled' in data:
        Settings.set('alerts_enabled', 'true' if data['alerts_enabled'] else 'false')
    if 'login_alerts' in data:
        Settings.set('login_alerts', 'true' if data['login_alerts'] else 'false')
    if 'logout_alerts' in data:
        Settings.set('logout_alerts', 'true' if data['logout_alerts'] else 'false')

    return jsonify({'status': 'ok'})


@api_bp.route('/test-webhook', methods=['POST'])
def test_webhook():
    """Test a Slack webhook"""
    data = request.get_json()
    webhook_url = data.get('webhook_url')

    if not webhook_url:
        return jsonify({'success': False, 'error': 'No webhook URL provided'}), 400

    env_name = data.get('environment', 'Test')

    try:
        response = requests.post(webhook_url, json={
            'attachments': [{
                'color': '#0088ff',
                'text': f":white_check_mark: *SSH Monitor Test*\n"
                       f"*Environment:* {env_name}\n"
                       f"*Message:* Webhook test successful!\n"
                       f"*Time:* {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}"
            }]
        }, timeout=10)

        if response.status_code == 200:
            return jsonify({'success': True})
        else:
            return jsonify({
                'success': False,
                'error': f'Slack returned status {response.status_code}'
            })
    except requests.exceptions.Timeout:
        return jsonify({'success': False, 'error': 'Request timed out'})
    except requests.exceptions.RequestException as e:
        return jsonify({'success': False, 'error': str(e)})


# =============================================================================
# API Routes - Agent Endpoints
# =============================================================================

@api_bp.route('/event', methods=['POST'])
@require_api_key
def receive_event():
    """Receive session event from agent"""
    data = request.get_json()

    if not data:
        return jsonify({'error': 'No data provided'}), 400

    required_fields = ['hostname', 'event_type', 'username', 'tty', 'timestamp']
    for field in required_fields:
        if field not in data:
            return jsonify({'error': f'Missing field: {field}'}), 400

    # Get or create server
    server = Server.query.filter_by(hostname=data['hostname']).first()
    if not server:
        server = Server(
            hostname=data['hostname'],
            ip_address=data.get('server_ip')
        )

        # Auto-assign environment if specified
        if data.get('environment'):
            env = Environment.query.filter_by(name=data['environment']).first()
            if not env:
                env = Environment(name=data['environment'])
                db.session.add(env)
            server.environment = env

        db.session.add(server)

    server.last_seen = datetime.utcnow()

    event_type = data['event_type'].upper()
    timestamp = parse_timestamp(data.get('timestamp'))

    if event_type == 'LOGIN':
        # Create new session
        session = Session(
            server=server,
            username=data['username'],
            source_ip=data.get('source_ip', 'unknown'),
            tty=data['tty'],
            login_time=timestamp,
            session_hash=data.get('session_hash')
        )
        db.session.add(session)

        # Send Slack notification
        send_slack_notification('LOGIN', {
            'username': data['username'],
            'source_ip': data.get('source_ip', 'unknown'),
            'tty': data['tty'],
            'timestamp': data['timestamp']
        }, server, server.environment)

    elif event_type == 'LOGOUT':
        # Find and close session
        session = Session.query.filter_by(
            server=server,
            username=data['username'],
            tty=data['tty'],
            logout_time=None
        ).order_by(Session.login_time.desc()).first()

        if session:
            session.logout_time = timestamp

            # Send Slack notification
            send_slack_notification('LOGOUT', {
                'username': data['username'],
                'source_ip': session.source_ip,
                'tty': data['tty'],
                'timestamp': data['timestamp']
            }, server, server.environment)

    db.session.commit()

    # Audit log
    audit = AuditLog(
        action=f'SESSION_{event_type}',
        source_ip=request.remote_addr,
        details=f"{data['username']}@{data['hostname']} via {data['tty']}"
    )
    db.session.add(audit)
    db.session.commit()

    return jsonify({'status': 'ok'}), 200


@api_bp.route('/heartbeat', methods=['POST'])
@require_api_key
def heartbeat():
    """Receive heartbeat from agent"""
    data = request.get_json()

    if not data or 'hostname' not in data:
        return jsonify({'error': 'Missing hostname'}), 400

    server = Server.query.filter_by(hostname=data['hostname']).first()
    if server:
        server.last_seen = datetime.utcnow()
        db.session.commit()

    return jsonify({'status': 'ok'}), 200


# =============================================================================
# API Routes - VPN Monitoring
# =============================================================================

def send_vpn_slack_notification(event_type, session_data, is_monitored, large_transfer=False):
    """Send VPN-related Slack notification"""
    webhook = Settings.get('slack_webhook') or current_app.config.get('SLACK_WEBHOOK')
    if not webhook:
        return

    # Only alert for monitored users or large transfers
    if not is_monitored and not large_transfer:
        return

    if event_type == 'CONNECT':
        color = '#FF0000' if is_monitored else '#36A64F'
        emoji = '🚨' if is_monitored else '🔗'
        priority = '*HIGH PRIORITY* - Monitored User' if is_monitored else ''
    else:
        color = '#FF0000' if large_transfer else '#808080'
        emoji = '🚨' if large_transfer else '🔌'
        priority = '*LARGE DATA TRANSFER DETECTED*' if large_transfer else ''

    try:
        requests.post(webhook, json={
            'attachments': [{
                'color': color,
                'text': f"{emoji} *VPN {event_type}*\n"
                       f"*User:* {session_data['username']}\n"
                       f"*Source IP:* {session_data.get('source_ip', 'N/A')}\n"
                       f"*VPN IP:* {session_data.get('vpn_ip', 'N/A')}\n"
                       f"*Server:* {session_data.get('vpn_server', 'N/A')}\n"
                       f"{priority}\n"
                       f"*Time:* {session_data.get('timestamp', 'N/A')}"
            }]
        }, timeout=5)
    except Exception:
        pass


@api_bp.route('/vpn/stats')
def vpn_stats():
    """Get VPN statistics"""
    now = datetime.utcnow()
    today_start = now.replace(hour=0, minute=0, second=0, microsecond=0)

    active_connections = VPNSession.query.filter_by(disconnect_time=None).count()
    monitored_active = VPNSession.query.filter_by(
        disconnect_time=None, is_monitored_user=True
    ).count()
    today_connections = VPNSession.query.filter(
        VPNSession.connect_time >= today_start
    ).count()
    total_vpn_servers = VPNServer.query.count()

    # Total data transferred today
    today_data = db.session.query(
        db.func.coalesce(db.func.sum(VPNSession.bytes_sent), 0),
        db.func.coalesce(db.func.sum(VPNSession.bytes_received), 0)
    ).filter(VPNSession.connect_time >= today_start).first()

    return jsonify({
        'active_connections': active_connections,
        'monitored_active': monitored_active,
        'today_connections': today_connections,
        'total_vpn_servers': total_vpn_servers,
        'today_bytes_sent': today_data[0],
        'today_bytes_received': today_data[1]
    })


@api_bp.route('/vpn/sessions')
def list_vpn_sessions():
    """List VPN sessions with filtering"""
    active_only = request.args.get('active', 'false').lower() == 'true'
    monitored_only = request.args.get('monitored', 'false').lower() == 'true'
    username = sanitize_string(request.args.get('username'), 100)
    limit = get_int_param('limit', 100, 1, 1000)
    offset = get_int_param('offset', 0, 0, 100000)

    query = VPNSession.query.join(VPNServer)

    if active_only:
        query = query.filter(VPNSession.disconnect_time.is_(None))

    if monitored_only:
        query = query.filter(VPNSession.is_monitored_user == True)

    if username:
        query = query.filter(VPNSession.username.ilike(f'%{username}%'))

    total = query.count()
    sessions = query.order_by(VPNSession.connect_time.desc()).offset(offset).limit(limit).all()

    return jsonify({
        'total': total,
        'sessions': [s.to_dict() for s in sessions]
    })


@api_bp.route('/vpn/sessions/active')
def active_vpn_sessions():
    """Get all active VPN sessions"""
    sessions = VPNSession.query.filter_by(disconnect_time=None).join(VPNServer).order_by(
        VPNSession.connect_time.desc()
    ).all()
    return jsonify([s.to_dict() for s in sessions])


@api_bp.route('/vpn/servers')
def list_vpn_servers():
    """List all VPN servers"""
    servers = VPNServer.query.order_by(VPNServer.hostname).all()
    return jsonify([s.to_dict() for s in servers])


@api_bp.route('/vpn/monitored-users')
def list_monitored_users():
    """List monitored users"""
    users = MonitoredUser.query.filter_by(is_active=True).order_by(MonitoredUser.username).all()
    return jsonify([u.to_dict() for u in users])


@api_bp.route('/vpn/monitored-users', methods=['POST'])
def add_monitored_user():
    """Add a monitored user"""
    data = request.get_json()

    if not data or 'username' not in data:
        return jsonify({'error': 'Username required'}), 400

    existing = MonitoredUser.query.filter_by(username=data['username']).first()
    if existing:
        existing.is_active = True
        existing.reason = data.get('reason', existing.reason)
        db.session.commit()
        return jsonify(existing.to_dict())

    user = MonitoredUser(
        username=data['username'],
        reason=data.get('reason', ''),
        added_by=data.get('added_by', 'admin')
    )
    db.session.add(user)
    db.session.commit()

    return jsonify(user.to_dict()), 201


@api_bp.route('/vpn/monitored-users/<int:user_id>', methods=['DELETE'])
def remove_monitored_user(user_id):
    """Remove a monitored user"""
    user = MonitoredUser.query.get_or_404(user_id)
    user.is_active = False
    db.session.commit()
    return jsonify({'status': 'removed'})


@api_bp.route('/vpn/connect', methods=['POST'])
@require_api_key
def vpn_connect():
    """Receive VPN connect event from OpenVPN script"""
    data = request.get_json()

    if not data:
        return jsonify({'error': 'No data provided'}), 400

    required_fields = ['hostname', 'username', 'trusted_ip']
    for field in required_fields:
        if field not in data:
            return jsonify({'error': f'Missing field: {field}'}), 400

    # Get or create VPN server
    vpn_server = VPNServer.query.filter_by(hostname=data['hostname']).first()
    if not vpn_server:
        vpn_server = VPNServer(hostname=data['hostname'])
        db.session.add(vpn_server)

    vpn_server.last_seen = datetime.utcnow()

    # Check if user is monitored
    monitored_user = MonitoredUser.query.filter_by(
        username=data['username'], is_active=True
    ).first()
    is_monitored = monitored_user is not None

    # Parse timestamp
    timestamp = parse_timestamp(data.get('timestamp'))

    # Create session
    session = VPNSession(
        vpn_server=vpn_server,
        username=data['username'],
        source_ip=data['trusted_ip'],
        vpn_ip=data.get('vpn_ip'),
        connect_time=timestamp,
        is_monitored_user=is_monitored,
        session_hash=data.get('session_hash')
    )
    db.session.add(session)
    db.session.commit()

    # Send Slack notification for monitored users
    send_vpn_slack_notification('CONNECT', {
        'username': data['username'],
        'source_ip': data['trusted_ip'],
        'vpn_ip': data.get('vpn_ip'),
        'vpn_server': data['hostname'],
        'timestamp': data.get('timestamp', timestamp.isoformat())
    }, is_monitored)

    # Audit log
    audit = AuditLog(
        action='VPN_CONNECT',
        source_ip=request.remote_addr,
        details=f"{data['username']} from {data['trusted_ip']} on {data['hostname']}"
    )
    db.session.add(audit)
    db.session.commit()

    return jsonify({'status': 'ok', 'is_monitored': is_monitored}), 200


@api_bp.route('/vpn/disconnect', methods=['POST'])
@require_api_key
def vpn_disconnect():
    """Receive VPN disconnect event from OpenVPN script"""
    data = request.get_json()

    if not data:
        return jsonify({'error': 'No data provided'}), 400

    required_fields = ['hostname', 'username']
    for field in required_fields:
        if field not in data:
            return jsonify({'error': f'Missing field: {field}'}), 400

    # Find VPN server
    vpn_server = VPNServer.query.filter_by(hostname=data['hostname']).first()
    if not vpn_server:
        return jsonify({'error': 'VPN server not found'}), 404

    vpn_server.last_seen = datetime.utcnow()

    # Find active session for this user
    session = VPNSession.query.filter_by(
        vpn_server=vpn_server,
        username=data['username'],
        disconnect_time=None
    ).order_by(VPNSession.connect_time.desc()).first()

    if not session:
        return jsonify({'error': 'No active session found'}), 404

    # Parse timestamp
    timestamp = parse_timestamp(data.get('timestamp'))

    # Update session
    session.disconnect_time = timestamp
    session.duration_seconds = data.get('duration_seconds', 0)
    session.bytes_received = data.get('bytes_received', 0)
    session.bytes_sent = data.get('bytes_sent', 0)

    db.session.commit()

    # Check for large data transfer (500MB threshold)
    large_transfer = session.bytes_sent > 524288000

    # Send Slack notification
    send_vpn_slack_notification('DISCONNECT', {
        'username': data['username'],
        'source_ip': session.source_ip,
        'vpn_ip': session.vpn_ip,
        'vpn_server': data['hostname'],
        'timestamp': data.get('timestamp', timestamp.isoformat()),
        'bytes_sent': session.bytes_sent,
        'bytes_received': session.bytes_received
    }, session.is_monitored_user, large_transfer)

    # Audit log
    audit = AuditLog(
        action='VPN_DISCONNECT',
        source_ip=request.remote_addr,
        details=f"{data['username']} on {data['hostname']} - sent: {session.bytes_sent}, received: {session.bytes_received}"
    )
    db.session.add(audit)
    db.session.commit()

    return jsonify({'status': 'ok'}), 200
