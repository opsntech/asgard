from datetime import datetime, timedelta
from functools import wraps
from flask import Blueprint, request, jsonify, render_template, current_app, session, redirect, url_for
import requests
import secrets
import re

from app import db
from app.models import (
    Environment, Server, Session, AuditLog, Settings,
    MonitoredUser, VPNServer, VPNSession, User,
    SiriusIncident, SiriusAlert, SiriusAction, SiriusInvestigationStep
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
        if not session.get('user_id'):
            return redirect(url_for('main.login'))
        return f(*args, **kwargs)
    return decorated


def require_admin(f):
    """Decorator to require admin role"""
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get('user_id'):
            return redirect(url_for('main.login'))
        user = User.query.get(session['user_id'])
        if not user or not user.is_admin():
            return jsonify({'error': 'Admin access required'}), 403
        return f(*args, **kwargs)
    return decorated


def get_current_user():
    """Get the currently logged in user"""
    if session.get('user_id'):
        return User.query.get(session['user_id'])
    return None


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
    # Redirect to setup if no users exist
    if User.query.count() == 0:
        return redirect(url_for('main.setup'))

    if session.get('user_id'):
        return redirect(url_for('main.dashboard'))

    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')

        user = User.query.filter_by(username=username, is_active=True).first()
        if user and user.check_password(password):
            session['user_id'] = user.id
            session['username'] = user.username
            session['role'] = user.role
            user.last_login = datetime.utcnow()
            db.session.commit()
            return redirect(url_for('main.dashboard'))
        return render_template('login.html', error='Invalid username or password')

    return render_template('login.html')


@main_bp.route('/logout')
def logout():
    """Logout from dashboard"""
    session.clear()
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


@main_bp.route('/sirius')
@require_dashboard_auth
def sirius_view():
    """Sirius AI DevOps Agent incidents view"""
    return render_template('sirius.html')


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

    # Update environment if specified (for new or existing servers without environment)
    if data.get('environment') and not vpn_server.environment:
        env = Environment.query.filter_by(name=data['environment']).first()
        if not env:
            env = Environment(name=data['environment'])
            db.session.add(env)
        vpn_server.environment = env

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


# =============================================================================
# API Routes - User Management
# =============================================================================

@main_bp.route('/users')
@require_dashboard_auth
def users_view():
    """Users management view (admin only)"""
    user = get_current_user()
    if not user or not user.is_admin():
        return redirect(url_for('main.dashboard'))
    return render_template('users.html')


@main_bp.route('/setup', methods=['GET', 'POST'])
def setup():
    """Initial setup - create admin user if none exists"""
    # Check if any users exist
    if User.query.count() > 0:
        return redirect(url_for('main.login'))

    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '')
        confirm_password = request.form.get('confirm_password', '')

        errors = []
        if not username or len(username) < 3:
            errors.append('Username must be at least 3 characters')
        if not email or '@' not in email:
            errors.append('Valid email is required')
        if not password or len(password) < 8:
            errors.append('Password must be at least 8 characters')
        if password != confirm_password:
            errors.append('Passwords do not match')

        if errors:
            return render_template('setup.html', errors=errors)

        admin = User(
            username=username,
            email=email,
            role='admin'
        )
        admin.set_password(password)
        db.session.add(admin)
        db.session.commit()

        session['user_id'] = admin.id
        session['username'] = admin.username
        session['role'] = admin.role
        return redirect(url_for('main.dashboard'))

    return render_template('setup.html')


@api_bp.route('/users')
@require_admin
def list_users():
    """List all users (admin only)"""
    users = User.query.order_by(User.username).all()
    return jsonify([u.to_dict() for u in users])


@api_bp.route('/users', methods=['POST'])
@require_admin
def create_user():
    """Create a new user (admin only)"""
    data = request.get_json()

    if not data:
        return jsonify({'error': 'No data provided'}), 400

    username = sanitize_string(data.get('username', '').strip(), 80)
    email = sanitize_string(data.get('email', '').strip(), 120)
    password = data.get('password', '')
    role = data.get('role', 'user')

    if not username or len(username) < 3:
        return jsonify({'error': 'Username must be at least 3 characters'}), 400
    if not email or '@' not in email:
        return jsonify({'error': 'Valid email is required'}), 400
    if not password or len(password) < 8:
        return jsonify({'error': 'Password must be at least 8 characters'}), 400
    if role not in ['admin', 'user']:
        return jsonify({'error': 'Role must be admin or user'}), 400

    if User.query.filter_by(username=username).first():
        return jsonify({'error': 'Username already exists'}), 400
    if User.query.filter_by(email=email).first():
        return jsonify({'error': 'Email already exists'}), 400

    user = User(username=username, email=email, role=role)
    user.set_password(password)
    db.session.add(user)
    db.session.commit()

    return jsonify(user.to_dict()), 201


@api_bp.route('/users/<int:user_id>', methods=['PUT'])
@require_admin
def update_user(user_id):
    """Update a user (admin only)"""
    user = User.query.get_or_404(user_id)
    data = request.get_json()

    if 'email' in data:
        email = sanitize_string(data['email'].strip(), 120)
        existing = User.query.filter(User.email == email, User.id != user_id).first()
        if existing:
            return jsonify({'error': 'Email already exists'}), 400
        user.email = email

    if 'role' in data and data['role'] in ['admin', 'user']:
        user.role = data['role']

    if 'is_active' in data:
        user.is_active = bool(data['is_active'])

    if 'password' in data and data['password']:
        if len(data['password']) < 8:
            return jsonify({'error': 'Password must be at least 8 characters'}), 400
        user.set_password(data['password'])

    db.session.commit()
    return jsonify(user.to_dict())


@api_bp.route('/users/<int:user_id>', methods=['DELETE'])
@require_admin
def delete_user(user_id):
    """Delete a user (admin only)"""
    current_user = get_current_user()
    if current_user and current_user.id == user_id:
        return jsonify({'error': 'Cannot delete your own account'}), 400

    user = User.query.get_or_404(user_id)
    db.session.delete(user)
    db.session.commit()
    return jsonify({'status': 'deleted'})


@api_bp.route('/me')
@require_dashboard_auth
def get_current_user_info():
    """Get current user info"""
    user = get_current_user()
    if not user:
        return jsonify({'error': 'Not authenticated'}), 401
    return jsonify(user.to_dict())


# =============================================================================
# API Routes - Sirius AI DevOps Agent
# =============================================================================

@api_bp.route('/sirius/webhook/incident', methods=['POST'])
@require_api_key
def sirius_webhook_incident():
    """Receive incident from Sirius agent"""
    data = request.get_json()

    if not data:
        return jsonify({'error': 'No data provided'}), 400

    required_fields = ['incident_id', 'title', 'severity', 'status', 'detected_at']
    for field in required_fields:
        if field not in data:
            return jsonify({'error': f'Missing field: {field}'}), 400

    # Check if incident already exists
    incident = SiriusIncident.query.get(data['incident_id'])

    if incident:
        # Update existing incident
        incident.title = data['title']
        incident.severity = data['severity']
        incident.status = data['status']
        incident.root_cause = data.get('root_cause')
        incident.root_cause_confidence = data.get('root_cause_confidence')
        incident.affected_servers = data.get('affected_servers', [])
        incident.affected_services = data.get('affected_services', [])
        incident.analyzed_at = parse_timestamp(data.get('analyzed_at')) if data.get('analyzed_at') else None
        incident.resolved_at = parse_timestamp(data.get('resolved_at')) if data.get('resolved_at') else None
    else:
        # Create new incident
        incident = SiriusIncident(
            id=data['incident_id'],
            title=data['title'],
            severity=data['severity'],
            status=data['status'],
            root_cause=data.get('root_cause'),
            root_cause_confidence=data.get('root_cause_confidence'),
            affected_servers=data.get('affected_servers', []),
            affected_services=data.get('affected_services', []),
            detected_at=parse_timestamp(data['detected_at']),
            analyzed_at=parse_timestamp(data.get('analyzed_at')) if data.get('analyzed_at') else None,
        )
        db.session.add(incident)

    # Process alerts
    if 'alerts' in data:
        # Remove existing alerts and add new ones
        SiriusAlert.query.filter_by(incident_id=incident.id).delete()
        for alert_data in data['alerts']:
            alert = SiriusAlert(
                incident_id=incident.id,
                alertname=alert_data.get('alertname', 'Unknown'),
                severity=alert_data.get('severity'),
                status=alert_data.get('status', 'firing'),
                instance=alert_data.get('instance'),
                job=alert_data.get('job'),
                description=alert_data.get('description'),
                labels=alert_data.get('labels'),
                annotations=alert_data.get('annotations'),
                starts_at=parse_timestamp(alert_data.get('starts_at')) if alert_data.get('starts_at') else None,
                ends_at=parse_timestamp(alert_data.get('ends_at')) if alert_data.get('ends_at') else None,
                fingerprint=alert_data.get('fingerprint'),
            )
            db.session.add(alert)

    # Process actions
    if 'actions' in data:
        # Remove existing actions and add new ones
        SiriusAction.query.filter_by(incident_id=incident.id).delete()
        for idx, action_data in enumerate(data['actions']):
            action = SiriusAction(
                incident_id=incident.id,
                action_type=action_data.get('action_type', 'unknown'),
                description=action_data.get('description'),
                target_host=action_data.get('target_host'),
                target_service=action_data.get('target_service'),
                command=action_data.get('command'),
                risk_level=action_data.get('risk_level', 'medium'),
                status=action_data.get('status', 'pending'),
                order_index=idx,
            )
            db.session.add(action)

    # Process investigation steps
    if 'investigation_steps' in data:
        # Remove existing steps and add new ones
        SiriusInvestigationStep.query.filter_by(incident_id=incident.id).delete()
        for step_data in data['investigation_steps']:
            step = SiriusInvestigationStep(
                incident_id=incident.id,
                agent=step_data.get('agent'),
                action=step_data.get('action'),
                target=step_data.get('target'),
                result=step_data.get('result'),
                timestamp=parse_timestamp(step_data.get('timestamp')) if step_data.get('timestamp') else datetime.utcnow(),
            )
            db.session.add(step)

    db.session.commit()

    # Audit log
    audit = AuditLog(
        action='SIRIUS_INCIDENT',
        source_ip=request.remote_addr,
        details=f"Incident {incident.id}: {incident.title} ({incident.status})"
    )
    db.session.add(audit)
    db.session.commit()

    return jsonify({'status': 'ok', 'incident_id': incident.id}), 200


@api_bp.route('/sirius/approval/<incident_id>')
@require_api_key
def sirius_check_approval(incident_id):
    """Check approval status for an incident (polled by Sirius)"""
    incident = SiriusIncident.query.get(incident_id)

    if not incident:
        return jsonify({'error': 'Incident not found'}), 404

    status = 'pending'
    if incident.status == 'approved':
        status = 'approved'
    elif incident.status == 'rejected':
        status = 'rejected'
    elif incident.status in ['awaiting_approval', 'analyzing', 'pending']:
        status = 'pending'
    else:
        status = incident.status

    return jsonify({
        'status': status,
        'approved_by': incident.approved_by,
        'approved_at': incident.approved_at.isoformat() if incident.approved_at else None,
        'reason': incident.rejection_reason,
    })


@api_bp.route('/sirius/webhook/execution_result', methods=['POST'])
@require_api_key
def sirius_execution_result():
    """Receive action execution results from Sirius"""
    data = request.get_json()

    if not data:
        return jsonify({'error': 'No data provided'}), 400

    incident_id = data.get('incident_id')
    action_id = data.get('action_id')

    if not incident_id or action_id is None:
        return jsonify({'error': 'Missing incident_id or action_id'}), 400

    action = SiriusAction.query.filter_by(
        incident_id=incident_id,
        id=action_id
    ).first()

    if not action:
        # Try to find by order_index if action_id doesn't match
        action = SiriusAction.query.filter_by(
            incident_id=incident_id,
            order_index=action_id
        ).first()

    if not action:
        return jsonify({'error': 'Action not found'}), 404

    action.status = 'executed' if data.get('status') == 'success' else 'failed'
    action.execution_output = data.get('output', '')
    action.executed_at = datetime.utcnow()

    # Update incident status if all actions are done
    incident = SiriusIncident.query.get(incident_id)
    if incident:
        all_done = all(
            a.status in ['executed', 'failed', 'rejected']
            for a in incident.actions.all()
        )
        if all_done:
            all_success = all(
                a.status == 'executed'
                for a in incident.actions.all()
            )
            if all_success:
                incident.status = 'resolved'
                incident.resolved_at = datetime.utcnow()

    db.session.commit()

    return jsonify({'status': 'ok'}), 200


@api_bp.route('/sirius/stats')
def sirius_stats():
    """Get Sirius statistics for dashboard"""
    now = datetime.utcnow()
    today_start = now.replace(hour=0, minute=0, second=0, microsecond=0)

    total_incidents = SiriusIncident.query.count()
    pending_approvals = SiriusIncident.query.filter(
        SiriusIncident.status.in_(['awaiting_approval'])
    ).count()
    resolved_today = SiriusIncident.query.filter(
        SiriusIncident.resolved_at >= today_start
    ).count()

    # Calculate average MTTR for resolved incidents today
    resolved_incidents = SiriusIncident.query.filter(
        SiriusIncident.resolved_at >= today_start,
        SiriusIncident.resolved_at.isnot(None),
        SiriusIncident.detected_at.isnot(None)
    ).all()

    if resolved_incidents:
        total_mttr = sum(
            (i.resolved_at - i.detected_at).total_seconds()
            for i in resolved_incidents
        )
        avg_mttr = int(total_mttr / len(resolved_incidents))
    else:
        avg_mttr = 0

    # Incidents by severity
    severity_counts = db.session.query(
        SiriusIncident.severity,
        db.func.count(SiriusIncident.id)
    ).group_by(SiriusIncident.severity).all()

    # Incidents by status
    status_counts = db.session.query(
        SiriusIncident.status,
        db.func.count(SiriusIncident.id)
    ).group_by(SiriusIncident.status).all()

    return jsonify({
        'total_incidents': total_incidents,
        'pending_approvals': pending_approvals,
        'resolved_today': resolved_today,
        'avg_mttr_seconds': avg_mttr,
        'by_severity': dict(severity_counts),
        'by_status': dict(status_counts),
    })


@api_bp.route('/sirius/incidents')
def sirius_list_incidents():
    """List Sirius incidents with filtering and pagination"""
    # Query parameters
    status = sanitize_string(request.args.get('status'), 20)
    severity = sanitize_string(request.args.get('severity'), 20)
    server = sanitize_string(request.args.get('server'), 255)
    service = sanitize_string(request.args.get('service'), 100)
    search = sanitize_string(request.args.get('search'), 100)
    limit = get_int_param('limit', 50, 1, 500)
    offset = get_int_param('offset', 0, 0, 100000)

    query = SiriusIncident.query

    if status:
        query = query.filter(SiriusIncident.status == status)

    if severity:
        query = query.filter(SiriusIncident.severity == severity)

    if server:
        # Filter by affected server (JSON array contains)
        query = query.filter(
            SiriusIncident.affected_servers.contains([server])
        )

    if service:
        # Filter by affected service (JSON array contains)
        query = query.filter(
            SiriusIncident.affected_services.contains([service])
        )

    if search:
        query = query.filter(
            db.or_(
                SiriusIncident.title.ilike(f'%{search}%'),
                SiriusIncident.root_cause.ilike(f'%{search}%'),
                SiriusIncident.id.ilike(f'%{search}%')
            )
        )

    total = query.count()
    incidents = query.order_by(SiriusIncident.detected_at.desc()).offset(offset).limit(limit).all()

    return jsonify({
        'total': total,
        'incidents': [i.to_dict() for i in incidents]
    })


@api_bp.route('/sirius/incidents/pending')
def sirius_pending_incidents():
    """Get all incidents awaiting approval"""
    incidents = SiriusIncident.query.filter(
        SiriusIncident.status == 'awaiting_approval'
    ).order_by(SiriusIncident.detected_at.desc()).all()

    return jsonify([i.to_dict(include_details=True) for i in incidents])


@api_bp.route('/sirius/incidents/<incident_id>')
def sirius_get_incident(incident_id):
    """Get a specific incident with full details"""
    incident = SiriusIncident.query.get(incident_id)

    if not incident:
        return jsonify({'error': 'Incident not found'}), 404

    return jsonify(incident.to_dict(include_details=True))


@api_bp.route('/sirius/incidents/<incident_id>/approve', methods=['POST'])
@require_dashboard_auth
def sirius_approve_incident(incident_id):
    """Approve incident remediation actions"""
    incident = SiriusIncident.query.get(incident_id)

    if not incident:
        return jsonify({'error': 'Incident not found'}), 404

    if incident.status != 'awaiting_approval':
        return jsonify({'error': f'Incident is not awaiting approval (current status: {incident.status})'}), 400

    user = get_current_user()
    username = user.username if user else 'unknown'

    incident.status = 'approved'
    incident.approved_by = username
    incident.approved_at = datetime.utcnow()

    # Update all pending actions to approved
    for action in incident.actions.filter_by(status='pending').all():
        action.status = 'approved'

    db.session.commit()

    # Audit log
    audit = AuditLog(
        action='SIRIUS_APPROVE',
        source_ip=request.remote_addr,
        details=f"Incident {incident.id} approved by {username}"
    )
    db.session.add(audit)
    db.session.commit()

    return jsonify({'status': 'ok', 'approved_by': username})


@api_bp.route('/sirius/incidents/<incident_id>/reject', methods=['POST'])
@require_dashboard_auth
def sirius_reject_incident(incident_id):
    """Reject incident remediation actions"""
    incident = SiriusIncident.query.get(incident_id)

    if not incident:
        return jsonify({'error': 'Incident not found'}), 404

    if incident.status != 'awaiting_approval':
        return jsonify({'error': f'Incident is not awaiting approval (current status: {incident.status})'}), 400

    data = request.get_json() or {}
    reason = data.get('reason', '')

    user = get_current_user()
    username = user.username if user else 'unknown'

    incident.status = 'rejected'
    incident.approved_by = username
    incident.approved_at = datetime.utcnow()
    incident.rejection_reason = reason

    # Update all pending actions to rejected
    for action in incident.actions.filter_by(status='pending').all():
        action.status = 'rejected'

    db.session.commit()

    # Audit log
    audit = AuditLog(
        action='SIRIUS_REJECT',
        source_ip=request.remote_addr,
        details=f"Incident {incident.id} rejected by {username}: {reason}"
    )
    db.session.add(audit)
    db.session.commit()

    return jsonify({'status': 'ok', 'rejected_by': username})
