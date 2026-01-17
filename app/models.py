from datetime import datetime
from app import db


class Settings(db.Model):
    """Global application settings"""
    __tablename__ = 'settings'

    id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.String(100), unique=True, nullable=False)
    value = db.Column(db.Text)

    @staticmethod
    def get(key, default=None):
        setting = Settings.query.filter_by(key=key).first()
        return setting.value if setting else default

    @staticmethod
    def set(key, value):
        setting = Settings.query.filter_by(key=key).first()
        if setting:
            setting.value = value
        else:
            setting = Settings(key=key, value=value)
            db.session.add(setting)
        db.session.commit()


class Environment(db.Model):
    """Represents a server environment (prod, staging, dev, etc.)"""
    __tablename__ = 'environments'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True, nullable=False)
    description = db.Column(db.String(200))
    slack_webhook = db.Column(db.String(500))  # Optional per-env webhook
    alerts_enabled = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    servers = db.relationship('Server', backref='environment', lazy='dynamic')

    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'description': self.description,
            'slack_webhook': self.slack_webhook,
            'alerts_enabled': self.alerts_enabled,
            'server_count': self.servers.count(),
            'created_at': self.created_at.isoformat()
        }


class Server(db.Model):
    """Represents a monitored server"""
    __tablename__ = 'servers'

    id = db.Column(db.Integer, primary_key=True)
    hostname = db.Column(db.String(255), unique=True, nullable=False)
    ip_address = db.Column(db.String(45))
    environment_id = db.Column(db.Integer, db.ForeignKey('environments.id'))
    last_seen = db.Column(db.DateTime)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    sessions = db.relationship('Session', backref='server', lazy='dynamic')

    def to_dict(self):
        return {
            'id': self.id,
            'hostname': self.hostname,
            'ip_address': self.ip_address,
            'environment': self.environment.name if self.environment else None,
            'last_seen': self.last_seen.isoformat() if self.last_seen else None,
            'active_sessions': self.sessions.filter_by(logout_time=None).count()
        }


class Session(db.Model):
    """Represents an SSH session"""
    __tablename__ = 'sessions'

    id = db.Column(db.Integer, primary_key=True)
    server_id = db.Column(db.Integer, db.ForeignKey('servers.id'), nullable=False)
    username = db.Column(db.String(100), nullable=False)
    source_ip = db.Column(db.String(45))
    tty = db.Column(db.String(50))
    login_time = db.Column(db.DateTime, nullable=False)
    logout_time = db.Column(db.DateTime)
    session_hash = db.Column(db.String(64), index=True)  # For deduplication

    # Indexes for common queries
    __table_args__ = (
        db.Index('idx_session_active', 'logout_time', 'login_time'),
        db.Index('idx_session_user', 'username', 'login_time'),
    )

    def to_dict(self):
        return {
            'id': self.id,
            'server': self.server.hostname,
            'environment': self.server.environment.name if self.server.environment else None,
            'username': self.username,
            'source_ip': self.source_ip,
            'tty': self.tty,
            'login_time': self.login_time.isoformat(),
            'logout_time': self.logout_time.isoformat() if self.logout_time else None,
            'is_active': self.logout_time is None,
            'duration': str(self.logout_time - self.login_time) if self.logout_time else None
        }


class AuditLog(db.Model):
    """Audit log for tracking API access and changes"""
    __tablename__ = 'audit_logs'

    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    action = db.Column(db.String(50), nullable=False)
    source_ip = db.Column(db.String(45))
    details = db.Column(db.Text)


# =============================================================================
# VPN Monitoring Models
# =============================================================================

class MonitoredUser(db.Model):
    """Users flagged for enhanced monitoring"""
    __tablename__ = 'monitored_users'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    reason = db.Column(db.String(200))
    added_by = db.Column(db.String(100))
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {
            'id': self.id,
            'username': self.username,
            'reason': self.reason,
            'added_by': self.added_by,
            'is_active': self.is_active,
            'created_at': self.created_at.isoformat()
        }


class VPNServer(db.Model):
    """Represents a VPN server"""
    __tablename__ = 'vpn_servers'

    id = db.Column(db.Integer, primary_key=True)
    hostname = db.Column(db.String(255), unique=True, nullable=False)
    description = db.Column(db.String(200))
    last_seen = db.Column(db.DateTime)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    sessions = db.relationship('VPNSession', backref='vpn_server', lazy='dynamic')

    def to_dict(self):
        return {
            'id': self.id,
            'hostname': self.hostname,
            'description': self.description,
            'last_seen': self.last_seen.isoformat() if self.last_seen else None,
            'active_connections': self.sessions.filter_by(disconnect_time=None).count()
        }


class VPNSession(db.Model):
    """Represents a VPN connection session"""
    __tablename__ = 'vpn_sessions'

    id = db.Column(db.Integer, primary_key=True)
    vpn_server_id = db.Column(db.Integer, db.ForeignKey('vpn_servers.id'), nullable=False)
    username = db.Column(db.String(100), nullable=False)
    source_ip = db.Column(db.String(45))  # trusted_ip
    vpn_ip = db.Column(db.String(45))  # ifconfig_pool_remote_ip
    connect_time = db.Column(db.DateTime, nullable=False)
    disconnect_time = db.Column(db.DateTime)
    duration_seconds = db.Column(db.Integer)
    bytes_received = db.Column(db.BigInteger, default=0)
    bytes_sent = db.Column(db.BigInteger, default=0)
    is_monitored_user = db.Column(db.Boolean, default=False)
    session_hash = db.Column(db.String(64), index=True)

    __table_args__ = (
        db.Index('idx_vpn_session_active', 'disconnect_time', 'connect_time'),
        db.Index('idx_vpn_session_user', 'username', 'connect_time'),
    )

    def to_dict(self):
        return {
            'id': self.id,
            'vpn_server': self.vpn_server.hostname,
            'username': self.username,
            'source_ip': self.source_ip,
            'vpn_ip': self.vpn_ip,
            'connect_time': self.connect_time.isoformat(),
            'disconnect_time': self.disconnect_time.isoformat() if self.disconnect_time else None,
            'is_active': self.disconnect_time is None,
            'duration_seconds': self.duration_seconds,
            'duration_formatted': self._format_duration(),
            'bytes_received': self.bytes_received,
            'bytes_sent': self.bytes_sent,
            'bytes_received_formatted': self._format_bytes(self.bytes_received),
            'bytes_sent_formatted': self._format_bytes(self.bytes_sent),
            'is_monitored_user': self.is_monitored_user
        }

    def _format_duration(self):
        if not self.duration_seconds:
            return None
        hours = self.duration_seconds // 3600
        minutes = (self.duration_seconds % 3600) // 60
        seconds = self.duration_seconds % 60
        return f"{hours:02d}:{minutes:02d}:{seconds:02d}"

    def _format_bytes(self, bytes_val):
        if not bytes_val:
            return "0 B"
        if bytes_val >= 1073741824:
            return f"{bytes_val / 1073741824:.2f} GB"
        elif bytes_val >= 1048576:
            return f"{bytes_val / 1048576:.2f} MB"
        elif bytes_val >= 1024:
            return f"{bytes_val / 1024:.2f} KB"
        return f"{bytes_val} B"
