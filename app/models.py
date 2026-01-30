from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
from app import db


class User(db.Model):
    """Application users with role-based access"""
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    role = db.Column(db.String(20), default='user')  # 'admin' or 'user'
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def is_admin(self):
        return self.role == 'admin'

    def to_dict(self):
        return {
            'id': self.id,
            'username': self.username,
            'email': self.email,
            'role': self.role,
            'is_active': self.is_active,
            'created_at': self.created_at.isoformat(),
            'last_login': self.last_login.isoformat() if self.last_login else None
        }


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
    environment_id = db.Column(db.Integer, db.ForeignKey('environments.id'))
    last_seen = db.Column(db.DateTime)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    environment = db.relationship('Environment', backref='vpn_servers')
    sessions = db.relationship('VPNSession', backref='vpn_server', lazy='dynamic')

    def to_dict(self):
        return {
            'id': self.id,
            'hostname': self.hostname,
            'description': self.description,
            'environment': self.environment.name if self.environment else None,
            'environment_id': self.environment_id,
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
            'environment': self.vpn_server.environment.name if self.vpn_server.environment else None,
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


# =============================================================================
# Sirius AI DevOps Agent Models
# =============================================================================

class SiriusIncident(db.Model):
    """Represents an incident analyzed by Sirius AI agent"""
    __tablename__ = 'sirius_incidents'

    id = db.Column(db.String(36), primary_key=True)  # UUID from Sirius
    title = db.Column(db.String(255), nullable=False)
    severity = db.Column(db.String(20), nullable=False)  # critical, high, medium, low, info
    status = db.Column(db.String(20), nullable=False, default='pending')
    # Status values: pending, analyzing, awaiting_approval, approved, rejected, executing, resolved

    # Analysis results
    root_cause = db.Column(db.Text)
    root_cause_confidence = db.Column(db.Float)

    # Affected resources (stored as JSON arrays)
    affected_servers = db.Column(db.JSON)
    affected_services = db.Column(db.JSON)

    # Timestamps
    detected_at = db.Column(db.DateTime, nullable=False)
    analyzed_at = db.Column(db.DateTime)
    resolved_at = db.Column(db.DateTime)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Approval tracking
    approved_by = db.Column(db.String(100))
    approved_at = db.Column(db.DateTime)
    rejection_reason = db.Column(db.Text)

    # Relationships
    alerts = db.relationship('SiriusAlert', backref='incident', lazy='dynamic', cascade='all, delete-orphan')
    actions = db.relationship('SiriusAction', backref='incident', lazy='dynamic', cascade='all, delete-orphan')
    investigation_steps = db.relationship('SiriusInvestigationStep', backref='incident', lazy='dynamic', cascade='all, delete-orphan')

    __table_args__ = (
        db.Index('idx_sirius_incident_status', 'status'),
        db.Index('idx_sirius_incident_severity', 'severity'),
        db.Index('idx_sirius_incident_detected', 'detected_at'),
    )

    def to_dict(self, include_details=False):
        result = {
            'id': self.id,
            'title': self.title,
            'severity': self.severity,
            'status': self.status,
            'root_cause': self.root_cause,
            'root_cause_confidence': self.root_cause_confidence,
            'affected_servers': self.affected_servers or [],
            'affected_services': self.affected_services or [],
            'detected_at': self.detected_at.isoformat() if self.detected_at else None,
            'analyzed_at': self.analyzed_at.isoformat() if self.analyzed_at else None,
            'resolved_at': self.resolved_at.isoformat() if self.resolved_at else None,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'approved_by': self.approved_by,
            'approved_at': self.approved_at.isoformat() if self.approved_at else None,
            'rejection_reason': self.rejection_reason,
            'alert_count': self.alerts.count(),
            'action_count': self.actions.count(),
        }

        if include_details:
            result['alerts'] = [a.to_dict() for a in self.alerts.all()]
            result['actions'] = [a.to_dict() for a in self.actions.order_by(SiriusAction.order_index).all()]
            result['investigation_steps'] = [s.to_dict() for s in self.investigation_steps.order_by(SiriusInvestigationStep.timestamp).all()]

        return result


class SiriusAlert(db.Model):
    """Individual alerts that make up an incident"""
    __tablename__ = 'sirius_alerts'

    id = db.Column(db.Integer, primary_key=True)
    incident_id = db.Column(db.String(36), db.ForeignKey('sirius_incidents.id'), nullable=False)

    alertname = db.Column(db.String(255), nullable=False)
    severity = db.Column(db.String(20))
    status = db.Column(db.String(20), default='firing')  # firing, resolved

    instance = db.Column(db.String(255))
    job = db.Column(db.String(100))
    description = db.Column(db.Text)

    labels = db.Column(db.JSON)
    annotations = db.Column(db.JSON)

    starts_at = db.Column(db.DateTime)
    ends_at = db.Column(db.DateTime)
    fingerprint = db.Column(db.String(100))

    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {
            'id': self.id,
            'alertname': self.alertname,
            'severity': self.severity,
            'status': self.status,
            'instance': self.instance,
            'job': self.job,
            'description': self.description,
            'labels': self.labels or {},
            'annotations': self.annotations or {},
            'starts_at': self.starts_at.isoformat() if self.starts_at else None,
            'ends_at': self.ends_at.isoformat() if self.ends_at else None,
            'fingerprint': self.fingerprint,
        }


class SiriusAction(db.Model):
    """Remediation actions recommended by Sirius"""
    __tablename__ = 'sirius_actions'

    id = db.Column(db.Integer, primary_key=True)
    incident_id = db.Column(db.String(36), db.ForeignKey('sirius_incidents.id'), nullable=False)

    action_type = db.Column(db.String(50), nullable=False)
    description = db.Column(db.Text)
    target_host = db.Column(db.String(255))
    target_service = db.Column(db.String(100))
    command = db.Column(db.Text)

    risk_level = db.Column(db.String(20))  # low, medium, high, critical
    status = db.Column(db.String(20), default='pending')  # pending, approved, rejected, executing, executed, failed

    execution_output = db.Column(db.Text)
    executed_at = db.Column(db.DateTime)

    order_index = db.Column(db.Integer, default=0)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {
            'id': self.id,
            'action_type': self.action_type,
            'description': self.description,
            'target_host': self.target_host,
            'target_service': self.target_service,
            'command': self.command,
            'risk_level': self.risk_level,
            'status': self.status,
            'execution_output': self.execution_output,
            'executed_at': self.executed_at.isoformat() if self.executed_at else None,
            'order_index': self.order_index,
        }


class SiriusInvestigationStep(db.Model):
    """Investigation steps performed during incident analysis"""
    __tablename__ = 'sirius_investigation_steps'

    id = db.Column(db.Integer, primary_key=True)
    incident_id = db.Column(db.String(36), db.ForeignKey('sirius_incidents.id'), nullable=False)

    agent = db.Column(db.String(50))  # triage, analysis, remediation
    action = db.Column(db.String(100))
    target = db.Column(db.String(255))
    result = db.Column(db.Text)

    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {
            'id': self.id,
            'agent': self.agent,
            'action': self.action,
            'target': self.target,
            'result': self.result,
            'timestamp': self.timestamp.isoformat() if self.timestamp else None,
        }
