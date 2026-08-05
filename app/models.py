import enum
import uuid
from datetime import datetime, date

from sqlalchemy import (
    Column, String, Boolean, Date, DateTime, Text, ForeignKey, Enum
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship

from app.database import Base


def gen_uuid():
    return str(uuid.uuid4())


class UserRole(str, enum.Enum):
    admin = "admin"
    staff = "staff"


class ComplexityLevel(str, enum.Enum):
    moderate = "moderate"   # CPT 99495 — face-to-face visit due within 14 days
    high = "high"            # CPT 99496 — face-to-face visit due within 7 days
    unspecified = "unspecified"


class BillingStatus(str, enum.Enum):
    not_ready = "not_ready"       # visit hasn't happened yet
    ready_to_bill = "ready_to_bill"  # visit done, not yet submitted
    submitted = "submitted"
    paid = "paid"
    denied = "denied"


class User(Base):
    __tablename__ = "users"

    id = Column(UUID(as_uuid=False), primary_key=True, default=gen_uuid)
    username = Column(String(64), unique=True, nullable=False, index=True)
    password_hash = Column(String(255), nullable=False)
    role = Column(Enum(UserRole), default=UserRole.staff, nullable=False)
    totp_secret = Column(String(64), nullable=True)
    totp_enabled = Column(Boolean, default=False, nullable=False)
    is_active = Column(Boolean, default=True, nullable=False)
    must_change_password = Column(Boolean, default=True, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)

    episodes = relationship("TCMEpisode", back_populates="created_by_user")


class TCMEpisode(Base):
    """One hospital/ED discharge transition-of-care episode for a patient."""
    __tablename__ = "tcm_episodes"

    id = Column(UUID(as_uuid=False), primary_key=True, default=gen_uuid)

    # De-identified patient reference — initials + MRN only, per practice policy.
    patient_initials = Column(String(8), nullable=False)
    mrn = Column(String(32), nullable=False, index=True)

    facility_name = Column(String(255), nullable=False)
    encounter_type = Column(String(32), default="inpatient")  # inpatient | ed | snf

    admission_date = Column(Date, nullable=True)
    discharge_date = Column(Date, nullable=True)  # null while patient is still admitted
    discharge_diagnosis = Column(Text, nullable=True)

    complexity = Column(Enum(ComplexityLevel), default=ComplexityLevel.unspecified)

    tcm_contact_date = Column(Date, nullable=True)   # TCM order / interactive contact initiated
    contact_method = Column(String(64), nullable=True)  # phone, portal, etc.

    appointment_scheduled_date = Column(Date, nullable=True)
    appointment_completed_date = Column(Date, nullable=True)

    billing_status = Column(Enum(BillingStatus), default=BillingStatus.not_ready)
    cpt_code = Column(String(8), nullable=True)  # 99495 or 99496
    billing_submitted_date = Column(Date, nullable=True)
    billing_notes = Column(Text, nullable=True)

    notes = Column(Text, nullable=True)
    is_closed = Column(Boolean, default=False, nullable=False)  # episode fully wrapped up

    created_by = Column(UUID(as_uuid=False), ForeignKey("users.id"), nullable=True)
    created_by_user = relationship("User", back_populates="episodes")
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # --- derived helpers used by the dashboard/templates ---
    @property
    def contact_deadline(self):
        """2 business-day contact requirement from discharge."""
        if not self.discharge_date:
            return None
        d = self.discharge_date
        days_added = 0
        cursor = d
        while days_added < 2:
            cursor = date.fromordinal(cursor.toordinal() + 1)
            if cursor.weekday() < 5:  # Mon-Fri
                days_added += 1
        return cursor

    @property
    def visit_deadline(self):
        if not self.discharge_date:
            return None
        window = 7 if self.complexity == ComplexityLevel.high else 14
        return date.fromordinal(self.discharge_date.toordinal() + window)

    @property
    def suggested_cpt(self):
        if self.complexity == ComplexityLevel.high:
            return "99496"
        if self.complexity == ComplexityLevel.moderate:
            return "99495"
        return None

    @property
    def status_label(self):
        """Human-readable status shown on the dashboard."""
        if not self.discharge_date:
            return "In patient" if self.admission_date else "Pending admission info"
        if self.appointment_completed_date:
            return "Visit completed"
        return "Discharged — TCM in progress"


class AuditLog(Base):
    __tablename__ = "audit_log"

    id = Column(UUID(as_uuid=False), primary_key=True, default=gen_uuid)
    user_id = Column(UUID(as_uuid=False), ForeignKey("users.id"), nullable=True)
    username = Column(String(64), nullable=True)
    action = Column(String(64), nullable=False)   # login, create_episode, edit_episode, etc.
    entity_type = Column(String(64), nullable=True)
    entity_id = Column(String(64), nullable=True)
    details = Column(Text, nullable=True)
    timestamp = Column(DateTime, default=datetime.utcnow)
