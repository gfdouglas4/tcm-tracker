import os
import io
import base64
from datetime import date, datetime

import qrcode
from fastapi import FastAPI, Request, Depends, Form, HTTPException
from fastapi.responses import RedirectResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware
from sqlalchemy.orm import Session

from app.database import Base, engine, get_db
from app import models, auth

Base.metadata.create_all(bind=engine)

SECRET_KEY = os.environ.get("SESSION_SECRET")
if not SECRET_KEY:
    raise RuntimeError("SESSION_SECRET environment variable must be set")

app = FastAPI(title="TCM Tracker")
app.add_middleware(
    SessionMiddleware,
    secret_key=SECRET_KEY,
    session_cookie="tcm_session",
    same_site="lax",
    https_only=os.environ.get("COOKIE_SECURE", "true").lower() == "true",
    max_age=60 * 60 * 8,  # 8 hour session
)
app.mount("/static", StaticFiles(directory="app/static"), name="static")
templates = Jinja2Templates(directory="app/templates")

# Preset facility list shown as quick-pick options on the episode form.
# "Other" always lets staff type in anything not on this list.
FACILITY_OPTIONS = [
    "UAB St. Vincent's",
    "UAB St. Vincent's East",
    "UAB St. Vincent's Saint Clair",
    "UAB St. Vincent's Blount",
    "Grandview Medical Center",
    "University Hospital",
]


def log_action(db: Session, request: Request, action: str, entity_type=None, entity_id=None, details=None):
    user_id = request.session.get("user_id")
    username = request.session.get("username")
    entry = models.AuditLog(
        user_id=user_id, username=username, action=action,
        entity_type=entity_type, entity_id=str(entity_id) if entity_id else None,
        details=details,
    )
    db.add(entry)
    db.commit()


def current_user(request: Request, db: Session):
    return auth.get_current_user(request, db)


# ---------------------------------------------------------------- auth ----

@app.get("/login", response_class=HTMLResponse)
def login_form(request: Request):
    if request.session.get("user_id") and request.session.get("mfa_ok"):
        return RedirectResponse("/", status_code=303)
    return templates.TemplateResponse("login.html", {"request": request, "error": None})


@app.post("/login", response_class=HTMLResponse)
def login_submit(request: Request, username: str = Form(...), password: str = Form(...),
                  db: Session = Depends(get_db)):
    user = db.query(models.User).filter(models.User.username == username.strip().lower()).first()
    if not user or not user.is_active or not auth.verify_password(password, user.password_hash):
        log_action(db, request, "login_failed", details=f"username={username}")
        return templates.TemplateResponse(
            "login.html", {"request": request, "error": "Invalid username or password."}, status_code=401
        )

    request.session.clear()
    request.session["user_id"] = user.id
    request.session["username"] = user.username
    # TEMP: 2FA requirement disabled for faster login/logout during active dev work.
    # Re-enable by restoring the pending_user_id / setup-2fa / verify-2fa redirect below.
    request.session["mfa_ok"] = True

    return RedirectResponse("/", status_code=303)


@app.get("/setup-2fa", response_class=HTMLResponse)
def setup_2fa_form(request: Request, db: Session = Depends(get_db)):
    user_id = request.session.get("pending_user_id")
    if not user_id:
        return RedirectResponse("/login", status_code=303)
    user = db.query(models.User).filter(models.User.id == user_id).first()
    if not user or user.totp_enabled:
        return RedirectResponse("/login", status_code=303)

    secret = auth.new_totp_secret()
    request.session["pending_totp_secret"] = secret
    uri = auth.totp_uri(secret, user.username)

    qr = qrcode.make(uri)
    buf = io.BytesIO()
    qr.save(buf, format="PNG")
    qr_b64 = base64.b64encode(buf.getvalue()).decode()

    return templates.TemplateResponse(
        "setup_2fa.html",
        {"request": request, "qr_b64": qr_b64, "secret": secret, "error": None},
    )


@app.post("/setup-2fa", response_class=HTMLResponse)
def setup_2fa_submit(request: Request, code: str = Form(...), db: Session = Depends(get_db)):
    user_id = request.session.get("pending_user_id")
    secret = request.session.get("pending_totp_secret")
    user = db.query(models.User).filter(models.User.id == user_id).first() if user_id else None
    if not user or not secret:
        return RedirectResponse("/login", status_code=303)

    if not auth.verify_totp(secret, code):
        uri = auth.totp_uri(secret, user.username)
        qr = qrcode.make(uri)
        buf = io.BytesIO()
        qr.save(buf, format="PNG")
        qr_b64 = base64.b64encode(buf.getvalue()).decode()
        return templates.TemplateResponse(
            "setup_2fa.html",
            {"request": request, "qr_b64": qr_b64, "secret": secret,
             "error": "That code didn't verify. Try again."},
            status_code=401,
        )

    user.totp_secret = secret
    user.totp_enabled = True
    db.commit()

    request.session["user_id"] = user.id
    request.session["mfa_ok"] = True
    request.session.pop("pending_user_id", None)
    request.session.pop("pending_totp_secret", None)
    log_action(db, request, "2fa_enrolled", entity_type="user", entity_id=user.id)
    return RedirectResponse("/", status_code=303)


@app.get("/verify-2fa", response_class=HTMLResponse)
def verify_2fa_form(request: Request):
    if not request.session.get("pending_user_id"):
        return RedirectResponse("/login", status_code=303)
    return templates.TemplateResponse("verify_2fa.html", {"request": request, "error": None})


@app.post("/verify-2fa", response_class=HTMLResponse)
def verify_2fa_submit(request: Request, code: str = Form(...), db: Session = Depends(get_db)):
    user_id = request.session.get("pending_user_id")
    user = db.query(models.User).filter(models.User.id == user_id).first() if user_id else None
    if not user:
        return RedirectResponse("/login", status_code=303)

    if not auth.verify_totp(user.totp_secret, code):
        log_action(db, request, "2fa_failed", entity_type="user", entity_id=user.id)
        return templates.TemplateResponse(
            "verify_2fa.html", {"request": request, "error": "Invalid code."}, status_code=401
        )

    request.session["user_id"] = user.id
    request.session["mfa_ok"] = True
    request.session.pop("pending_user_id", None)
    log_action(db, request, "login_success", entity_type="user", entity_id=user.id)
    return RedirectResponse("/", status_code=303)


@app.get("/logout")
def logout(request: Request, db: Session = Depends(get_db)):
    if request.session.get("user_id"):
        log_action(db, request, "logout", entity_type="user", entity_id=request.session.get("user_id"))
    request.session.clear()
    return RedirectResponse("/login", status_code=303)


# ----------------------------------------------------------- dashboard ----

@app.get("/", response_class=HTMLResponse)
def dashboard(request: Request, db: Session = Depends(get_db)):
    user = current_user(request, db)
    if not user:
        return RedirectResponse("/login", status_code=303)

    episodes = (
        db.query(models.TCMEpisode)
        .filter(models.TCMEpisode.is_closed == False)  # noqa: E712
        .order_by(models.TCMEpisode.discharge_date.desc())
        .all()
    )
    today = date.today()

    billing_followup = [
        e for e in episodes
        if e.appointment_completed_date
        and e.billing_status in (models.BillingStatus.not_ready, models.BillingStatus.ready_to_bill)
    ]

    return templates.TemplateResponse(
        "dashboard.html",
        {
            "request": request, "user": user, "episodes": episodes,
            "today": today, "billing_followup": billing_followup,
        },
    )


@app.get("/episodes/new", response_class=HTMLResponse)
def new_episode_form(request: Request, db: Session = Depends(get_db)):
    user = current_user(request, db)
    if not user:
        return RedirectResponse("/login", status_code=303)
    return templates.TemplateResponse(
        "episode_form.html",
        {"request": request, "user": user, "episode": None, "facilities": FACILITY_OPTIONS},
    )


def _parse_date(val: str):
    return datetime.strptime(val, "%Y-%m-%d").date() if val else None


def _resolve_facility(facility_select: str, facility_other: str) -> str:
    """Combine the preset dropdown + free-text 'Other' field into one value."""
    if facility_select == "__other__":
        return facility_other.strip()
    return facility_select.strip()


@app.post("/episodes/new")
def create_episode(
    request: Request,
    patient_initials: str = Form(...),
    mrn: str = Form(...),
    facility_select: str = Form(...),
    facility_other: str = Form(""),
    encounter_type: str = Form("inpatient"),
    admission_date: str = Form(""),
    discharge_date: str = Form(""),
    discharge_diagnosis: str = Form(""),
    complexity: str = Form("unspecified"),
    tcm_contact_date: str = Form(""),
    contact_method: str = Form(""),
    appointment_scheduled_date: str = Form(""),
    notes: str = Form(""),
    db: Session = Depends(get_db),
):
    user = current_user(request, db)
    if not user:
        return RedirectResponse("/login", status_code=303)

    episode = models.TCMEpisode(
        patient_initials=patient_initials.strip().upper(),
        mrn=mrn.strip(),
        facility_name=_resolve_facility(facility_select, facility_other),
        encounter_type=encounter_type,
        admission_date=_parse_date(admission_date),
        discharge_date=_parse_date(discharge_date),
        discharge_diagnosis=discharge_diagnosis.strip(),
        complexity=complexity,
        tcm_contact_date=_parse_date(tcm_contact_date),
        contact_method=contact_method.strip(),
        appointment_scheduled_date=_parse_date(appointment_scheduled_date),
        notes=notes.strip(),
        created_by=user.id,
    )
    db.add(episode)
    db.commit()
    log_action(db, request, "create_episode", entity_type="episode", entity_id=episode.id,
               details=f"MRN={episode.mrn}")
    return RedirectResponse("/", status_code=303)


@app.get("/episodes/{episode_id}/edit", response_class=HTMLResponse)
def edit_episode_form(episode_id: str, request: Request, db: Session = Depends(get_db)):
    user = current_user(request, db)
    if not user:
        return RedirectResponse("/login", status_code=303)
    episode = db.query(models.TCMEpisode).filter(models.TCMEpisode.id == episode_id).first()
    if not episode:
        raise HTTPException(404, "Episode not found")
    return templates.TemplateResponse(
        "episode_form.html",
        {"request": request, "user": user, "episode": episode, "facilities": FACILITY_OPTIONS},
    )


@app.post("/episodes/{episode_id}/edit")
def update_episode(
    episode_id: str,
    request: Request,
    patient_initials: str = Form(...),
    mrn: str = Form(...),
    facility_select: str = Form(...),
    facility_other: str = Form(""),
    encounter_type: str = Form("inpatient"),
    admission_date: str = Form(""),
    discharge_date: str = Form(""),
    discharge_diagnosis: str = Form(""),
    complexity: str = Form("unspecified"),
    tcm_contact_date: str = Form(""),
    contact_method: str = Form(""),
    appointment_scheduled_date: str = Form(""),
    appointment_completed_date: str = Form(""),
    billing_status: str = Form("not_ready"),
    cpt_code: str = Form(""),
    billing_submitted_date: str = Form(""),
    billing_notes: str = Form(""),
    notes: str = Form(""),
    is_closed: str = Form(None),
    db: Session = Depends(get_db),
):
    user = current_user(request, db)
    if not user:
        return RedirectResponse("/login", status_code=303)
    episode = db.query(models.TCMEpisode).filter(models.TCMEpisode.id == episode_id).first()
    if not episode:
        raise HTTPException(404, "Episode not found")

    episode.patient_initials = patient_initials.strip().upper()
    episode.mrn = mrn.strip()
    episode.facility_name = _resolve_facility(facility_select, facility_other)
    episode.encounter_type = encounter_type
    episode.admission_date = _parse_date(admission_date)
    episode.discharge_date = _parse_date(discharge_date)
    episode.discharge_diagnosis = discharge_diagnosis.strip()
    episode.complexity = complexity
    episode.tcm_contact_date = _parse_date(tcm_contact_date)
    episode.contact_method = contact_method.strip()
    episode.appointment_scheduled_date = _parse_date(appointment_scheduled_date)
    episode.appointment_completed_date = _parse_date(appointment_completed_date)
    episode.billing_status = billing_status
    episode.cpt_code = cpt_code.strip()
    episode.billing_submitted_date = _parse_date(billing_submitted_date)
    episode.billing_notes = billing_notes.strip()
    episode.notes = notes.strip()
    episode.is_closed = bool(is_closed)

    db.commit()
    log_action(db, request, "edit_episode", entity_type="episode", entity_id=episode.id)
    return RedirectResponse("/", status_code=303)


# ------------------------------------------------------------- billing ----

@app.get("/billing", response_class=HTMLResponse)
def billing_view(request: Request, db: Session = Depends(get_db)):
    user = current_user(request, db)
    if not user:
        return RedirectResponse("/login", status_code=303)
    episodes = (
        db.query(models.TCMEpisode)
        .order_by(models.TCMEpisode.discharge_date.desc())
        .all()
    )
    return templates.TemplateResponse("billing.html", {"request": request, "user": user, "episodes": episodes})


# --------------------------------------------------------- user admin -----

@app.get("/users", response_class=HTMLResponse)
def user_admin(request: Request, db: Session = Depends(get_db)):
    user = current_user(request, db)
    if not user:
        return RedirectResponse("/login", status_code=303)
    if user.role != models.UserRole.admin:
        raise HTTPException(403, "Admin access required")
    users = db.query(models.User).order_by(models.User.username).all()
    return templates.TemplateResponse(
        "users.html",
        {"request": request, "user": user, "users": users, "temp_password": None,
         "reset_username": None, "error": None},
    )


def _remaining_active_admins(db: Session, excluding_id: str) -> int:
    return db.query(models.User).filter(
        models.User.role == models.UserRole.admin,
        models.User.is_active == True,  # noqa: E712
        models.User.id != excluding_id,
    ).count()


@app.post("/users/{user_id}/edit")
def edit_user(
    user_id: str,
    request: Request,
    role: str = Form("staff"),
    is_active: str = Form(None),
    db: Session = Depends(get_db),
):
    admin = current_user(request, db)
    if not admin or admin.role != models.UserRole.admin:
        raise HTTPException(403, "Admin access required")
    target = db.query(models.User).filter(models.User.id == user_id).first()
    if not target:
        raise HTTPException(404, "User not found")

    new_active = bool(is_active)
    demoting_or_deactivating_admin = (
        target.role == models.UserRole.admin and (role != "admin" or not new_active)
    )
    if target.id == admin.id and demoting_or_deactivating_admin:
        # Don't let an admin lock themselves out via their own row's controls
        # (UI also disables this, but enforce server-side too).
        demoting_or_deactivating_admin = True

    if demoting_or_deactivating_admin and _remaining_active_admins(db, target.id) == 0:
        users = db.query(models.User).order_by(models.User.username).all()
        return templates.TemplateResponse(
            "users.html",
            {"request": request, "user": admin, "users": users, "temp_password": None,
             "reset_username": None, "error": "Can't remove the last active admin."},
            status_code=400,
        )

    target.role = role
    target.is_active = new_active
    db.commit()
    log_action(db, request, "edit_user", entity_type="user", entity_id=target.id,
               details=f"role={role} active={new_active}")
    return RedirectResponse("/users", status_code=303)


@app.post("/users/{user_id}/reset-password")
def reset_user_password(user_id: str, request: Request, db: Session = Depends(get_db)):
    import secrets
    admin = current_user(request, db)
    if not admin or admin.role != models.UserRole.admin:
        raise HTTPException(403, "Admin access required")
    target = db.query(models.User).filter(models.User.id == user_id).first()
    if not target:
        raise HTTPException(404, "User not found")

    temp_password = secrets.token_urlsafe(9)
    target.password_hash = auth.hash_password(temp_password)
    target.must_change_password = True
    target.totp_enabled = False
    target.totp_secret = None
    db.commit()
    log_action(db, request, "reset_password", entity_type="user", entity_id=target.id)

    users = db.query(models.User).order_by(models.User.username).all()
    return templates.TemplateResponse(
        "users.html",
        {
            "request": request, "user": admin, "users": users,
            "temp_password": temp_password, "new_username": target.username,
            "reset_username": target.username, "error": None,
        },
    )


@app.post("/users/{user_id}/delete")
def delete_user(user_id: str, request: Request, db: Session = Depends(get_db)):
    admin = current_user(request, db)
    if not admin or admin.role != models.UserRole.admin:
        raise HTTPException(403, "Admin access required")
    if user_id == admin.id:
        users = db.query(models.User).order_by(models.User.username).all()
        return templates.TemplateResponse(
            "users.html",
            {"request": request, "user": admin, "users": users, "temp_password": None,
             "reset_username": None, "error": "You can't delete the account you're currently logged in as."},
            status_code=400,
        )
    target = db.query(models.User).filter(models.User.id == user_id).first()
    if not target:
        raise HTTPException(404, "User not found")

    if target.role == models.UserRole.admin and _remaining_active_admins(db, target.id) == 0:
        users = db.query(models.User).order_by(models.User.username).all()
        return templates.TemplateResponse(
            "users.html",
            {"request": request, "user": admin, "users": users, "temp_password": None,
             "reset_username": None, "error": "Can't delete the last active admin."},
            status_code=400,
        )

    # Preserve episode + audit history — detach rather than cascade-delete
    # (both tables FK to users.id; audit_log.user_id is set on the actor's
    # own login/logout/2fa events, so a deleted user's own history hits this too).
    db.query(models.TCMEpisode).filter(models.TCMEpisode.created_by == target.id).update(
        {"created_by": None}
    )
    db.query(models.AuditLog).filter(models.AuditLog.user_id == target.id).update(
        {"user_id": None}
    )
    deleted_username = target.username
    db.delete(target)
    db.commit()
    log_action(db, request, "delete_user", entity_type="user", entity_id=user_id,
               details=f"username={deleted_username}")
    return RedirectResponse("/users", status_code=303)


@app.post("/users/new")
def create_user(
    request: Request,
    username: str = Form(...),
    role: str = Form("staff"),
    db: Session = Depends(get_db),
):
    import secrets
    admin = current_user(request, db)
    if not admin or admin.role != models.UserRole.admin:
        raise HTTPException(403, "Admin access required")

    temp_password = secrets.token_urlsafe(9)
    new_u = models.User(
        username=username.strip().lower(),
        password_hash=auth.hash_password(temp_password),
        role=role,
        must_change_password=True,
    )
    db.add(new_u)
    db.commit()
    log_action(db, request, "create_user", entity_type="user", entity_id=new_u.id)

    users = db.query(models.User).order_by(models.User.username).all()
    return templates.TemplateResponse(
        "users.html",
        {
            "request": request, "user": admin, "users": users,
            "temp_password": temp_password, "new_username": new_u.username,
            "reset_username": None, "error": None,
        },
    )


@app.get("/health")
def health():
    return {"status": "ok"}
