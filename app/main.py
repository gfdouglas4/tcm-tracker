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
    request.session["pending_user_id"] = user.id
    request.session["username"] = user.username

    if not user.totp_enabled:
        # First login: force 2FA enrollment before any access is granted.
        return RedirectResponse("/setup-2fa", status_code=303)

    return RedirectResponse("/verify-2fa", status_code=303)


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
        "episode_form.html", {"request": request, "user": user, "episode": None}
    )


def _parse_date(val: str):
    return datetime.strptime(val, "%Y-%m-%d").date() if val else None


@app.post("/episodes/new")
def create_episode(
    request: Request,
    patient_initials: str = Form(...),
    mrn: str = Form(...),
    facility_name: str = Form(...),
    encounter_type: str = Form("inpatient"),
    admission_date: str = Form(""),
    discharge_date: str = Form(...),
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
        facility_name=facility_name.strip(),
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
        "episode_form.html", {"request": request, "user": user, "episode": episode}
    )


@app.post("/episodes/{episode_id}/edit")
def update_episode(
    episode_id: str,
    request: Request,
    patient_initials: str = Form(...),
    mrn: str = Form(...),
    facility_name: str = Form(...),
    encounter_type: str = Form("inpatient"),
    admission_date: str = Form(""),
    discharge_date: str = Form(...),
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
    episode.facility_name = facility_name.strip()
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
        "users.html", {"request": request, "user": user, "users": users, "temp_password": None}
    )


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
        },
    )


@app.get("/health")
def health():
    return {"status": "ok"}
