import os
from datetime import date, timedelta

from fastapi import FastAPI, Request, Depends, Form, HTTPException, status
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware
from sqlalchemy.orm import Session

from app import models, auth
from app.database import get_db, engine, Base

Base.metadata.create_all(bind=engine)

app = FastAPI(title="TCM Tracker")
app.add_middleware(
    SessionMiddleware,
    secret_key=os.environ["SESSION_SECRET"],
    https_only=os.environ.get("COOKIE_SECURE", "true").lower() == "true",
    same_site="lax",
)
app.mount("/static", StaticFiles(directory="app/static"), name="static")
templates = Jinja2Templates(directory="app/templates")
