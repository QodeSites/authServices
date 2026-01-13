from db.session import get_db
from models.schemas import ResponseModel
from fastapi import APIRouter, Depends, HTTPException, status, Query, Path
from sqlalchemy.orm import Session

router = APIRouter()