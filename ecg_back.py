from fastapi import FastAPI, HTTPException, Depends, File, UploadFile, Query, Path
from typing import List, Dict, Optional
from pydantic import BaseModel
import jwt
import datetime
import base64

app = FastAPI()

SECRET_KEY = "your_secret_key_here"
ALGORITHM = "HS256"
BASE_URL = "https://ecg-analysis.vivalnk.com"

class AuthRequest(BaseModel):
    grant_type: str
    username: str
    password: str

class AuthResponse(BaseModel):
    token: str

@app.post("/oauth/token", response_model=AuthResponse)
def get_token(auth_request: AuthRequest, authorization: str = Depends()):
    try:
        client_id, client_secret = base64.b64decode(authorization.replace("Basic ", "")).decode("utf-8").split(":")
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid Authorization Header")
    
    if auth_request.grant_type != "password":
        raise HTTPException(status_code=400, detail="Invalid grant type")
    
    expiration = datetime.datetime.utcnow() + datetime.timedelta(hours=1)
    token = jwt.encode({"sub": auth_request.username, "exp": expiration}, SECRET_KEY, algorithm=ALGORITHM)
    return {"token": token}

class AnalysisResponse(BaseModel):
    task_id: str
    upload_url: str

@app.post("/upload", response_model=AnalysisResponse)
def upload_ecg_file(
    file: UploadFile = File(...),
    demographic: Optional[dict] = None,
    authorization: str = Depends()
):
    if not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Invalid Authorization Header")
    
    return {"message": "ECG file uploaded successfully"}

@app.get("/tasks")
def get_all_tasks(
    authorization: str = Depends(),
    limit: int = Query(10, ge=1),
    offset: int = Query(0, ge=0)
):
    if not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Invalid Authorization Header")
    
    return {"message": "Tasks retrieved successfully"}

@app.get("/tasks/{task_id}")
def retrieve_task(
    task_id: str = Path(..., description="Task ID of a certain task"),
    file_type: str = Query("xml", description="Type of the returned result: 'xml' or 'pdf'"),
    authorization: str = Depends()
):
    if not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Invalid Authorization Header")
    
    return {"message": "Task retrieved successfully"}

@app.get("/results/{result_id}")
def retrieve_result(
    result_id: str = Path(..., description="Result ID to download"),
    authorization: str = Depends()
):
    if not authorization.startswith("Bearer "):
        raise HTTPException(status_code=403, detail="Invalid Access Token")
    
    return {"message": "Result retrieved successfully"}
