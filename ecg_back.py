from fastapi import FastAPI, HTTPException, Depends, File, UploadFile, Query, Path
from typing import Dict, Optional
from pydantic import BaseModel
import jwt
import datetime
import base64
import json

app = FastAPI()

SECRET_KEY = "your_secret_key_here"
ALGORITHM = "HS256"
BASE_URL = "https://ecg-analysis.vivalnk.com"

# Function to load JSON data
def load_json_file(file_path: str):
    try:
        with open(file_path, "r") as file:
            return json.load(file)
    except FileNotFoundError:
        raise HTTPException(status_code=500, detail=f"File {file_path} not found.")
    except json.JSONDecodeError:
        raise HTTPException(status_code=500, detail=f"Error decoding JSON from {file_path}.")

# Load demographic and settings JSON files
DEMOGRAPHIC_FILE = "demographic_data.json"
SETTINGS_FILE = "settings_data.json"

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
    authorization: str = Depends()
):
    """
    Upload ECG File
    - Requires Bearer token authentication
    - Reads demographic data from JSON file automatically
    """
    if not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Invalid Authorization Header")

    demographic_data = load_json_file(DEMOGRAPHIC_FILE)

    return {
        "task_id": "generated_task_id_12345",
        "upload_url": f"{BASE_URL}/upload",
        "demographic_data": demographic_data
    }

class SubmitTaskRequest(BaseModel):
    url: str  # Publicly accessible raw ECG file URL

class SubmitTaskResponse(BaseModel):
    task_id: str  # Task ID for tracking

@app.post("/submit", response_model=SubmitTaskResponse)
def submit_task(
    request: SubmitTaskRequest,
    authorization: str = Depends()
):
    """
    Submit a Task for ECG Analysis
    - Requires Bearer token authentication
    - Reads demographic and settings data from JSON files automatically
    """
    if not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Invalid Authorization Header")

    demographic_data = load_json_file(DEMOGRAPHIC_FILE)
    settings_data = load_json_file(SETTINGS_FILE)

    return {
        "task_id": "generated_task_id_12345",
        "demographic_data": demographic_data,
        "settings_data": settings_data
    }


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
