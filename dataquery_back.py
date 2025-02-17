import requests
from fastapi import FastAPI, HTTPException, Depends, Query, Header
from fastapi import FastAPI, HTTPException, Header, Path, Body, Query
from pydantic import BaseModel, Field
from fastapi.security import OAuth2PasswordBearer
from pydantic import BaseModel
import httpx
import os
from typing import Optional

app = FastAPI()

# OAuth2 Authentication
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="auth")

# VivaLNK API Base URL
VIVALINK_BASE_URL = "https://site2-vcloud.vivalink.com"

# Request Body Model
class TokenRequest(BaseModel):
    id: str  # Tenant ID
    key: str  # Tenant Key

# 📌 **🔹 Endpoint: Get Access Token (`POST /auth`)**
@app.post("/auth")
async def login_for_access_token(request: TokenRequest):
    """
    Authenticate with VivaLNK API to get an access token.
    """
    payload = {
        "id": request.id,
        "key": request.key
    }

    headers = {"Content-Type": "application/json"}

    # Send authentication request to VivaLNK API
    response = requests.post(f"{VIVALINK_BASE_URL}/auth", json=payload, headers=headers)

    if response.status_code == 200:
        return response.json()  # Return access token, token type, refresh token
    else:
        raise HTTPException(status_code=response.status_code, detail=response.json())


# Dependency to get current tenant from JWT token
async def get_current_tenant(token: str = Depends(oauth2_scheme)):
    headers = {"Authorization": token}
    # Make a request to VivaLNK API to validate the token
    response = requests.get(f"{VIVALINK_BASE_URL}/validate_token", headers=headers)

    if response.status_code == 200:
        return response.json().get("tenantId")  # Extract tenant ID from token
    else:
        raise HTTPException(status_code=401, detail="Bla Bla Invalid authentication credentials")

@app.get("/tenants/{tenantId}")
async def get_tenant_info(
    tenantId: str,
    authorization: str = Header(..., description="JWT token for authentication"),
    content_type: str = Header(..., description="Must be application/json"),
    accept_encoding: str = Header(None, description="Optional: gzip, deflate, identity"),
    startTime: int = Query(None, description="Query start time, Unix timestamp in milliseconds. Null means infinitesimal."),
    endTime: int = Query(None, description="Query end time, Unix timestamp in milliseconds. Null means infinity."),
):
    # Validate Content-Type
    if content_type.lower() != "application/json":
        raise HTTPException(status_code=400, detail="Invalid Content-Type. Must be application/json.")

    print("Printing token", authorization)
    # Forward request to VivaLNK API
    headers = {
        "Authorization": authorization,  # Forward token
    }

    params = {
        "startTime": startTime,
        "endTime": endTime
    }

    response = requests.get(f"{VIVALINK_BASE_URL}/tenants/{tenantId}", headers=headers, params=params)

    if response.status_code == 200:
        data = response.json()
        print(f"✅ Retrieved Mappings for Tenant {tenantId}:", data)
        return {
            "message": f"Tenant {tenantId} data retrieved successfully",
            "data": data
        }
    elif response.status_code == 404:
        raise HTTPException(status_code=404, detail="Tenant data not found")
    else:
        raise HTTPException(status_code=response.status_code, detail=response.json())
    
    
@app.get("/tenants/{tenantId}/sensor/activity")
async def get_tenant_sensor_activity(
    tenantId: str,
    offsetTime: int = Query(..., description="Time period from present to past in which sensors are considered active (in seconds)."),
    authorization: str = Header(..., description="JWT token for authentication"),
):

    # Validate offsetTime (should be positive)
    if offsetTime <= 0:
        raise HTTPException(status_code=400, detail="offsetTime must be a positive integer.")
    
    print("Printing token", authorization)
    
    # Prepare headers and parameters
    headers = {
        "Authorization": authorization,  # Forward token
        "Content-Type": "application/json"
    }
    
    params = {
        "offsetTime": offsetTime
    }
    
    # Forward request to VivaLNK API
    response = requests.get(f"{VIVALINK_BASE_URL}/tenants/{tenantId}/sensor/activity", headers=headers, params=params)
    
    if response.status_code == 200:
        data = response.json()
        print(f"✅ Retrieved Sensor Activity for Tenant {tenantId}:", data)
        return {
            "message": f"Tenant {tenantId} sensor activity retrieved successfully",
            "data": data
        }
    elif response.status_code == 404:
        raise HTTPException(status_code=404, detail="Sensor activity data not found")
    else:
        raise HTTPException(status_code=response.status_code, detail=response.json())


class ExportDataRequest(BaseModel):
    startTime: int = Field(..., description="Query start time, Unix timestamp in milliseconds")
    endTime: int = Field(..., description="Query end time, Unix timestamp in milliseconds")
    sensorId: str = Field(..., description="A unique identifier for VivaLNK sensor devices")
    format: str = Field(..., description="Format type: Ishne or Json")
    timezone: str | None = Field(None, description="ISHNE file timezone, e.g., GMT+8:00")
    denoise: bool | None = Field(None, description="ECG only, indicates whether the returned ECG is raw or de-noised")
    subjectId: str | None = Field(None, description="Included in ISHNE file output")
    subjectName: str | None = Field(None, description="Included in ISHNE file output")
    projectId: str | None = Field(None, description="Included in ISHNE file output")
    deviceId: str | None = Field(None, description="Included in ISHNE file output")

@app.post("/tenants/{tenantId}/data/export")
async def export_sensor_data(
    tenantId: str = Path(..., description="The ID of the target tenant"),
    authorization: str = Header(..., description="JWT token for authentication"),
    request: ExportDataRequest = Body(...)
):
    # Validate time range (max 7 days)
    if (request.endTime - request.startTime) > 7 * 24 * 3600 * 1000:
        raise HTTPException(status_code=400, detail="Time range must be 7 days or less.")

    headers = {
        "Authorization": authorization,
        "Content-Type": "application/json"
    }

    async with httpx.AsyncClient() as client:
        try:
            response = await client.post(
                f"{VIVALINK_BASE_URL}/tenants/{tenantId}/data/export",
                headers=headers,
                json=request.dict()
            )

            if response.status_code == 200:
                return response.json()
            elif response.status_code == 401:
                raise HTTPException(status_code=401, detail="Unauthorized request. Check your token.")
            elif response.status_code == 403:
                raise HTTPException(status_code=403, detail="Permission denied.")
            elif response.status_code == 10000:
                raise HTTPException(status_code=400, detail="Invalid time range.")
            else:
                raise HTTPException(status_code=response.status_code, detail=response.json())

        except httpx.RequestError as e:
            raise HTTPException(status_code=500, detail=f"External API request failed: {str(e)}")





@app.get("/tenants/{tenantId}/userEvents")
async def get_user_events(
    tenantId: str = Path(..., description="The ID of the target tenant"),
    authorization: str = Header(..., description="JWT token for authentication"),
    subjectId: Optional[str] = Query(None, description="Required if 'sensorId' is not provided"),
    sensorId: Optional[str] = Query(None, description="Required if 'subjectId' is not provided"),
    startTime: Optional[int] = Query(None, description="Query start time (Unix timestamp in milliseconds)"),
    endTime: Optional[int] = Query(None, description="Query end time (Unix timestamp in milliseconds)")
):
    # Ensure either subjectId or sensorId is provided
    if not subjectId and not sensorId:
        raise HTTPException(status_code=400, detail="Either 'subjectId' or 'sensorId' must be provided.")

    # Validate time range (cannot exceed 30 days)
    if startTime and endTime:
        max_range = 30 * 24 * 3600 * 1000  # 30 days in milliseconds
        if (endTime - startTime) > max_range:
            raise HTTPException(status_code=400, detail="Time range cannot exceed 30 days.")

    # Prepare headers and query parameters
    headers = {
        "Authorization": authorization,
        "Content-Type": "application/json"
    }
    
    params = {
        "subjectId": subjectId,
        "sensorId": sensorId,
        "startTime": startTime,
        "endTime": endTime
    }
    
    # Remove None values from params
    params = {key: value for key, value in params.items() if value is not None}

    async with httpx.AsyncClient() as client:
        try:
            response = await client.get(f"{VIVALINK_BASE_URL}/tenants/{tenantId}/userEvents", headers=headers, params=params)

            if response.status_code == 200:
                return response.json()
            elif response.status_code == 401:
                raise HTTPException(status_code=401, detail="Unauthorized request. Check your token.")
            elif response.status_code == 403:
                raise HTTPException(status_code=403, detail="Permission denied.")
            elif response.status_code == 40000:
                raise HTTPException(status_code=400, detail="Invalid time range.")
            else:
                raise HTTPException(status_code=response.status_code, detail=response.json())

        except httpx.RequestError as e:
            raise HTTPException(status_code=500, detail=f"External API request failed: {str(e)}")



@app.get("/tenants/{tenantId}/data")
async def get_sensor_data(
    tenantId: str = Path(..., description="The ID of the target tenant"),
    authorization: str = Header(..., description="JWT token for authentication"),
    appId: Optional[str] = Query(None, description="A unique identifier for an application uploading data to cloud"),
    subjectId: Optional[str] = Query(None, description="A unique identifier for a subject"),
    type: Optional[str] = Query(None, description="Required if subjectId is presented. Options: EcgRaw, SpO2Raw, BPRaw, TemperatureRaw, GlucoseRaw, ActivityDaily"),
    patchSn: Optional[str] = Query(None, description="A unique identifier for sensor devices"),
    topOne: Optional[bool] = Query(False, description="Indicates whether only the top (oldest or latest) data is returned"),
    denoise: Optional[bool] = Query(False, description="Indicates whether returned ECG data is raw or de-noised"),
    hrOnly: Optional[bool] = Query(False, description="Indicates whether only HR is returned"),
    startTime: Optional[int] = Query(None, description="Query start time (Unix timestamp in milliseconds)"),
    endTime: Optional[int] = Query(None, description="Query end time (Unix timestamp in milliseconds)"),
    order: Optional[str] = Query("ascending", description="Order of returned data by recordTime (ascending/descending)"),
    version: Optional[str] = Query("v1", description="Version of response body (v1, v2, v3, v4)")
):
    # Ensure required parameters are set correctly
    if not patchSn and not subjectId:
        raise HTTPException(status_code=400, detail="Either 'patchSn' or 'subjectId' must be provided.")
    
    if subjectId and not type:
        raise HTTPException(status_code=400, detail="If 'subjectId' is provided, 'type' is required.")

    # Prepare headers and query parameters
    headers = {
        "Authorization": authorization,
        "Content-Type": "application/json"
    }
    
    params = {
        "appId": appId,
        "subjectId": subjectId,
        "type": type,
        "patchSn": patchSn,
        "topOne": topOne,
        "denoise": denoise,
        "hrOnly": hrOnly,
        "startTime": startTime,
        "endTime": endTime,
        "order": order,
        "version": version
    }

    # Remove None values to ensure clean API request
    params = {key: value for key, value in params.items() if value is not None}

    async with httpx.AsyncClient() as client:
        try:
            response = await client.get(f"{VIVALINK_BASE_URL}/tenants/{tenantId}/data", headers=headers, params=params)

            if response.status_code == 200:
                return response.json()
            elif response.status_code == 401:
                raise HTTPException(status_code=401, detail="Unauthorized request. Check your token.")
            elif response.status_code == 403:
                raise HTTPException(status_code=403, detail="Permission denied.")
            elif response.status_code == 40000:
                raise HTTPException(status_code=400, detail="Invalid request parameters.")
            else:
                raise HTTPException(status_code=response.status_code, detail=response.json())

        except httpx.RequestError as e:
            raise HTTPException(status_code=500, detail=f"External API request failed: {str(e)}")
