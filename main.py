from fastapi import FastAPI, APIRouter, HTTPException, Request, Depends
from fastapi.responses import JSONResponse
from dotenv import load_dotenv
import uvicorn
import os
import logging
from realsense_worker import RealsenseWorker, RealsenseBusyError
from contextlib import asynccontextmanager
import paho.mqtt.client as mqtt
from urllib.parse import urlparse
from uuid import UUID
import base64

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[logging.StreamHandler()],
)

logger = logging.getLogger("app")

load_dotenv()

REALSENSE_PORT = os.getenv("REALSENSE_PORT")

if REALSENSE_PORT is None:
    raise ValueError("No REALSENSE_PORT is provided")

LISTEN_PORT = os.getenv("LISTEN_PORT", 8080)
API_KEY = os.getenv("API_KEY")
MQTT_URI = os.getenv("MQTT_URI")
MQTT_CA_PATH = os.getenv("MQTT_CA_PATH")
MQTT_TOPIC = os.getenv("MQTT_TOPIC")

if MQTT_URI is None:
    raise ValueError("No MQTT_URI is provided")

if MQTT_TOPIC is None:
    raise ValueError("No MQTT_URI is provided")

REALSENSE_HOST_PRIVATE_KEY_PATH = os.getenv("REALSENSE_HOST_PRIVATE_KEY_PATH")
REALSENSE_DEVICE_PUBLIC_KEY_PATH = os.getenv("REALSENSE_DEVICE_PUBLIC_KEY_PATH")

if REALSENSE_HOST_PRIVATE_KEY_PATH is None:
    raise ValueError("No REALSENSE_HOST_PRIVATE_KEY_PATH is provided")

if REALSENSE_DEVICE_PUBLIC_KEY_PATH is None:
    raise ValueError("No REALSENSE_DEVICE_PUBLIC_KEY_PATH is provided")


def mqtt_on_connect(client, userdata, flags, reason_code, properties):
    logger.info(f"Connected to MQTT. Result code: {reason_code}")


def mqtt_on_connect_fail(client, error):
    logger.error(f"Failed to connect to MQTT. Error: {error}")

def convert_uuid_to_b64(uuid: UUID) -> str:
    return base64.urlsafe_b64encode(uuid.bytes).decode('ascii')

def convert_b64_to_uuid(data: str) -> UUID:
    return UUID(bytes=base64.urlsafe_b64decode(data))

@asynccontextmanager
async def lifespan(app: FastAPI):
    mqttc = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2)
    mqttc.on_connect = mqtt_on_connect
    mqttc.on_connect_fail = mqtt_on_connect_fail

    mqtt_url = urlparse(MQTT_URI)

    if mqtt_url.username or mqtt_url.password:
        mqttc.username_pw_set(mqtt_url.username, mqtt_url.password)
    if MQTT_CA_PATH:
        mqttc.tls_set(MQTT_CA_PATH)
    mqttc.connect(mqtt_url.hostname, mqtt_url.port)

    mqttc.loop_start()

    def auth_handler(user_id: str) -> None:
        mqttc.publish(MQTT_TOPIC, str(convert_b64_to_uuid(user_id)))

    realsense = RealsenseWorker(
        REALSENSE_PORT,
        REALSENSE_HOST_PRIVATE_KEY_PATH,
        REALSENSE_DEVICE_PUBLIC_KEY_PATH,
        auth_handler,
    )
    realsense.start()
    app.state.realsense = realsense
    yield
    realsense.stop()
    mqttc.loop_stop()
    mqttc.disconnect()


app = FastAPI(lifespan=lifespan)


@app.middleware("http")
async def add_process_time_header(request: Request, call_next):
    if API_KEY is not None:
        if (
            not "authorization" in request.headers
            or request.headers["authorization"] != f"Bearer {API_KEY}"
        ):
            return JSONResponse(status_code=401, content={"detail": "Unauthorized"})
    return await call_next(request)


api_router = APIRouter(prefix="/api")


def get_realsense(request: Request) -> RealsenseWorker:
    return request.app.state.realsense


@api_router.get("/users/{id}")
def user_status(id: UUID, realsense: RealsenseWorker = Depends(get_realsense)):
    return {"is_enrolled": realsense.is_enrolled(convert_uuid_to_b64(id))}


@api_router.delete("/users/{id}")
def user_remove(id: UUID, realsense: RealsenseWorker = Depends(get_realsense)):
    try:
        realsense.remove(convert_uuid_to_b64(id))
    except RealsenseBusyError:
        raise HTTPException(400, detail="RealSense is busy")
    return {}


@api_router.post("/users/{id}")
def user_enroll(id: UUID, realsense: RealsenseWorker = Depends(get_realsense)):
    try:
        success, status = realsense.enroll(convert_uuid_to_b64(id))
        return {"success": success, "status": status}
    except RealsenseBusyError:
        raise HTTPException(400, detail="RealSense is busy")


@api_router.get("/users")
def users_list(realsense: RealsenseWorker = Depends(get_realsense)):
    return map(convert_b64_to_uuid, realsense.get_users())


app.include_router(api_router)

if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=LISTEN_PORT, log_config=None)
