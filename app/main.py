from fastapi import FastAPI
from contextlib import asynccontextmanager
from app.database import connect_to_mongo, close_mongo_connection
from app.routes import auth, protected

@asynccontextmanager
async def lifespan(app: FastAPI):
    await connect_to_mongo()
    yield
    await close_mongo_connection()

app = FastAPI(title="Per-Request Asymmetric Auth API", lifespan=lifespan)

app.include_router(auth.router)
app.include_router(protected.router)

@app.get("/")
def root():
    return {"status": "ok", "auth_type": "per-request-signature"}