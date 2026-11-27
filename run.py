"""Start Netrik:  python run.py"""
import uvicorn
from app import config

if __name__ == "__main__":
    c = config.cfg()
    uvicorn.run("app.main:app", host=c["host"], port=int(c["port"]), log_level="info")
