
import os, datetime

LOG_DIR="logs"
os.makedirs(LOG_DIR,exist_ok=True)

def log_event(msg):
    with open(os.path.join(LOG_DIR,"activity.log"),"a") as f:
        f.write(f"{datetime.datetime.now()} : {msg}\n")
