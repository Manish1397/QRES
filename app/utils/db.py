from pymongo import MongoClient
from app.utils.rbac import normalize_roles

db = None


def init_db():
    global db
    client = MongoClient("mongodb://localhost:27017")
    db = client["amqres_deploy"]
    migrate_users()



def migrate_users():
    if db is None:
        return

    for user in db.users.find():
        roles = normalize_roles(user)
        updates = {
            "roles": roles,
            "role": roles[-1],
        }
        if "status" not in user:
            updates["status"] = "active"
        db.users.update_one({"_id": user["_id"]}, {"$set": updates})
