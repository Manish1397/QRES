
from app.utils import db as db_module
from bson import ObjectId

def add_file(owner,name,path):
    db_module.db.files.insert_one({
        "owner":owner,
        "filename":name,
        "path":path
    })

def get_user_files(user):
    return list(db_module.db.files.find({"owner":user}))

def get_file(file_id):
    return db_module.db.files.find_one({"_id":ObjectId(file_id)})

def delete_file(file_id):
    db_module.db.files.delete_one({"_id":ObjectId(file_id)})
