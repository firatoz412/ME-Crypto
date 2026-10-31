import mysql.connector as msqlc
import os
from dotenv import load_dotenv

load_dotenv()

def getDatabase():
    print("DB_USER:", os.getenv("DB_USER"), "| DB_HOST:", os.getenv("DB_HOST"))
    return msqlc.connect(
        host=os.getenv("DB_HOST"),
        user=os.getenv("DB_USER"),
        password=os.getenv("DB_PASSWORD"),
        database=os.getenv("DB_NAME")
    )