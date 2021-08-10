import os
from dotenv import load_dotenv
import pymongo
from pymongo import MongoClient

load_dotenv()
MONGO_USER_PASSWORD = os.getenv('MONGO_USER_PASSWORD')

cluster = MongoClient("mongodb+srv://pranav_goel:{}@pwnybotcluster.zbo2x.mongodb.net/test".format(MONGO_USER_PASSWORD))
db = cluster["UserData"]
collection = db["UserData"]

cursor = collection.find({})
documents = []
for document in cursor:
    documents.append(document)

list_stuff = sorted(documents, key=lambda k: k['currency'])
list_stuff.reverse()
top10 = []
count = 0 
for listtt in list_stuff:
    if count == 11:
        break
    top10.append({'_id': listtt['_id'], 'currency': listtt['currency']})
    count +=1
top10.remove({'_id': <YOUR_DISCORD_ID>, 'currency': <YOUR_CURRENCY>}) # Remove Yourself from Top 10
m = "Top 10 Leaderboard for Auction Bot:\n"
position = 1
for p in top10:
    m += "{}) <@{}>: ${}\n".format(position, p["_id"], p["currency"])
    position += 1

print(m)