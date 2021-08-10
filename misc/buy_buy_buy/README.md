# auction-bot

# Setup and Run Steps
1) Make sure you have your MongoDB account and stuff setup.
2) Create a table for marketplace, public auction, private auction, and user data.
3) You need to create the Marketplace and Public Auction documents manually (use the jsons included to quickly add stuff) The formats are in `auction.py`. I'll probably also put a copy here at the bottom.
4) Set all the environment variables needed in `auction.py`.
5) `pip install -r requirements`
6) `./auction.py`

# Dockerfile
- I have a dockerfile but I haven't really tested it. 
- It probably works.
- You can figure it out. 
- I just started a TMUX session in a server so it keeps running

# Database basic format examples
## User
```json
{"_id": <discord_id>},"currency":10000,"items":{"set":["Samurai Set","Megazord","Megazord"],"collectable":["Terracotta Warrior","Terracotta Warrior","Terracotta Warrior","Terracotta Warrior","Terracotta Warrior","Terracotta Warrior","Terracotta Warrior"],"single":[],"part":[]},"private_auction_room":"A5YULNJV","personal_auction_room":"LZ2TC2W3"}
```
## Public Auction Room
```json
{"_id":{"$oid":"6103c5765103f5fe5ea02738"},"items":["1964 Ferrari 250 LM","Golden Fleece","Rare Yugioh Card","Grand Piano","Ancient Gold Medallion","Totally Normal Knife","Venus of Willendorf","Knight Set","Megazord","Shiny Pokemon Card","Flag Ultra Rare"],"bids":[],"start_pov":0.38,"accepting_bids":true}
```
## Private Auction Room
```json
{"_id":{"$oid":"6103d75bfeaa4aba3c12ede1"},"_room":"LZ2TC2W3","owner":{"$numberLong":"294098277702303745"},"members":["191656769267695617",{"$numberLong":"114094000100737024"},{"$numberLong":"717861866105470987"},{"$numberLong":"404920284060057611"}],"items":{"set":[],"collectable":[],"single":[],"part":[]},"current_auction_item":"","bids":[],"in_session":true,"start_pov":20000}
```
## Market Place
### Set
```json
"_id": { "item": "Samurai Set", "type": "set", "price": 130000, "parts": [{ "helmet": 10000 }, { "body armor": 30000 }, { "boots": 5000 }, { "katana": 40000 }] }
```
### Collectable
```json
"_id": { "item": "Terracotta Warrior", "type": "collectable", "price": 10000, "multiplier": 1.5 }
```
### Single
```json
"_id": { "item": "Ancient Gold Medallion", "type": "single", "price": 20000 }
```

# Functions Todo:
- [x] ping - verified
- [x] initiate - verified
- [x] join - verified
- [x] bid - verified
- [x] private_bid - verified
- [x] create - verified
- [x] sell - verified
- [x] buy - verified
- [x] assemble - verified
- [x] marketplace - verified
- [x] how_it_works - verified
- [x] leave_room - verified
- [x] auction_item - verified
- [x] run_private_auction - verified
- [x] stop_private_bidding - verified
- [x] auction_item - verified
- [x] end_private_auction - verified
- [x] run_public_auction - verified
- [x] public_auction_items - verified
- [x] flag - verified
- [x] balance - verified
- [x] inventory - verified
- [x] redeem_flags - verified
