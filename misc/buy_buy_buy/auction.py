#!/usr/bin/env python

# bot.py
import os
from re import split
from typing import List

import discord
from discord import Embed
from discord import Colour
from discord.ext import commands
from discord.ext import tasks
from dotenv import load_dotenv
from discord_slash import SlashCommand # Importing the newly installed library.
from discord_slash.utils.manage_commands import create_option, create_choice
from discord_slash.model import SlashCommandOptionType
import pymongo
from pymongo import MongoClient
import random
import string

load_dotenv()
TOKEN = os.getenv('DISCORD_TOKEN')
MONGO_USER_PASSWORD = os.getenv('MONGO_USER_PASSWORD')
MONGO_USERNAME = os.getenv('MONGO_USERNAME')
MONGO_SERVER = os.getenv('MONGO_SERVER')
BOT_CHANNEL = 865054781495312405 # Put whatever channel ID you want

# Connect to database
cluster = MongoClient("mongodb+srv://{}:{}@{}".format(MONGO_USERNAME, MONGO_USER_PASSWORD, MONGO_SERVER))

# Connect to all the tables in the MongoDB Database
db = cluster["UserData"]
collection = db["UserData"]

db = cluster["PrivateAuction"]
private_auction = db["PrivateAuction"]

db = cluster["PublicAuction"]
public_auction = db["PublicAuction"]

db = cluster["MarketPlace"]
market_place = db["MarketPlace"]

bot = commands.Bot(command_prefix='!', intents=discord.Intents.all()) # not really necessary but I put it just in case I'd want to have some of these.
slash = SlashCommand(bot, sync_commands=True) # Declares slash commands through the client.

# Database basic format examples:
# User: 
    # {"_id": <discord id>},"currency":10000,"items":{"set":["Samurai Set","Megazord","Megazord"],"collectable":["Terracotta Warrior","Terracotta Warrior","Terracotta Warrior","Terracotta Warrior","Terracotta Warrior","Terracotta Warrior","Terracotta Warrior"],"single":[],"part":[]},"private_auction_room":"A5YULNJV","personal_auction_room":"LZ2TC2W3"}
# Public Auction Room: 
    # {"_id":{"$oid":"6103c5765103f5fe5ea02738"},"items":["1964 Ferrari 250 LM","Golden Fleece","Rare Yugioh Card","Grand Piano","Ancient Gold Medallion","Totally Normal Knife","Venus of Willendorf","Knight Set","Megazord","Shiny Pokemon Card","Flag Ultra Rare"],"bids":[],"start_pov":0.38,"accepting_bids":true}
# Private Auction Room: 
    # {"_id":{"$oid":"6103d75bfeaa4aba3c12ede1"},"_room":"LZ2TC2W3","owner":{"$numberLong":"294098277702303745"},"members":["191656769267695617",{"$numberLong":"114094000100737024"},{"$numberLong":"717861866105470987"},{"$numberLong":"404920284060057611"}],"items":{"set":[],"collectable":[],"single":[],"part":[]},"current_auction_item":"","bids":[],"in_session":true,"start_pov":20000}
# Market Place: 
    # "_id": { "item": "Samurai Set", "type": "set", "price": 130000, "parts": [{ "helmet": 10000 }, { "body armor": 30000 }, { "boots": 5000 }, { "katana": 40000 }] },
    # "_id": { "item": "Terracotta Warrior", "type": "collectable", "price": 10000, "multiplier": 1.5 },
    # "_id": { "item": "Ancient Gold Medallion", "type": "single", "price": 20000 },
    # "_id": { "item": "Ancient Silver Medallion", "type": "single", "price": 10000 },
    # "_id": { "item": "Ancient Bronze Medallion", "type": "single", "price": 20000 }


# Before you look past this point I want to apologize for all this gobbledygook I am calling code.

@bot.event
async def on_ready():
    print("Ready!")

guild_ids = [] # Put your server ID in this array.

# Check Ping!
@slash.slash(name="ping", guild_ids=guild_ids)
async def _ping(ctx): # Defines a new "context" (ctx) command called "ping."
    await ctx.send(f"Pong! ({bot.latency*1000}ms)")

# Add user to database
@slash.slash(name="initiate", description="Become a member of the auction house!", guild_ids=guild_ids)
async def _initiate(ctx):
    myquery = { "_id": ctx.author.id }
    if collection.count_documents(myquery) == 0:
        post = {"_id": ctx.author.id, "currency": 10000, "items":{"set": [], "collectable": [], "single": [], "part": []}, "private_auction_room":"", "personal_auction_room": ""}
        collection.insert_one(post)
        await ctx.send(content="<@{}> Congrats, you have been initiated into the auction house!".format(ctx.author.id))
    else:
        await ctx.send(content="<@{}> You have already been initiated! Try /help for more information".format(ctx.author.id))

# Place a bid on public auction item
@slash.slash(name="bid", description="Bid for item currently being auctioned in the public auction", guild_ids=guild_ids,
                options=[
                create_option(
                    name="bid_amount",
                    description="Bid the amount you are willing to spend on the current item being auctioned",
                    option_type=4,
                    required=True
                ),
                create_option(
                    name="item",
                    description="What item are you bidding on?",
                    option_type=3,
                    required=True
                )
            ])
async def _bid(ctx, bid_amount: int, item: str):
    myquery = { "_id": ctx.author.id }
    if collection.count_documents(myquery) == 0:
        await ctx.send(content="<@{}> You have not yet been initiated! Please run the command `/initiate` in order to use auction commands".format(ctx.author.id))
        return
    accepting = public_auction.find_one()["accepting_bids"]
    if not accepting:
        await ctx.send(content="Processing bids for payouts, not currently accepting bids.")
        return
    if bid_amount <= 0:
        await ctx.send(content="Heyyyy, you can't do thatttt. Make sure you bid a positive number.")
    else:
        currency = collection.find_one({"_id": ctx.author.id})["currency"]
        if bid_amount > currency:
            await ctx.send(content="I see you. You can't bid more than what you have.")
            return
        cursor = public_auction.find_one()
        # {<id>: {<item_name>: <price>, "sold": <boolean>}
        items = cursor["items"]
        if not item in items:
            await ctx.send(content="{} is not currently being auctioned".format(item))
            return
        pov = cursor["start_pov"]
        price = market_place.find_one({"item": item})["price"] * pov
        if bid_amount < price:
            await ctx.send(content="The starting price is ${}. Please at least bid above that.".format(round(price, 2)))
            return
        current_bids = public_auction.find_one()["bids"]
        highest_price = 0
        if (len(current_bids) > 0):
            for bid in current_bids:
                if bid["item"] == item and bid["price"] > highest_price:
                    highest_price = bid["price"]
            if bid_amount <= highest_price:
                await ctx.send(content="You must bid a number higher than the current highest bid! Highest bid: ${}".format(highest_price))
                return
        public_auction.update_one({"_id": cursor["_id"]}, {"$push": {"bids": {"bidder": ctx.author.id, "item": item, "price": bid_amount}}})
        await ctx.send(content="<@{}> bid ${} for {}!".format(ctx.author.id, bid_amount, item))

# Let member join a private room
@slash.slash(
            name="join",
            description="Join a private auction room",
            guild_ids=guild_ids,
            options=[
                create_option(
                    name="private",
                    description="Join Privately hosted Auction by typing the auction code",
                    option_type=3,
                    required=True
                )
            ]
        )
async def _join(ctx, private: str):
    # check if initiated
    myquery = { "_id": ctx.author.id }
    if collection.count_documents(myquery) == 0:
        await ctx.send(content="<@{}> You have not yet been initiated! Please run the command `/initiate` in order to use auction commands".format(ctx.author.id))
        return
    elif collection.count_documents({ "_id": ctx.author.id, "personal_auction_room": private}) == 1:
        await ctx.send(content="<@{}> You can't join your own room silly!".format(ctx.author.id))
    else:
        # check if private auction room exists
        myquery = {"_room": private}
        private_query = {"_room": private, "in_session": True}
        if private_auction.count_documents(myquery) == 0:
            await ctx.send(content="Looks like private auction room {} does not exist :(. You should double check the auction room code or create your own with /create_auction_room".format(private))
        else:
            user = collection.find_one({"_id": ctx.author.id})
            if user["private_auction_room"] == private:
                await ctx.send(content="You are already a member of this room!".format(private))
                return
            # check if auction room is middle of session
            if collection.count_documents(private_query) == 1:
                await ctx.send(content="Looks like this private auction room is in the middle of an auction! Please wait till the auction is over to join room.".format(private))
            else:
                post = {"_id": ctx.author.id, "currency": 10000, "items":[], "private_auction_room":private, "personal_auction_room": ""}
                collection.update_one({"_id": ctx.author.id}, {"$set": {"private_auction_room": private}})
                private_auction.update_one({"_room": private},{"$push": {"members": ctx.author.id}})
                await ctx.send(content="<@{}> You have joined a private auction room! Check your DMs for the room number".format(ctx.author.id))
                await ctx.author.send(content="You have joined private auction room {}! If you were in another one, you were removed as you can only be in one room at a time.".format(private))

# Place bids on items in a private auction
@slash.slash(name="private_bid", description="Bid for item currently being auctioned in the private auction!", guild_ids=guild_ids,
                options=[
                create_option(
                    name="bid_amount",
                    description="Bid the amount you are willing to spend on the current item being auctioned for your private room",
                    option_type=4,
                    required=True
                )]
            )
async def _private_bid(ctx, bid_amount: int):
    myquery = { "_id": ctx.author.id }
    if collection.count_documents(myquery) == 0:
        await ctx.send(content="<@{}> You have not yet been initiated! Please run the command `/initiate` in order to use auction commands".format(ctx.author.id))
        return
    if bid_amount <= 0:
        await ctx.send(content="Heyyyy, you can't do thatttt. Make sure you bid a positive number.")
    else:
        currency = collection.find_one({"_id": ctx.author.id})["currency"]
        if bid_amount > currency:
            await ctx.send(content="I see you. You can't bid more than what you have.")
            return
        p_r = collection.find_one({"_id": ctx.author.id})["private_auction_room"]
        if not p_r:
            await ctx.send(content="You are not part of any private auctions!")
            return
        private_room = private_auction.find_one({"_room": p_r})
        pov = private_room["start_pov"]
        price = market_place.find_one({"item": private_room["current_auction_item"]})["price"] * pov
        if bid_amount < pov:
            await ctx.send(content="The starting price is ${}. Please at least bid above that.".format(round(price,2)))
            return
        if not private_room["in_session"]:
            await ctx.send(content="Looks like the private auction is not in session. Please wait.")
        else:
            cursor = private_auction.find_one({"_room": p_r})
            current_bids = cursor["bids"]
            highest_price = 0
            for bid in current_bids:
                if bid["price"] > highest_price:
                    highest_price = bid["price"]
            if bid_amount <= highest_price:
                await ctx.send(content="You must bid above: ${}".format(round(highest_price, 2)))
                return
            else:
                # {<id>: {"item": <item_name>, "price": <price>, "sold": <boolean>}
                curr_item = cursor["current_auction_item"]
                private_auction.update_one({"_room": p_r}, {"$push": {"bids": {"bidder": ctx.author.id, "item": curr_item, "price": bid_amount, "sold": False}}})
                await ctx.send(content="<@{}> bid ${} for {}!".format(ctx.author.id, bid_amount, curr_item))

# Create your own private auction room!
@slash.slash(name="create", description="Create a private auction room!", guild_ids=guild_ids)
async def _create(ctx):
    myquery = { "_id": ctx.author.id }
    if collection.count_documents(myquery) == 0:
        await ctx.send(content="<@{}> You have not yet been initiated! Please run the command `/initiate` in order to use auction commands".format(ctx.author.id))
        return
    ud = collection.find_one({"_id": ctx.author.id})
    print(ud)
    if "private_auction_room" in ud.keys() and ud["personal_auction_room"]:
        await ctx.send(content="<@{}> You already have a private room! I sent a reminder of the room code in your DMs".format(ctx.author.id))
        await ctx.author.send(content="You already have a private room, it is: {}".format(ud["personal_auction_room"]))
    else:
        room = ''.join(random.choices(string.ascii_uppercase + string.digits, k=8))
        while not private_auction.count_documents({"_room": room}) == 0:
            room = ''.join(random.choices(string.ascii_uppercase + string.digits, k=8))
        items = collection.find_one({"_id": ctx.author.id})["items"]
        post = {"_room": room, "owner": ctx.author.id, "members": [], "items": items, "current_auction_item": "", "bids": [], "in_session": False}
        private_auction.insert_one(post)
        collection.update_one({"_id": ctx.author.id}, {"$set": {"personal_auction_room": room}})
        ud = collection.find_one({"_id": ctx.author.id})
        await ctx.send(content="<@{}> I created your private auction room! I sent the room code your DMs".format(ctx.author.id))
        await ctx.author.send(content="Your private room code is: {}".format(ud["personal_auction_room"]))

# Sell stuff back to the marketplace
@slash.slash(name="sell", description="Sell ALL instances of your item to the market place!", guild_ids=guild_ids,
                options=[
                create_option(
                    name="item_type",
                    description="Choose what type of item you are selling.",
                    option_type=3,
                    choices=[
                        create_choice(
                            name="set",
                            value="set"
                        ),
                        create_choice(
                            name="part",
                            value="part"
                        ),
                        create_choice(
                            name="collectable",
                            value="collectable"
                        ),
                        create_choice(
                            name="single",
                            value="single"
                        ),
                    ],
                    required=True
                ),
                create_option(
                    name="item",
                    description="What item are you selling?",
                    option_type=3,
                    required=True
                )]
            )
async def _sell(ctx, item_type: str, item: str):
    myquery = { "_id": ctx.author.id }
    if collection.count_documents(myquery) == 0:
        await ctx.send(content="<@{}> You have not yet been initiated! Please run the command `/initiate` in order to use auction commands".format(ctx.author.id))
        return
    items = collection.find_one({"_id": ctx.author.id})["items"]
    item_found = False
    index = 0
    if item_type == "part":
        splitval = item.split("|")
        if len(splitval) == 2:
            item_set = splitval[0].strip()
            part = splitval[1].strip()
        else:
            await ctx.send(content="The format should be set|part. Please try again.")
            return
    count = 0
    for item_it in items[item_type]:
        if item_it == item:
            count += 1
    if count == 0:
        await ctx.send(content="Looks like you don't own this item. Perhaps check your capitalizations or spelling. Perhaps you selected the wrong type? Please try purchasing something you actually own.")
        return
    elif item_type == "part":
        market_item = market_place.find_one({"item": item_set})
        for x in range(len(market_item["parts"])):
            if list(market_item["parts"][x].keys())[0] == part:
                print(list(market_item["parts"][x].keys())[0])
                print(list(market_item["parts"])[x][part])
                collection.update_one({"_id": ctx.author.id}, {"$inc": {"currency": list(market_item["parts"])[x][part]}})
                collection.update_one({"_id": ctx.author.id}, {"$pull": {"items.{}".format(item_type): item}})
                break
        currency = collection.find_one({"_id": ctx.author.id})["currency"]
        await ctx.send(content="Congrats! You have sold {} {} from {} for a total of ${}. Your current balance is: ${:.2f}".format(count, part, item_set, market_item["price"] * count, currency)) 
    else:
        market_item = market_place.find_one({"item": item})
        print(market_item)
        if item_type == "collectable":
            # q = []
            # for x in range(len(f_i)):
            #     q.append({item_type: item_type[f_i[x]]})
            collection.update_one({"_id": ctx.author.id}, {"$inc": {"currency": market_item["price"] * market_item["multiplier"] * count}})
            collection.update_one({"_id": ctx.author.id}, {"$pull": {"items.{}".format(item_type): item}})
            currency = collection.find_one({"_id": ctx.author.id})["currency"]
            await ctx.send(content="Congrats! You have sold {} {} for a total of ${}. Your current balance is: ${:.2f}".format(count, item, market_item["price"] * market_item["multiplier"] * count, currency))
        else:
            collection.update_one({"_id": ctx.author.id}, {"$inc": {"currency": market_item["price"] * count}})
            collection.update_one({"_id": ctx.author.id}, {"$pull": {"items.{}".format(item_type): item}})
            currency = collection.find_one({"_id": ctx.author.id})["currency"]
            await ctx.send(content="Congrats! You have sold {} {} for a total of ${}. Your current balance is: ${:.2f}".format(count, item, market_item["price"] * count, currency))        

# Buy stuff from the marketplace
@slash.slash(name="buy", description="Buy an item from the market place!", guild_ids=guild_ids,
                options=[
                    create_option(
                        name="item_type",
                        description="Choose what type of item you are buying.",
                        option_type=3,
                        choices=[
                            create_choice(
                                name="set",
                                value="set"
                            ),
                            create_choice(
                                name="part",
                                value="part"
                            ),
                            create_choice(
                                name="collectable",
                                value="collectable"
                            ),
                            create_choice(
                                name="single",
                                value="single"
                            ),
                        ],
                        required=True
                    ),
                    create_option(
                        name="item",
                        description="What item are you buying?",
                        option_type=3,
                        required=True
                    ),
                    create_option(
                        name="number_of_items",
                        description="How many do you want to buy?",
                        option_type=4,
                        required=True
                    )])
async def _buy(ctx, item_type: str, item: str, number_of_items: int):
    myquery = { "_id": ctx.author.id }
    if collection.count_documents(myquery) == 0:
        await ctx.send(content="<@{}> You have not yet been initiated! Please run the command `/initiate` in order to use auction commands".format(ctx.author.id))
        return
    if number_of_items <= 0:
        await ctx.send(content="So, uh no. Make sure the number of items is greater than 0")
        return
    user_data = collection.find_one({"_id": ctx.author.id})
    cash = user_data["currency"]
    if item_type == "part":
        splitval = item.split("|")
        if len(splitval) == 2:
            item_set = splitval[0].strip()
            part = splitval[1].strip()
            market_item = market_place.find_one({"item": item_set})
            item_price = 0
            for x in market_item["parts"]:
                if list(x.keys())[0] == part:
                    print()
                    item_price = x[part]
                    break
            if item_price == 0:
                await ctx.send(content="It seems like {} doesn't exist...".format(item))
                return
            else:
                total_cost = item_price * number_of_items
                if total_cost < 0:
                    await ctx.send(content="<@{}>I don't know how you've done this but I put extra check just in case smh.".format(ctx.author.id))
                    return
                if total_cost > cash:
                    await ctx.send(content="Rip, looks like you don't have enough".format(item))
                    return
                else:
                    collection.update_one({"_id": ctx.author.id}, {"$inc": {"currency": -total_cost}})
                    # I had -1000 IQ here and decided to make a request to the database every N items bought. 
                    # Who would have guessed that people will buy hundreds to thousands of items?
                    for i in range(number_of_items):
                        collection.update_one({"_id": ctx.author.id}, {"$push": {"items.{}".format(item_type): item}})
                    bal = collection.find_one({"_id": ctx.author.id})["currency"]
                    await ctx.send(content="Congrats you bought {} {}! It cost you ${} so your current balance is ${}".format(number_of_items, item, total_cost, bal))
        else:
            await ctx.send(content="The format should be set|part. Please try again.")
            return
    else:
        market_item = market_place.find_one({"item": item})
        print(market_item)
        if not market_item["type"] == item_type:
            await ctx.send(content="<@{}>You got the type wrong. Please use {}.".format(ctx.author.id, market_item["type"]))
            return
        item_price = market_item["price"]
        if item_price * number_of_items < 0:
            await ctx.send(content="<@{}>I don't know how you've done this but I put extra check just in case smh.".format(ctx.author.id))
            return
        if (item_price * number_of_items) > cash:
            await ctx.send(content="Rip, looks like you don't have enough".format(item))
            return
        else:
            collection.update_one({"_id": ctx.author.id}, {"$inc": {"currency": -item_price * number_of_items}})
            for i in range(number_of_items):
                collection.update_one({"_id": ctx.author.id}, {"$push": {"items.{}".format(item_type): item}})
            bal = collection.find_one({"_id": ctx.author.id})["currency"]
            await ctx.send(content="Congrats you bought {} {}! It cost you ${} so your current balance is ${}".format(number_of_items, item, item_price * number_of_items, bal))
        

# Assemble parts into a set
@slash.slash(name="assemble", description="Assemble your parts into a set!", guild_ids=guild_ids,
                options=[
                    create_option(
                        name="set_name",
                        description="Choose what set you want to assemble",
                        option_type=3,
                        required=True
                    )])
async def _assemble(ctx, set_name: str):
    myquery = { "_id": ctx.author.id }
    if collection.count_documents(myquery) == 0:
        await ctx.send(content="<@{}> You have not yet been initiated! Please run the command `/initiate` in order to use auction commands".format(ctx.author.id))
        return

    # get list of user parts
    user_data = collection.find_one({"_id": ctx.author.id})
    user_items: dict = user_data["items"]
    user_parts = user_items["part"]

    # generate list of required parts given the set name
    item_set: dict = market_place.find_one({"item": set_name})
    if not item_set["type"] == "set":
        await ctx.send(content="<@{}> That is not a set.".format(ctx.author.id))
        return
    parts_dict: List[dict] = item_set["parts"]
    parts_in_set: List[str] = []
    for part in parts_dict:
        key = list(part.keys())
        parts_in_set.append(set_name + "|" + key[0])

    
    if item_set is None:
        await ctx.send(content="<@{}> It seems like {} doesn't exist...".format(ctx.author.id, set_name))
        return

    # check if user has required parts
    assemble: bool = True
    for required in parts_in_set:
        if required not in user_parts:
            assemble = False
    
    if assemble is False:
        await ctx.send(content="<@{}> You do not have the required parts for this set.".format(ctx.author.id))
        return
    else:
        new_user_parts = list(user_parts)
        for required in parts_in_set: 
            # remove the required items for the set
            print(new_user_parts)
            new_user_parts.remove(required)
        collection.update_one({"_id": ctx.author.id}, {"$set": {"items.{}".format("part"): new_user_parts}})

        # add the new assembled set to user's inventory
        collection.update_one({"_id": ctx.author.id}, {"$push": {"items.{}".format("set"): set_name}})
        await ctx.send(content="<@{}> You have assembled {} ".format(ctx.author.id, set_name))
        return

# Get and Display all items from the marketplace
@slash.slash(name="marketplace", description="Find out whats in the marketplace!", guild_ids=guild_ids)
async def _marketplace(ctx):
    market = market_place.find()
    message = "```md\n"
    for item in market:
        name = item["item"]
        item_type = item["type"]
        if item_type == "set":
            complete_price = item["price"]
            parts = ""
            for part in item["parts"]:
                parts += "Part: {}| Price: {}, ".format(list(part.keys())[0], part[list(part.keys())[0]])
            parts = parts[:-2]
            message += "- **{}**: Type: {}, Price: {} Parts: {}\n".format(name, item_type, complete_price, parts)
            # embed.add_field(name="_", value="\u200B", inline=False)
        else:
            price = item["price"]
            message += "- **{}**: Type: {}, Price: {}\n".format(name, item_type, price)
    # await ctx.send(content="<@{}> I DM'd you the marketplace!".format(ctx.author.id))    
    message += "```"
    await ctx.send(content=message)

# Help
@slash.slash(name="help", description="What is auction bot?", guild_ids=guild_ids)
async def _help(ctx):
    m = """
    This is auction bot! Auction bot is dedicated to provide the best auctioning experience possible.

    To become a member of the Auction House please run the command `/initiate`.
    There are a variety of commands you can run (type `/` to see a list).
    You can buy and sell items from the market places. Each item has a specific type.

    - `single`: Price for item is static no matter how many you sell.
    - `collectable`: If you sell these at the same time an arbitrary multiplier increases overall value
    - `part`: Get an item that can be assembled into a larger single `set`!
    - `set`: An item worth more than all the parts combined. Type `/assemble <Set Name>` to convert `parts` to `set`

    There is a public auction happening with payouts and new items happening every 10 minutes.
    You check which items are being auctioned with `/public_auction_items`.
    
    `/bid` to bid in the public auction btw.

    These items are all being auctioned at the same time so feel free to bid for any item being auctioned you fancy.
    
    You can also host your own private auctions! Simply run `/create` to make a private room and share that code with
    anyone you want! Your private room is permanent so share your room code wisely! However, members of your room
    can leave with `/leave_room`. Steps are:

    1) /start_private_auction
    2) /auction <item> <starting bid>
    3) /stop_private_bidding (this determines who one the bid and distributes the payout)
    4) /end_private_auction

    If you royally screw up you can do /i_screwed_up

    Good Luck!
    """
    await ctx.send(m)

# If you no longer want to be in a private room
@slash.slash(name="leave_room", description="Leave the private room you are in.", guild_ids=guild_ids)
async def _leave_room(ctx):
    myquery = { "_id": ctx.author.id }
    if (collection.count_documents(myquery) == 0):
        await ctx.send(content="<@{}> You have not yet been initiated! Please run the command `/initiate` in order to use auction commands".format(ctx.author.id))
        return
    user_data = collection.find_one({"_id": ctx.author.id})
    if user_data["private_auction_room"]:
        members = private_auction.find_one({"_room": user_data["private_auction_room"]})["members"]
        members.remove(ctx.author.id)
        collection.update_one({"_id": ctx.author.id}, {"$set": {"private_auction_room": ""}})
        private_auction.update_one({"_room": user_data["private_auction_room"]}, {"$set": {"members": members}})
        await ctx.send(content="<@{}> You have left the private auction room".format(ctx.author.id))
    else:
        await ctx.send(content="<@{}> Looks like you already left a private auction room".format(ctx.author.id))

# Start your private auction (notifies everyone in your room)
@slash.slash(name="start_private_auction", description="Start your private auction!", guild_ids=guild_ids)
async def _start_private_auction(ctx):
    myquery = { "_id": ctx.author.id }
    if (collection.count_documents(myquery) == 0):
        await ctx.send(content="<@{}> You have not yet been initiated! Please run the command `/initiate` in order to use auction commands".format(ctx.author.id))
        return
    user_data = collection.find_one({"_id": ctx.author.id})
    if user_data["personal_auction_room"]:
        auction_room = private_auction.find_one({"_room": user_data["personal_auction_room"]})
        if auction_room["in_session"]:
            await ctx.send(content="<@{}> You already started a session. Do /end_private_auction to end current session".format(ctx.author.id))
            return
        if len(auction_room["members"]) <= 0:
            await ctx.send(content="<@{}> Looks Like you have no members in your private room. Send your room code to people so they can join!".format(ctx.author.id))
            return
        private_auction.update_one({"_room": user_data["personal_auction_room"]}, {"$set": {"in_session": True}})
        starting_price = random.randint(30, 50)
        starting_price /= 100
        private_auction.update_one({"_room": user_data["personal_auction_room"]}, {"$set": {"start_pov": starting_price}})
        m = ""
        for member in auction_room["members"]:
            m += "<@{}>".format(member)
        await ctx.author.send(content="You have started a private auction. Type /auction_item <item_type> <item> to put it up for a bid. Once an item is put up do /stop_private_bidding to distribute payouts.")
        await ctx.send(content="{}: <@{}> has started a private auction!".format(m, ctx.author.id))
    else:
        await ctx.send(content="<@{}> Looks like you have not made a private auction room. Please run /create in order to make one".format(ctx.author.id))
        return

# Check who owns the private room you are in
@slash.slash(name="private_room_owner", description="Who owns the private auction room you're in?", guild_ids=guild_ids)
async def _private_auction_items(ctx):
    myquery = { "_id": ctx.author.id }
    if (collection.count_documents(myquery) == 0):
        await ctx.send(content="<@{}> You have not yet been initiated! Please run the command `/initiate` in order to use auction commands".format(ctx.author.id))
        return
    myquery = { "_id": ctx.author.id }
    if (collection.count_documents(myquery) == 0):
        await ctx.send(content="<@{}> You have not yet been initiated! Please run the command `/initiate` in order to use auction commands".format(ctx.author.id))
        return
    p_r = collection.find_one({"_id": ctx.author.id})["private_auction_room"]
    if not p_r:
        await ctx.send(content="You are not in a private room! /join <room code> to join private room")
        return
    private_room = private_auction.find_one({"_room": p_r})
    await ctx.send(content="I sent the ID of the owner in your DMs because pinging them would be annoying. You probably can't see the user unless you have discord's developer mode enabled.")
    await ctx.author.send("Owner of private room is: <@{}>".format(private_room["owner"]))

# Check what is being auctioned in the private room
@slash.slash(name="private_auction_item", description="Check what item is up for auction in the private auction room", guild_ids=guild_ids)
async def _private_auction_items(ctx):
    myquery = { "_id": ctx.author.id }
    if (collection.count_documents(myquery) == 0):
        await ctx.send(content="<@{}> You have not yet been initiated! Please run the command `/initiate` in order to use auction commands".format(ctx.author.id))
        return
    p_r = collection.find_one({"_id": ctx.author.id})["private_auction_room"]
    if not p_r:
        await ctx.send(content="You are not in a private room! /join <room code> to join private room")
        return
    private_room = private_auction.find_one({"_room": p_r})
    pov = private_room["start_pov"]
    item = private_room["current_auction_item"]
    if not private_room["in_session"]:
        await ctx.send(content="There is currently no private auction in session")
        return
    if item:
        await ctx.send(content="Item currently being auctioned in private room is {} starting at ${}".format(item, pov))
    else:
        await ctx.send(content="There are currently no items up for auction.")
    
# Choose an item to auction off at your desired price
@slash.slash(name="auction_item", description="Put one of your items up for auction", guild_ids=guild_ids,
                options=[
                    create_option(
                        name="item_type",
                        description="Choose what type of item you are auctioning.",
                        option_type=3,
                        choices=[
                            create_choice(
                                name="set",
                                value="set"
                            ),
                            create_choice(
                                name="collectable",
                                value="collectable"
                            ),
                            create_choice(
                                name="single",
                                value="single"
                            ),
                        ],
                        required=True
                    ),
                    create_option(
                        name="item",
                        description="What item are you auctioning?",
                        option_type=3,
                        required=True
                    ),
                    create_option(
                        name="starting_bid_price",
                        description="Auction Item Start Price.",
                        option_type=4,
                        required=True
                    ),
                ]
            )
async def _auction_item(ctx, item_type: str, item: str, starting_bid_price: int):
    myquery = { "_id": ctx.author.id }
    if (collection.count_documents(myquery) == 0):
        await ctx.send(content="<@{}> You have not yet been initiated! Please run the command `/initiate` in order to use auction commands".format(ctx.author.id))
        return
    user_data = collection.find_one({"_id": ctx.author.id})
    if not item in user_data["items"][item_type]:
        await ctx.send(content="Looks like you don't own this item. Maybe you chose the wrong type?")
        return
    if user_data["personal_auction_room"]:
        auction_room = private_auction.find_one({"_room": user_data["personal_auction_room"]})
        if auction_room["in_session"]:
            if auction_room["current_auction_item"]:
                await ctx.send(content="You already have up {} for auction! Do /stop_private_bidding in order sell your item to the highest bidder.".format(auction_room["current_auction_item"]))
                return
            private_auction.update_one({"_room": user_data["personal_auction_room"]}, {"$set": {"current_auction_item": item}})
            price = market_place.find_one({"item": item})["price"]
            if (float(starting_bid_price) / float(price)) < .3:
                await ctx.send(content="The starting bid price must be at least 30% of the original value".format(auction_room["current_auction_item"]))
                return
            pov = starting_bid_price
            private_auction.update_one({"_room": user_data["personal_auction_room"]}, {"$set": {"start_pov": pov}})
            await ctx.send(content="<@{}> has put up {} for auction starting at ${}!".format(ctx.author.id, item, starting_bid_price ))
        else:
            await ctx.send(content="Looks like your private auction is NOT in session. Please do /run_private_auction in order to start a session".format(item))
    else:
        await ctx.send(content="<@{}> Looks like you have not made a private auction room. Please run /create in order to make one".format(ctx.author.id))
        return

# Sell item to highest current bidder
@slash.slash(name="stop_private_bidding", description="Sell your item to the highest private bidder!", guild_ids=guild_ids)
async def _stop_private_bidding(ctx):
    myquery = { "_id": ctx.author.id }
    if (collection.count_documents(myquery) == 0):
        await ctx.send(content="<@{}> You have not yet been initiated! Please run the command `/initiate` in order to use auction commands".format(ctx.author.id))
        return
    user_data = collection.find_one({"_id": ctx.author.id})
    if user_data["personal_auction_room"]:
        auction_room = private_auction.find_one({"_room": user_data["personal_auction_room"]})
        if len(auction_room["members"]) <= 0:
            await ctx.send(content="<@{}> Looks Like you have no members in your private room. Send your room code to people so they can join!".format(ctx.author.id))
            return
        if not auction_room["current_auction_item"]:
            await ctx.send("Looks like you didn't have an item up for auction. Type /private_auction_item to see what is up for the private auction")
            return
        if not auction_room["in_session"]:
            await ctx.send("You haven't started an auction session. Do /run_private_auction to start an auction")
            return
        highest_bid = 0
        highest_bidder = ""
        for x in auction_room["bids"]:
            if x["price"] > highest_bid:
                highest_bid += x["price"]
                highest_bidder = x["bidder"]
        if highest_bid <= 0:
            await ctx.send("Looks like there are no bidders.")
            private_auction.update_one({"_room": user_data["personal_auction_room"]}, {"$set": {"current_auction_item": ""}})
            return
        else:
            item_type = market_place.find_one({"item": auction_room["current_auction_item"]})["type"]
            user_items = collection.find_one({"_id": ctx.author.id})["items"][item_type]
            user_items.remove(auction_room["current_auction_item"])
            collection.update_one({"_id": highest_bidder}, {"$push": {"items.{}".format(item_type): auction_room["current_auction_item"]}})
            collection.update_one({"_id": ctx.author.id}, {"$set": {"items.{}".format(item_type): user_items}})
            collection.update_one({"_id": highest_bidder}, {"$inc": {"currency": -highest_bid}})
            collection.update_one({"_id": ctx.author.id}, {"$inc": {"currency": highest_bid}})
            private_auction.update_one({"_room": user_data["personal_auction_room"]}, {"$set": {"current_auction_item": ""}})
            private_auction.update_one({"_room": user_data["personal_auction_room"]}, {"$set": {"bids": []}})
            await ctx.send(content="Congrats to <@{}> for winning <@{}>'s private auction of {}!".format(highest_bidder, ctx.author.id, auction_room["current_auction_item"]))
    else:
        await ctx.send(content="<@{}> Looks like you have not made a private auction room. Please run /create in order to make one".format(ctx.author.id))
        return

# Stop a private auction session
@slash.slash(name="end_private_auction", description="Stop your private auction session.", guild_ids=guild_ids)
async def _end_private_auction(ctx):
    myquery = { "_id": ctx.author.id }
    if (collection.count_documents(myquery) == 0):
        await ctx.send(content="<@{}> You have not yet been initiated! Please run the command `/initiate` in order to use auction commands".format(ctx.author.id))
        return
    user_data = collection.find_one({"_id": ctx.author.id})
    if user_data["personal_auction_room"]:
        auction_room = private_auction.find_one({"_room": user_data["personal_auction_room"]})
        if auction_room["current_auction_item"]:
            await ctx.send(content="<@{}> You can't end an auction session while an item is up for bidding. Do /stop_private_bidding to sell the current auction item".format(ctx.author.id))
            return
        if not auction_room["in_session"]:
            await ctx.send(content="<@{}> Looks you haven't started a private auction yet!".format(ctx.author.id))
            return
        else:
            private_auction.update_one({"_room": user_data["personal_auction_room"]}, {"$set": {"in_session": False}})
            m = ""
            if len(auction_room["members"]) > 0:
                for member in auction_room["members"]:
                    m += "<@{}>".format(member)
            else:
                m = "<@{}>"
            await ctx.author.send(content="You have ended your private auction! Type /run_private_auction to start a new session!")
            await ctx.send(content="{}: <@{}> has ended the current private auction session! Keep your ears open for when the next session starts!".format(m, ctx.author.id))
    else:
        await ctx.send(content="<@{}> Looks like you have not made a private auction room. Please run /create in order to make one".format(ctx.author.id))
        return

# Check what items are being auctioned in the public room
@slash.slash(name="public_auction_items", description="What items are being auctioned publicly?",  guild_ids=guild_ids)
async def _public_auction_items(ctx):
    items = public_auction.find_one()["items"]
    pov = public_auction.find_one()["start_pov"]
    m = "Items Currently in Public Auction:\n"
    for item in items:
        price = market_place.find_one({"item": item})["price"] * pov
        m += "- **{}**, starting price: {}\n".format(item, round(price,2))
    await ctx.send(content=m)    

# This is the main public auction that distributes winnings and selects new items to be auctioned
@tasks.loop(minutes=5)
async def run_public_auction():
    print("Running run_public_auction()")
    auction = public_auction.find_one()
    items = auction["items"]
    bids = auction["bids"]
    highest_bidders = {}
    public_auction.update_one({"_id": auction["_id"]}, {"$set": {"accepting_bids": False}})
    if len(bids) == 0:
        await bot.wait_until_ready()
        channel = bot.get_channel(BOT_CHANNEL)
        await channel.send(content="Looks like nobody put in any bids. Remember do /bid <amount> <item> to bid.")
    else:
        for item in items:
            highest_bidders[item] = {"highest_bid": 0, "bidder": ""}
        for bid in bids:
            if highest_bidders[bid["item"]]["highest_bid"] < bid["price"]:
                highest_bidders[bid["item"]]["highest_bid"] = bid["price"]
                highest_bidders[bid["item"]]["bidder"] = bid["bidder"]

        for item in highest_bidders:
            if highest_bidders[item]["bidder"]:
                item_type = market_place.find_one({"item": item})["type"]
                collection.update_one({"_id": highest_bidders[item]["bidder"]}, {"$push": {"items.{}".format(item_type): item}})
                collection.update_one({"_id": highest_bidders[item]["bidder"]}, {"$inc": {"currency": -highest_bidders[item]["highest_bid"]}})
                await bot.wait_until_ready()
                channel = bot.get_channel(BOT_CHANNEL)
                await channel.send(content="Congrats <@{}> you won the bid for {} for ${}!".format(highest_bidders[item]["bidder"], item, highest_bidders[item]["highest_bid"]))
    
    size = 10
    new_items = market_place.aggregate( [ { "$sample": {"size": size} } ] )
    items = []
    for document in new_items:
        items.append(document["item"])
    items = list(set(items))
    # I probably could have weighted this so Ultra Rare actually shows up a lot less but done > than nothing.
    flags = ["Flag Common", "Flag Rare", "Flag Ultra Rare"]
    flag = random.choice(flags)
    items.append(flag)
    starting_price = random.randint(30, 50)
    starting_price /= 100
    public_auction.update_one({"_id": auction["_id"]}, {"$set": {"items": items}})
    public_auction.update_one({"_id": auction["_id"]}, {"$set": {"start_pov": starting_price}})
    public_auction.update_one({"_id": auction["_id"]}, {"$set": {"bids": []}})
    await bot.wait_until_ready()
    channel = bot.get_channel(BOT_CHANNEL)
    public_auction.update_one({"_id": auction["_id"]}, {"$set": {"accepting_bids": True}})
    await channel.send(content="New items are being auctioned!")

# Check your balance
@slash.slash(name="balance", description="How much money do you have?", guild_ids=guild_ids)
async def _balance(ctx):
    myquery = { "_id": ctx.author.id }
    if (collection.count_documents(myquery) == 0):
        await ctx.send(content="<@{}> You have not yet been initiated! Please run the command `/initiate` in order to use auction commands".format(ctx.author.id))
        return
    balance = collection.find_one({"_id": ctx.author.id})["currency"]
    await ctx.send(content="<@{}> Your balance is ${}!".format(ctx.author.id, balance))

# Check your inventory... I totally forgot discord has a word limit.
@slash.slash(name="inventory", description="What's in your inventory?", guild_ids=guild_ids)
async def _inventory(ctx):
    myquery = { "_id": ctx.author.id }
    if (collection.count_documents(myquery) == 0):
        await ctx.send(content="<@{}> You have not yet been initiated! Please run the command `/initiate` in order to use auction commands".format(ctx.author.id))
        return
    inventory = collection.find_one({"_id": ctx.author.id})["items"]
    message = ""
    if len(inventory["set"]) > 0:
        message += "You have the following **sets**:\n"
        for x in inventory["set"]:
            message += "\t- {}\n".format(x)
        message += "\n"
    else:
        message += "You have no sets at the moment :(\n\n"
    
    if len(inventory["collectable"]) > 0:
        message += "You have the following **collectables**:\n"
        for x in inventory["collectable"]:
            message += "\t- {}\n".format(x)
        message += "\n"
    else:
        message += "You have no collectables at the moment :(\n\n"
    
    if len(inventory["single"]) > 0:
        message += "You have the following **single items**:\n"
        for x in inventory["single"]:
            message += "\t- {}\n".format(x)
        message += "\n"
    else:
        message += "You have no collectables at the moment :(\n\n"
    
    if len(inventory["part"]) > 0:
        message += "You have the following **parts**:\n"
        for x in inventory["part"]:
            message += "\t- {}\n".format(x)
        message += "\n"
    else:
        message += "You have no parts at the moment :(\n\n"
    
    await ctx.send(content="<@{}> I have DM'd you your inventory list!".format(ctx.author.id))
    await ctx.author.send(content=message)

# Reset your entry into the database (RIP)
@slash.slash(name="i_screwed_up", description="For when you need a clean slate.", guild_ids=guild_ids)
async def _i_screwed_up(ctx):
    myquery = { "_id": ctx.author.id }
    if (collection.count_documents(myquery) == 0):
        await ctx.send(content="<@{}> You have not yet been initiated! Please run the command `/initiate` in order to use auction commands".format(ctx.author.id))
        return
    collection.update_one({"_id": ctx.author.id}, {"$set": {"currency": 10000}})
    collection.update_one({"_id": ctx.author.id}, {"$set": {"items": {"set": [], "collectable": [], "single": [], "part": []}}})
    collection.update_one({"_id": ctx.author.id}, {"$set": {"private_auction_room": ""}})
    collection.update_one({"_id": ctx.author.id}, {"$set": {"personal_auction_room": ""}})
    private_auction.delete_one({"owner": ctx.author.id})
    await ctx.send("<@{}> Hey its ok. Not everyone makes the right decisions. Now you have a clean slate. Try not to mess it up this time.".format(ctx.author.id))

# Checks if you have all three flags and gives you flag if you do
@slash.slash(name="redeem_flags", description="Redeem those flags", guild_ids=guild_ids)
async def _redeem_flags(ctx):
    myquery = { "_id": ctx.author.id }
    if (collection.count_documents(myquery) == 0):
        await ctx.send(content="<@{}> You have not yet been initiated! Please run the command `/initiate` in order to use auction commands".format(ctx.author.id))
        return
    currency = collection.find_one({"_id": ctx.author.id})["currency"]
    if currency < 0:
        await ctx.send(content="<@{}> You cannot reedem a flag while in debt".format(ctx.author.id))
        return
    single = collection.find_one({"_id": ctx.author.id})["items"]["single"]
    count = 0
    if "Flag Common" in single:
        count += 1
    if "Flag Rare" in single:
        count += 1
    if "Flag Ultra Rare" in single:
        count += 1
    if count == 3:
        collection.update_one({"_id": ctx.author.id}, {"$pull": {"items.single": "Flag Common"}})
        collection.update_one({"_id": ctx.author.id}, {"$pull": {"items.single": "Flag Rare"}})
        collection.update_one({"_id": ctx.author.id}, {"$pull": {"items.single": "Flag Ultra Rare"}})
        await ctx.send(content="DM'd you the result.")
        await ctx.author.send(content="||uiuctf\{at_the_bang_of_the_gavel_only_one_can_win\}||")
    else:
        await ctx.send(content="DM'd you the result.")
        await ctx.author.send(content="||Looks like you didn't have all three versions the flag||")

# A little joke - tie in with that other osint chal
@slash.slash(name="flag", description="Wait... flag?", guild_ids=guild_ids)
async def _flag(ctx):
    await ctx.send("<@{}> Dm'd you a little surprise.".format(ctx.author.id))
    await ctx.author.send(content="My friend @ChaplinCoding has some of those, he has been doing coding recently on twitter??? Otherwise we are auctioning some off if you got the cash.")

run_public_auction.start()
bot.run(TOKEN)