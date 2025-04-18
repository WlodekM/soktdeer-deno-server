/**
 * some part of this code were taken from soktdeer helium
 * 
 * The license for soktdeer helium:
 * MIT License
 * 
 * Copyright (c) 2024-2025 Cole W.
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

import mongo from "npm:mongodb";
import dotenv from "npm:dotenv";
import { scryptSync, randomBytes } from "node:crypto";
import uuid from "npm:uuid";

dotenv.config()

const mongoUrl = Deno.env.get('MONGO_URL')
const salt = Deno.env.get('SALT') as string;

if (!Deno.env.has('MONGO_URL') ||
    !mongoUrl ||
    typeof mongoUrl != 'string')
    throw 'process.env.MONGO_URL not string\n\na'

const client = new mongo.MongoClient(mongoUrl);

const db = client.db('deer')

if (!await db.admin().command({ ping: 1 }))
    throw 'ping fail'

async function getColl(collName: string) {
    if (!(await db.collections()).find(c => c.dbName == collName))
        db.createCollection(collName);
    return db.collection(collName)
}

const postsColl = await getColl('posts')
const usersColl = await getColl('users')
const inboxColl = await getColl('inbox')

console.info('uh ya')

//SECTION - DB
const acc = {
    async getUser(username: string) {
        const user = await usersColl.findOne({ "username": username });
        if (!user)
            return "notExists";
        else return user;
    },

    /** get just the public stuff */
    async getUserPublic(username: string, includeProfile = true) {
        const user = await usersColl.findOne({ "username": username });
        if (!user)
            return "notExists";
        else {
            delete user.secure;
            if (!includeProfile)
                delete user.profile;
            return user;
        }
    },

    async addUser(data: any, username: string = '') {
        const user = await usersColl.findOne({ "username": username })
        if (user)
            return "exists";
        try {
            usersColl.insertOne(data);
        } catch (_e) {
            return 'fail'
        }
        return true
    },

    async editUser(data: any, username: string) {
        const user = await usersColl.findOne({ "username": username })
        if (!user)
            return "notExists";
        const endr = { $set: data }
        try {
            usersColl.updateOne({ 'username': username }, endr)
        } catch (_e) {
            return 'fail'
        }
        return true
    },

    async removeUser(username: string) {
        const user = await usersColl.findOne({ "username": username })
        if (!user)
            return "notExists"
        try {
            // usersColl.deleteOne({"username": username})
            usersColl.updateOne({ "username": username }, { '$set': { 'deleted': true } })
            postsColl.deleteMany({ "author": username })
            postsColl.updateMany(
                { "replies": { "$elemMatch": { "author": username } } },
                { "$set": { "replies.$.content": "post deleted" } }
            )
            postsColl.updateMany(
                { "replies": { "$elemMatch": { "author": username } } },
                { "$set": { "replies.$.author": "deleted" } }
            )
        } catch (_e) {
            return "fail"
        }
        return true
    },

    async verify(token: string) {
        const user = await usersColl.findOne({ "secure.token": token })
        if (!user || user.deleted)
            return "notExists"
        if (user.banned_until > Math.round(Date.now()))
            return { "banned": true, "username": user["username"], "bot": user["bot"] }
        else
            return { "banned": false, "username": user["username"], "bot": user["bot"] }
    },

    async verifyPswd(username: string, password: string) {
        const user = await usersColl.findOne({ "username": username })
        if (!user)
            return "notExists"
        if (scryptSync(password, salt, 128) != user.secure.password)
            return "unauthorized"
        else if (user["banned_until"] > Math.round(Date.now()))
            return "banned"
        else
            return { "token": user.secure.token, "bot": user.bot }
    },

    async get_ban(username: string) {
        const user = await usersColl.findOne({ "username": username })
        if (!user)
            return "notExists"
        return { "banned_until": user["banned_until"], "ban_reason": user["secure"]["ban_reason"] }
    },

    async get_perms(username: string) {
        const user = await usersColl.findOne({ "username": username })
        if (!user)
            return "notExists"
        return user["permissions"]
    },
}
//!SECTION

const util = {
    error(code:string, listener:string | undefined, data:any={}) {
        let context: string;
        if (errorContexts[code])
            context = errorContexts[code]
        else
            context = ""
        const response = {
            "error": true,
            "code": code,
            "form": "helium-util",
            "context": context,
            "listener": listener,
            ...data
        }
        return JSON.stringify(response)
    },
    fieldCheck(expects: Record<string, {range: [number, number], types: string[]}>, gets: Record<string, any>) {
        for (const i in expects){
            if (!gets[i])
                return "malformedJson"
            if (typeof(gets[i]) == 'string' || Array.isArray(gets[i])){
                let yes = false;
                if (!expects[i].types.includes(typeof(gets[i]))
                    && expects[i].types.includes('array')
                    && Array.isArray(gets[i]))
                    yes = true;
                console.log(gets[i].length,expects[i].range)
                if ((gets[i].length &&
                    (
                        gets[i].length > expects[i].range[1] ||
                        gets[i].length < expects[i].range[0]
                    )) ||
                    (!expects[i].types.includes(typeof(gets[i])) && !yes))
                    return "lengthInvalid"
            }
        }
        return true
    }
}

const errorContexts: Record<string, string> = {
    "malformedJson": "The JSON data sent to the server could not be parsed.",
    "lengthInvalid": "A value in the JSON data is longer or shorter than expected.",
    "invalidUsername": "Username is invalid. It may contain characters that are not permitted in usernames.",
    "invalidFormat": "Value contains invalid characters, or is too long.",
    "invalidInvite": "The invite code you are trying to use is invalid or has expired.",
    "usernameTaken": "This username has been taken.",
    "notExists": "The requested value does not exist.",
    "lockdown": "Maintenance is in progress.",
    "authed": "You are already authenticated.",
    "unauthorized": "You must be authorized to perform this action.",
    "deprecated": "This command is no longer supported.",
    "ratelimited": "You are ratelimited."
}

const ulist = {}
const client_data: Record<string, any> = {}

const ratelimits: Record<string, number> = {}

const clients = []
const ips_by_client = {}

// const invite_codes = []
let locked = false

if (await acc.getUser("deleted") == "notExists") {
    await acc.addUser({
        "_id": "00000000-0000-0000-0000-000000000000",
        "username": "deleted",
        "display_name": "deleted",
        "created": 0,
        "avatar": undefined,
        "bot": false,
        "banned_until": 32503698000,
        "permissions": [],
        "profile": {
            "bio": "",
            "lastfm": "",
            "banner": undefined,
            "links": {}
        },
        "secure": {
            "password": "",
            "token": "",
            "ban_reason": "",
            "invite_code": "",
            "support_code": ""
        }
    }, 'deleted')
}

let idThing = 0;

Deno.serve({
    //TODO: move to .env
    port: 3636,
    handler: async (request) => {
        if (request.headers.get("upgrade") === "websocket") {
            const { socket, response } = Deno.upgradeWebSocket(request);

            const id = idThing++;

            socket.onopen = () => {
                console.log("CONNECTED");
            };
            socket.onmessage = async (event) => {
                if (typeof event.data != 'string')
                    return;
                const message = String(event.data)
                console.log(ratelimits[String(id)])
                console.log(Date.now())
                console.log(Date.now() > ratelimits[String(id)])
                if (ratelimits[String(id)] > Date.now()) {
                    let lst = undefined
                    try {
                        const r = JSON.parse(message)
                        if (!r.listener)
                            r.listener = undefined
                        lst = r.listener
                    // deno-lint-ignore no-empty
                    } catch (_e) {}
                    socket.send(util.error("ratelimited", lst))
                    return;
                }
                ratelimits[String(id)] = Date.now() + 0.25;
                let r;
                try {
                    r = JSON.parse(message)
                } catch (_e) {
                    socket.send(util.error("malformedJson", undefined))
                    return;
                }
                if (!r.listener)
                    r.listener = undefined;
                const listener = r.listener
                if (!r.command){
                    socket.send(util.error("malformedJson", listener))
                    return;
                }
                const commands: Record<string, () => Promise<void>> = {
                    'register': async () => {
                        const fieldCheck = util.fieldCheck({
                            username: {range: [1,21], types: ['string']},
                            password: {range: [8,256], types: ['string']},
                            invite_code: {range: [0, 199], types: ['string', 'undefined']}
                        }, r)
                        if (fieldCheck != true)
                            return socket.send(util.error(fieldCheck, listener))
                        if (client_data[String(id)])
                            return socket.send(util.error("authed", listener));
                        if (locked)
                            return socket.send(util.error("lockdown", listener));
                        r.username = r.username.toLowerCase();
                        if (!r.username.match(/^[a-z0-9-_.]{1,20}$/))
                            return socket.send(util.error("invalidUsername", listener))
                        if (await acc.getUser(r.username) != "notExists")
                            return socket.send(util.error("usernameTaken", listener));
                        //TODO: ip stuff
                        // ips = []
                        // if ips_by_client[websocket]:
                        //     ips.append(ips_by_client[websocket])
                        const data = {
                            "_id": uuid.v4(),
                            "username": r.username,
                            "display_name": r.username,
                            "created": Date.now(),
                            "avatar": undefined,
                            "bot": false,
                            "banned_until": 0,
                            "permissions": [],
                            "profile": {
                                "bio": "",
                                "lastfm": "",
                                "banner": undefined,
                                "links": {}
                            },
                            "secure": {
                                "password": scryptSync(r["password"], salt, 128),
                                "token": randomBytes(64).toString('base64url'),
                                "ban_reason": "",
                                "invite_code": r.invite_code ?? '',
                                "support_code": randomBytes(16).toString('base64url'),
                                "ips": [] //ips
                            }
                        }
                        const result = await acc.addUser(data)
                        if (result != true)
                            return socket.send(util.error(result, listener));
                        // invite_codes.remove(r["invite_code"])
                        socket.send(JSON.stringify({
                            error: false,
                            token: data.secure.token,
                            listener
                        }))
                    }
                }
                if (!commands[r.command])
                    return socket.send(util.error("malformedJson", listener))
            };
            socket.onclose = () => console.log("DISCONNECTED");
            socket.onerror = (error) => console.error("ERROR:", error);

            return response;
        } else {
            // If the request is a normal HTTP request,
            // we serve the client HTML file.
            const file = await Deno.open("./index.html", { read: true });
            return new Response(file.readable);
        }
    },
});
