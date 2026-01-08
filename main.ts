
// deno-lint-ignore-file no-explicit-any
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
import { scryptSync, randomBytes, timingSafeEqual } from "node:crypto";
import { encodeBase64, decodeBase64 } from "https://deno.land/std@0.224.0/encoding/base64.ts";
import * as uuid from "npm:uuid";

const N = 16384;
const r = 8;
const p = 1;
const keylen = 64;
const maxmem = 128 * r * N + 64 * 1024 * 1024

function hash(password: string): string {
	const salt = randomBytes(16);
	const key = scryptSync(password, salt, keylen, { N, r, p, maxmem });

	const salt_b64 = encodeBase64(salt);
	const key_b64 = encodeBase64(key);

	return `$scrypt$ln=${N},r=${r},p=${p}$${salt_b64}$${key_b64}`;
}
function verify(password: string, hash: string): boolean {
	const parts = hash.split("$");
	if (parts.length !== 5 || parts[1] !== "scrypt") return false;

	const paramStr = parts[2];
	const params = Object.fromEntries(paramStr.split(",").map(p => p.split("=")));
	const ln = parseInt(params.ln, 10);
	const r = parseInt(params.r, 10);
	const p = parseInt(params.p, 10);

	const N = 2 ** ln;
	const salt = decodeBase64(parts[3]);
	const expected = decodeBase64(parts[4]);

	const actual = scryptSync(password, salt, expected.length, { N, r, p, maxmem });

	return timingSafeEqual(actual, expected);
}

dotenv.config()

/** the base user interface */
interface User {
	_id: string,
	username: string,
	display_name: string,
	created: number,
	avatar: null | string,
	bot: boolean,
	banned_until: number,
	permissions: string[],
	verified?: boolean,
	deleted?: boolean
}

/** the full user, what is sent to you when you get_user */
interface FullUser extends User {
	profile: {
		bio: string,
		lastfm: string,
		banner: null | string,
		links: emptyObj
	},
}

/** the actual data stored in the db, make sure to delete secure before sending anywhere */
interface UserData extends FullUser {
	secure: {
		password: string,
		token: string,
		ban_reason: string,
		invite_code: string,
		support_code: string,
	},
}


/** the data sent by the user */
interface SentPostData {
	content: string,
	attachments: string[],
}

/** base post data */
interface BasePostData extends SentPostData {
	_id: string,
	created: number,
}

/** the post data in the db */
interface PostData extends BasePostData {
	author: string,
	replies: PostData[],
	reactions: {},
}

type emptyObj = Record<string | number | symbol, never>

interface ReplyPost extends BasePostData {
	author: User | emptyObj, // is only {} when something fucks up horribly
	replies: PostData[],
}
interface Post extends BasePostData {
	author: User | emptyObj, // is only {} when something fucks up horribly
	replies: ReplyPost[],
}
interface InboxPost {
	_id: string,
	created: number,
	content: string,
	attachments: string[],
	author?: string
}

interface UserStatus {
	banned: boolean,
	username: string,
	bot: boolean
}

type Omit<T, K extends keyof T> = Pick<T, Exclude<keyof T, K>>

const config = JSON.parse(
	Deno.readTextFileSync('config.jsonc')
		.replace(/\s*\/\/.*$/gm, '')
		.replace(/,\s*(\]|\})/gm, '$1')
)

const attachment_whitelist: string[] = config.whitelisted_urls

const mongoUrl = Deno.env.get('MONGO_URL')

if (!Deno.env.has('MONGO_URL') ||
	!mongoUrl ||
	typeof mongoUrl != 'string')
	throw 'process.env.MONGO_URL not string\n\na'

const client = new mongo.MongoClient(mongoUrl);

const db = client.db('deer-test')

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

//TODO - user and post interfaces

//SECTION - DB
class Acc {
	async getUser(username: string): Promise<string | UserData> {
		const user: UserData | null = await usersColl.findOne<UserData>({ "username": username });
		if (!user)
			return "notExists";
		else return user;
	}

	/** get just the public stuff */
	async getUserPublic(username: string, includeProfile: true): Promise<FullUser | string>
	async getUserPublic(username: string, includeProfile: false): Promise<User | string>
	async getUserPublic(username: string, includeProfile = true): Promise<FullUser | User | string> {
		const user: (User & Partial<UserData>) | null = await usersColl.findOne<UserData>({ "username": username });
		if (!user)
			return "notExists";
		else {
			delete user.secure;
			if (!includeProfile)
				delete user.profile;
			return user;
		}
	}

	async addUser(data: any, username: string = ''): Promise<true | string> {
		const user = await usersColl.findOne({ "username": username })
		if (user)
			return "exists";
		try {
			usersColl.insertOne(data);
		} catch (_e) {
			return 'fail'
		}
		return true
	}

	async editUser(data: any, username: string): Promise<true | string> {
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
	}

	async removeUser(username: string): Promise<true | string> {
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
	}

	async verify(token: string): Promise<string | UserStatus> {
		const user = await usersColl.findOne({ "secure.token": token })
		if (!user || user.deleted)
			return "notExists"
		if (user.banned_until > Math.round(Date.now()))
			return { "banned": true, "username": user["username"], "bot": user["bot"] }
		else
			return { "banned": false, "username": user["username"], "bot": user["bot"] }
	}

	async verifyPswd(username: string, password: string): Promise<string | {token: string, bot: boolean}> {
		const user = await usersColl.findOne<UserData>({ "username": username })
		if (!user)
			return "notExists"
		if (!verify(password, user.secure.password))
			return "unauthorized"
		else if (user["banned_until"] > Math.round(Date.now()))
			return "banned"
		else
			return { "token": user.secure.token, "bot": user.bot }
	}

	async get_ban(username: string): Promise<string | {banned_until: number, ban_reason: string}> {
		const user = await usersColl.findOne({ "username": username })
		if (!user)
			return "notExists"
		return { "banned_until": user["banned_until"], "ban_reason": user["secure"]["ban_reason"] }
	}

	async get_perms(username: string): Promise<string | string[]> {
		const user = await usersColl.findOne({ "username": username })
		if (!user)
			return "notExists"
		return user["permissions"]
	}

	/*
	def get_author(username):
		user = usersd.find_one({"username": username, "$nor": [{"deleted": True}]})
		if not user:
			return "notExists"
		else:
			del user["secure"]
			del user["profile"]
			return user*/
	async get_author(username: string): Promise<string | User> {
		const user: null | (User & Partial<UserData>) = await usersColl.findOne<UserData>({username, "$nor": [{deleted: true}]});
		if (!user)
			return 'notExists';
		delete user.secure;
		delete user.profile;
		return user as User;
	}
}
const acc = new Acc()
class Posts {
	async get_recent(amount=75): Promise<Post[]> {
		const posts: PostData[] = await postsColl.find<PostData>({}).sort("created", -1).limit(amount).toArray()
		const newPosts: Post[] = await Promise.all(posts
			.map(async post => {
				const user = await acc.getUser(post.author)
				let data: User | emptyObj;
				if (typeof(user) != 'object')
					data = {}
				else {
					const userData = user as User & Partial<UserData>;
					delete userData.secure
					// delete userData.profile;
					data = userData;
				}
				const newPost: Post = {
					...post,
					author: data,
					replies: await Promise.all(post.replies
						.map<Promise<ReplyPost>>(async (j) => {
							const user = await acc.getUser(j.author)
							let data: User | emptyObj;
							if (typeof(user) != 'object')
								data = {}
							else {
								const userData = user as User & Partial<UserData>;
								delete userData.secure
								// delete userData.profile;
								data = userData;
							}
							return {
								...j,
								author: data
							} as ReplyPost
						})
					)
				}
				return newPost as Post
			}));
		return newPosts;
	}
	async get_page(offset=0): Promise<Post[]> {
		const posts: PostData[] = await postsColl.find<PostData>({}).sort("created", -1).skip(offset).limit(75 + offset).toArray()
		const newPosts: Post[] = await Promise.all(posts
			.map(async post => {
				const user = await acc.getUser(post.author)
				let data: User | emptyObj;
				if (typeof(user) != 'object')
					data = {}
				else {
					const userData = user as User & Partial<UserData>;
					delete userData.secure
					delete userData.profile;
					data = userData;
				}
				const newPost: Post = {
					...post,
					author: data,
					replies: await Promise.all(post.replies.map<Promise<ReplyPost>>(async (j) => {
						const user = await acc.getUser(j.author)
						let data: User | emptyObj;
						if (typeof(user) != 'object')
							data = {}
						else {
							const userData = user as User & Partial<UserData>;
							delete userData.secure
							// delete userData.profile;
							data = userData;
						}
						return {...j, author: data} as ReplyPost
					}))
				}
				return newPost as Post
			}));
		return newPosts;
	}
	async get_by_id(post_id: string, supply_author?:false): Promise<string | PostData>
	async get_by_id(post_id: string, supply_author:true): Promise<string | Post>
	async get_by_id(post_id: string, supply_author=false): Promise<string | Post | PostData> {
		//@ts-ignore: 
		const post: PostData = await postsColl.findOne<PostData>({"_id": post_id})
		if (!post)
			return "notExists"
		if (supply_author) {
			let data: any = await acc.getUser(post.author)
			if (typeof data != 'object')
				data = {}
			else {
				delete data.secure
				delete data.profile
			}
			post.author = data
			let incr = -1
			for (const j of post.replies) {
				incr += 1;
				data = await acc.getUser(j.author);
				if (typeof data != 'object')
					data = {}
				else {
					delete data.secure
					delete data.profile
				}
				post.replies[incr].author = data
			}
		}
		return post
	}

	async add(data: Omit<PostData, '_id'>) {
		try{
			await postsColl.insertOne(data)
		} catch (_e) {
			return "fail"
		}
		return true
	}
};
const posts = new Posts();
class Inbox {
	async get_recent(amount=75): Promise<InboxPost[]> {
		return await inboxColl.find<InboxPost>({}).sort("created", -1).limit(amount).toArray()
	}
	
	//TODO - types for inbox posts
	add(data: Omit<InboxPost, '_id'>) {
		try {
			inboxColl.insertOne(data)
		} catch (e) {
			return "fail"
		}
		return true
	}
}
const inbox = new Inbox()
//!SECTION

const util = {
	error(code: string, listener: string | undefined, data: any = {}) {
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
	fieldCheck(expects: Record<string, { range: [number, number], types: string[] }>, gets: Record<string, any>) {
		for (const i in expects) {
			if (!gets[i])
				return "malformedJson"
			if (typeof (gets[i]) == 'string' || Array.isArray(gets[i])) {
				let yes = false;
				if (!expects[i].types.includes(typeof (gets[i]))
					&& expects[i].types.includes('array')
					&& Array.isArray(gets[i]))
					yes = true;
				if ((gets[i].length &&
					(
						gets[i].length > expects[i].range[1] ||
						gets[i].length < expects[i].range[0]
					)) ||
					(!expects[i].types.includes(typeof (gets[i])) && !yes))
					return "lengthInvalid"
			}
		}
		return true
	},
	ulist() {
		for (const id in connecitons) {
			connecitons[id].send(JSON.stringify({
				command: "ulist",
				ulist: ulist
			}))
		}
	},
	async authorize(username: string, conn_id: string, socket: WebSocket, client: string | undefined, bot: boolean): Promise<User | string> {
		// (todo from helium)
		// TODO: statuses
		if (!client || !client.match || !client.match(/^[a-zA-Z0-9-_. ]{1,50}$/))
			client = "";
		
		ulist[username] = { "client": client, "status": "", "bot": bot }
		client_data[conn_id] = { "username": username, "client": client, "websocket": socket, "connected": Date.now(), "bot": bot }
		//TODO: ips
		// if ips_by_client[websocket]:
		//     db.acc.add_ip(ips_by_client[websocket], username)
		const data: (User & Partial<UserData>) | string = await acc.getUser(username)
		if (typeof data != 'string')
			delete data.secure
		return data as User | string
	},
	/*
	def author_data(username):
		data = db.acc.get(username)
		del data["secure"]
		del data["profile"]
		return data*/
	async author_data(username: string): Promise<User | string> {
		const data: (User & Partial<UserData>) | string = await acc.getUser(username);
		if (typeof data != 'string') {
			delete data.secure;
			// delete data.profile;
		}
		return data as User | string;
	},
	async greeting() {
		return JSON.stringify({
			"command": "greet",
			"version": config.version,
			"ulist": ulist,
			"messages": await posts.get_recent(),
			"locked": locked,
			"server_contributors": config.contributors
		})
	},
	greetingMaintenance(message: string) {
		return JSON.stringify({
			"command": "greet",
			"version": config.version,
			"ulist": ulist,
			"messages": [
				{
					_id: '0',
					attachments: [],
					author: {
						_id: '0',
						avatar: null,
						banned_until: 0,
						bot: true,
						created: 0,
						display_name: 'Administrator',
						permissions: [],
						username: 'server',
						deleted: false,
						verified: true
					},
					content: message,
					created: 0,
					replies: []
				}
			] as Post[],
			"locked": locked,
			"server_contributors": config.contributors
		})
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

const ulist: Record<string, any> = {}
const client_data: Record<string, any> = {}

const ratelimits: Record<string, number> = {}

const clients: WebSocket[] = []
const ips_by_client = {}

// const invite_codes = []
// deno-lint-ignore prefer-const
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

const connecitons: Record<string, WebSocket> = {}

function broadcast(sockets: WebSocket[], data: string | ArrayBufferLike | Blob | ArrayBufferView) {
	for (const socket of sockets) {
		socket.send(data)
	}
}

Deno.serve({
	port: +(Deno.env.get('PORT') as string),
	handler: async (request) => {
		if (request.headers.get("upgrade") !== "websocket") {
			// If the request is a normal HTTP request,
			// we serve the client HTML file.
			const file = await Deno.open("./index.html", { read: true });
			return new Response(file.readable);
		}
		const { socket, response } = Deno.upgradeWebSocket(request);

		const id = idThing++;

		connecitons[String(id)] = socket;

		clients.push(socket)

		socket.onopen = async () => {
			console.log("CONNECTED");
			socket.send(await util.greeting())
		};
		socket.onmessage = async (event) => {
			if (typeof event.data != 'string')
				return;
			const message = String(event.data)
			// console.log(ratelimits[String(id)])
			// console.log(Date.now())
			// console.log(Date.now() > ratelimits[String(id)])
			if (ratelimits[String(id)] > Date.now()) {
				let lst = undefined
				try {
					const r = JSON.parse(message)
					if (!r.listener)
						r.listener = undefined
					lst = r.listener
					// deno-lint-ignore no-empty
				} catch (_e) { }
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
			if (!r.command) {
				socket.send(util.error("malformedJson", listener))
				return;
			}
			//TODO: move into separate files
			const commands: Record<string, () => Promise<void>> = {
				'register': async () => {
					const fieldCheck = util.fieldCheck({
						username: { range: [1, 21], types: ['string'] },
						password: { range: [8, 256], types: ['string'] },
						invite_code: { range: [0, 199], types: ['string', 'undefined'] }
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
							"password": hash(r.password),
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
				},
				'login_pswd': async () => {
					const fieldCheck = util.fieldCheck({
						username: { range: [1, 21], types: ['string'] },
						password: { range: [8, 256], types: ['string'] }
					}, r)
					if (fieldCheck != true)
						return socket.send(util.error(fieldCheck, listener))
					if (client_data[String(id)])
						return socket.send(util.error("authed", listener));
					if (locked) {
						const perms = await acc.get_perms(r.username)
						if (!Array.isArray(perms))
							return socket.send(util.error("lockdown", listener))
						if (perms.includes('LOCK'))
							return socket.send(util.error("lockdown", listener))
					}
					r.username = r.username.toLowerCase();
					const valid = await acc.verifyPswd(r.username, r.password)
					if (typeof valid != 'string') {
						const userdata = await util.authorize(
							r.username,
							String(id),
							socket,
							undefined,
							valid.bot);
						socket.send(JSON.stringify({
							error: false,
							token: valid.token,
							user: userdata,
							listener
						}))
						util.ulist()
						return;
					} else if (valid == "banned")
						return socket.send(util.error(valid, listener, await acc.get_ban(r.username)))
					else
						return socket.send(util.error(valid, listener))
				},
				'login_token': async () => {
					const fieldCheck = util.fieldCheck({ "token": { "range": [32, 128], "types": ['string'] } }, r)
					if (fieldCheck != true)
						return socket.send(util.error(fieldCheck, listener))
					if (client_data[String(id)])
						return socket.send(util.error("authed", listener))
					if (locked)
						return socket.send(util.error("lockdown", listener))
					const valid = await acc.verify(r["token"])
					if (typeof valid != 'string') {
						if (valid.banned)
							return socket.send(util.error("banned", listener, acc.get_ban(valid["username"])))
						const userdata = await util.authorize(valid["username"], String(id), socket, undefined, valid["bot"])
						socket.send(JSON.stringify({ "error": false, "user": userdata, "listener": listener }))
						return util.ulist()
					}
					return socket.send(util.error(valid, listener))
				},
				'get_user': async () => {
					const fieldCheck = util.fieldCheck({ "username": { "range": [1, 21], "types": ['string'] } }, r)
					if (fieldCheck != true)
						return socket.send(util.error(fieldCheck, listener))
					if (!client_data[String(id)])
						return socket.send(util.error("unauthorized", listener))
					const valid = await acc.verify(r["token"])
					if (typeof valid != 'string') {
						if (valid.banned)
							return socket.send(util.error("banned", listener, acc.get_ban(valid["username"])))
						const userdata = util.authorize(valid["username"], String(id), socket, undefined, valid["bot"])
						socket.send(JSON.stringify({ "error": false, "user": userdata, "listener": listener }))
						return util.ulist()
					}
					return socket.send(util.error(valid, listener))
				},
				'get_post': async () => {
					const fieldCheck = util.fieldCheck({
						id: {range: [8,128], types: ['string']}
					}, r)
					if (fieldCheck != true)
						return socket.send(util.error(fieldCheck, listener))
					if (!client_data[String(id)])
						return socket.send(util.error("unauthorized", listener))
					const data = await posts.get_by_id(r.id, true)
					if (typeof data == 'string')
						return socket.send(util.error(data, listener))
					return socket.send(JSON.stringify({error: false, post: data, listener: listener}))
				},
				'get_posts': async () => {
					const fieldCheck = util.fieldCheck({offset: {types: ['number'], range: [-Infinity, Infinity]}}, r)
					if (fieldCheck != true)
						return socket.send(util.error(fieldCheck, listener))
					if (!client_data[String(id)])
						return socket.send(util.error("unauthorized", listener))
					const data = await posts.get_page(r["offset"])
					if (typeof data == 'string')
						return await socket.send(util.error(data, listener))
					return await socket.send(JSON.stringify({"error": false, "posts": data, "listener": listener}))
				},
				/*TODO: set_property, gen_invite, reset_invites, force_kick, ban, lock (finish)
				 * banish_to_the_SHADOW_REALM, get_ips, , post_inbox
				 */
				"get_inbox": async () => {
					if (!client_data[String(id)])
						return socket.send(util.error("unauthorized", listener))
					const data = await inbox.get_recent()
					socket.send(JSON.stringify({"error": false, "inbox": data, "listener": listener}))
				},
				'post': async () => {
					const fieldCheck = util.fieldCheck({
						content: {range: [1,3000], types: ['string']},
						replies: {range: [0,6], types: ['array']},
						attachments: {range: [0,6], types: ['array']}
					}, r)
					if (fieldCheck != true)
						return socket.send(util.error(fieldCheck, listener))
					if (!client_data[id])
						return socket.send(util.error("unauthorized", listener))
					//TODO - lc
					// if "chat" in r and r["chat"] == "livechat":
					//     attachments = []
					//     for i in r["attachments"]:
					//         if urlparse(i).hostname in attachment_whitelist:
					//             attachments.append(i)
					//     if len(r["content"]) == 0 and len(r["attachments"]) == 0:
					//         await websocket.send(util.error("lengthInvalid", listener))
					//         continue
					//     username = client_data[str(websocket.id)]["username"]
					//     author = util.author_data(username)
					//     replies = []
					//     for i in r["replies"]:
					//         post = db.posts.get_by_id(i)
					//         if type(post) == dict and i not in replies:
					//             replies.append(post)
					//     data = {
					//         "_id": str(uuid.uuid4()),
					//         "created": time.time(),
					//         "content": r["content"],
					//         "replies": replies,
					//         "attachments": attachments,
					//         "author": username
					//     }
					//     # posted = db.posts.add(data)
					//     # if posted != True:
					//     #     await websocket.send(util.error(fc, listener))
					//     #     continue
					//     data["author"] = author
					//     data["origin"] = "livechat"
					//     incr = -1
					//     for j in data["replies"]:
					//         incr += 1
					//         reply_author = db.acc.get_author(j["author"])
					//         if type(reply_author) != dict:
					//             reply_author = {}
					//         data["replies"][incr]["author"] = reply_author
					//     broadcast(clients, json.dumps({
					//         "command": "new_post",
					//         "origin": "livechat",
					//         "data": data
					//     }))
					//     await websocket.send(json.dumps({"error": False, "listener": listener}))
					//     continue
					const attachments = []
					for (const i of r["attachments"]) {
						try {
							if (attachment_whitelist.includes(new URL(i).hostname))
								attachments.push(i)
						// deno-lint-ignore no-empty
						} catch (_) {}
					}
					if (r.content.length == 0 && r.attachments.length == 0)
						return socket.send(util.error("lengthInvalid", listener));
					const username = client_data[String(id)].username
					const author = await util.author_data(username)
					const replies: PostData[] = []
					for (const i of r["replies"]) {
						const post = await posts.get_by_id(i)
						if (typeof post != 'string' && !replies.includes(i))
							replies.push(post)
					}
					const data: PostData = {
						_id: String(uuid.v4()),
						created: Date.now() / 1000,
						content: r.content,
						replies: replies,
						attachments: attachments,
						author: username,
						reactions: {}
					}
					const posted = await posts.add(data)
					if (posted != true)
						return socket.send(util.error(posted, listener))
					const newData: Post = {
						...data,
						author: typeof author == 'string' ? {} : author,
						replies: await Promise.all(data.replies.map<Promise<ReplyPost>>(async j => {
							const reply_author = await acc.get_author(j["author"])
							return {
								...j,
								author: typeof reply_author == 'object' ? reply_author : {}
							}
						}))
					}
					broadcast(clients, JSON.stringify({
						"command": "new_post",
						"data": newData
					}))
					return socket.send(JSON.stringify({"error": false, "listener": listener}))
				}
			}
			if (!commands[r.command])
				return socket.send(util.error("malformedJson", listener))
			await commands[r.command]()
		};
		socket.onclose = () => {
			clients.splice(clients.indexOf(socket));
			delete connecitons[String(id)];
		}
		socket.onerror = () => {
			clients.splice(clients.indexOf(socket));
			delete connecitons[String(id)];
		}

		return response;
	},
});
