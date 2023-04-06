"use strict";

const mqtt = require("mqtt");
const crypto = require("crypto");
const pem2jwk = require("pem2jwk");
const Parser = require("binary-parser").Parser;
const CRC32 = require("crc-32");
const zlib = require("zlib");
const {EventEmitter2} = require("eventemitter2");
const rr = new EventEmitter2();

const rr_rsa = require("./Utils/rsa/index");

let seq = 1;
let random = 4711; // Should be initialized with a number 0 - 1999?

const nonce = crypto.randomBytes(16);

// This value is stored hardcoded in librrcodec.so, encrypted by the value of "com.roborock.iotsdk.appsecret" from AndroidManifest.xml.
const salt = "TXdfu$jyZ#TZHsg4";


const mqttMessageParser = new Parser()
	.endianess("big")
	.string("version", {
		length: 3
	})
	.uint32("seq")
	.uint32("random")
	.uint32("timestamp")
	.uint16("protocol")
	.uint16("payloadLen")
	.buffer("payload", {
		length: "payloadLen"
	})
	.uint32("crc32");

const protocol301Parser = new Parser()
	.endianess("little")
	.string("endpoint", {
		length: 15,
		stripNull: true
	})
	.uint8("unknown1")
	.uint16("id")
	.buffer("unknown2", {
		length: 6
	});

const protocol301SSLParser = new Parser()
	.endianess("little")
	.string("endpoint", {
		length: 64,
		stripNull: true
	})
	.buffer("data", {
		length: 6
	});


let mqttUser;
let mqttPassword;
let client;
let endpoint;
let rriot;
let devices;
let localKeys;

class roborock_mqtt_connector {
	constructor(adapter) {
		this.adapter = adapter;

		this.keys = rr_rsa.generateRSAKeys();
		this.pub = JSON.parse(this.keys.pub);
		this.pri = JSON.parse(this.keys.pri);
	}

	initUser(userdata, homedata) {
		rriot = userdata.rriot;

		devices = homedata.devices.concat(homedata.receivedDevices);
		localKeys = new Map(devices.map(device => [device.duid, device.localKey]));
		endpoint = this.md5bin(rriot.k).subarray(8, 14).toString("base64"); // Could be a random but rather static string. The app generates it on first run.
		mqttUser = this.md5hex(rriot.u + ":" + rriot.k).substring(2, 10);
		// mqttUser = "52a9b8f4";
		mqttPassword = this.md5hex(rriot.s + ":" + rriot.k).substring(16);
		client = mqtt.connect(rriot.r.m, {
			username: mqttUser,
			password: mqttPassword,
			keepalive: 30
		});
	}

	async initMQTT_Subscribe() {
		const timeout = setTimeout(async () => {
			this.adapter.log.error("Connection timed out! Deleting UserData and trying again");
			await this.adapter.deleteStateAsync("UserData");
			this.adapter.restart();
		}, 5000);

		await client.on("connect", (result) => {
			if (typeof (result) != "undefined") {
				client.subscribe(`rr/m/o/${rriot.u}/${mqttUser}/#`, (err, granted) => {
					if (err) {
						this.adapter.log.error("Failed to subscribe to Roborock MQTT Server! Error: " + err + ", granted: " + JSON.stringify(granted));
					}
				});
				// client.subscribe(`rr/m/i/${rriot.u}/${mqttUser}/#`, (err, granted) => {
				// 	if (err) {
				// 		this.adapter.log.error("Failed to subscribe to input Roborock MQTT Server! Error: " + err + ", granted: " + JSON.stringify(granted));
				// 	}
				// });


				// for sniffing traffic of the android app
				// client.subscribe(`rr/m/o/${rriot.u}/52a9b8f4/#`, (err, granted) => {
				// 	if (err) {
				// 		this.adapter.log.error("Failed to subscribe to Roborock MQTT Server! Error: " + err + ", granted: " + JSON.stringify(granted));
				// 	}
				// });
				// client.subscribe(`rr/m/i/${rriot.u}/52a9b8f4/#`, (err, granted) => {
				// 	if (err) {
				// 		this.adapter.log.error("Failed to subscribe to input Roborock MQTT Server! Error: " + err + ", granted: " + JSON.stringify(granted));
				// 	}
				// });
				clearTimeout(timeout);
			}
		});

		await client.on("error", (result) => {
			this.adapter.log.error("MQTT connection error: " + result);
		});

		await client.on("close", () => {
			this.adapter.log.warn("MQTT connection close.");
		});

		await client.on("reconnect", () => {
			this.adapter.log.warn("MQTT connection reconnect.");
		});

		await client.on("offline", (result) => {
			this.adapter.log.error("MQTT connection offline: " + result);
		});
	}

	_decodeMsg(msg, localKey) {
		// Do some checks before trying to decode the message.
		if (msg.toString("latin1", 0, 3) !== "1.0") {
			throw new Error("Unknown protocol version");
		}
		const crc32 = CRC32.buf(msg.subarray(0, msg.length - 4)) >>> 0;
		const expectedCrc32 = msg.readUint32BE(msg.length - 4);
		if (crc32 != expectedCrc32) {
			throw new Error(`Wrong CRC32 ${crc32}, expected ${expectedCrc32}`);
		}

		const data = mqttMessageParser.parse(msg);
		delete data.payloadLen;
		const aesKey = this.md5bin(this._encodeTimestamp(data.timestamp) + localKey + salt);
		const decipher = crypto.createDecipheriv("aes-128-ecb", aesKey, null);
		data.payload = Buffer.concat([decipher.update(data.payload), decipher.final()]);
		return data;
	}

	async isArray(what) {
		return Object.prototype.toString.call(what) === "[object Array]";
	}

	async initMQTT_Message() {
		this.adapter.log.info("MQTT initialized");

		client.on("message", (topic, message) => {
			const duid = topic.split("/").slice(-1)[0];
			const data = this._decodeMsg(message, localKeys.get(duid));
			// this.adapter.log.debug("MESSAGE RECEIVED!!!!! " + JSON.stringify(JSON.parse(JSON.stringify(data))));
			// rr.emit("response.raw", duid, data);

			// for (const row in JSON.parse(data.payload).dps["102"])
			// {
			// 	this.adapter.log.debug("Mqtt test: " + topic + ": " + typeof(row));
			// }

			// this.adapter.log.debug("Raw data test: " + JSON.stringify(data.payload));
			// this.adapter.log.debug("Raw data test: " + JSON.stringify(data.payload));
			// this.adapter.log.debug(typeof(data.payload));
			// for (const row in data.payload)
			// {
			// 	this.adapter.log.debug(row + ":" + typeof(row));
			// }

			// this.adapter.log.debug("Protocol: " + data.protocol);
			if (data.protocol == 102) {
				// sometimes JSON.parse(data.payload).dps["102"] is not a JSON. Check for this!
				let dps;
				if (typeof (JSON.parse(data.payload).dps["102"]) != "undefined") {
					dps = JSON.parse(JSON.parse(data.payload).dps["102"]);
				}
				else {
					dps = JSON.parse(data.payload).dps;
				}
				this.adapter.log.debug("dps debug: " + JSON.stringify(dps));

				if (dps.result || dps.error) {
					rr.emit("response.102", duid, dps.id, dps.result || dps.error);
				}
				else {
					rr.emit("foreign.message", duid, dps);
				}
				this.adapter.log.debug("data.payload 102: " + JSON.stringify(data.payload));
			} else if (data.protocol == 301) {
				const data2 = protocol301Parser.parse(data.payload.subarray(0, 24));
				const data3 = protocol301Parser.parse(data.payload.subarray(24, 48));

				this.adapter.log.debug("data2 " + JSON.stringify(data2));
				this.adapter.log.debug("data3 " + JSON.stringify(data3));

				// this.adapter.log.debug("result.payload: " + data.payload);
				this.adapter.log.debug("result.payload.subarray(0, 8): " + data.payload.subarray(0, 8));
				if (data.payload.subarray(0, 8) == "ROBOROCK") {
					// const actualEncryptedPayload = data.payload.subarray(64);
					// const data2 = protocol301SSLParser.parse(data.payload.subarray(24, 48));

					// this.adapter.log.debug("raw 301 data2: " + JSON.stringify(data2));
					// // this.adapter.log.debug("raw 301 ssl: " + actualEncryptedPayload);

					// const test = JSON.stringify(JSON.stringify(data.payload.slice(0, 32).toString("utf-8")));
					// this.adapter.log.debug("ssl 301 test: " + test);

					// const iv = Buffer.alloc(16, 0);
					// const decipher = crypto.createDecipheriv("aes-128-cbc", nonce, iv);
					// let decrypted = Buffer.concat([decipher.update(data.payload.subarray(64)), decipher.final()]);
					// decrypted = zlib.gunzipSync(decrypted);
					// this.adapter.log.debug("ssl 301 decipher: " + JSON.stringify(decrypted));

					// const encryptedDataLength = data.payload.length; // The length of the encrypted data
					// this.adapter.log.debug("ssl 301 encryptedDataLength: " + encryptedDataLength);
					// const encryptedData = data.payload.slice(2048, encryptedDataLength);
					// this.adapter.log.debug("ssl 301 encryptedData: " + JSON.stringify(encryptedData));


					// const iv = Buffer.alloc(16, 0);
					// const decipher = crypto.createDecipheriv("aes-256-cbc", ssl_data.privateKey, iv);
					// let decrypted = Buffer.concat([decipher.update(data.payload.subarray(24)), decipher.final()]);
					// decrypted = zlib.gunzipSync(decrypted);
					// this.adapter.log.debug("ssl 301 encryptedData: " + decrypted);

					// this.adapter.log.debug("rsa: " + JSON.stringify(ssl_data));

					// this.adapter.log.debug("cipher_n: " + JSON.stringify(cipher_n));

					// const iv = Buffer.alloc(16, 0);
					// const decipher = crypto.createDecipheriv("aes-128-ecb", cipher_n, null);
					// let decrypted = Buffer.concat([decipher.update(data.payload.subarray(64)), decipher.final()]);
					// decrypted = zlib.gunzipSync(decrypted);
					// this.adapter.log.debug("message: " + JSON.stringify(message.toString("hex")));

					// const testDecode = this._decodeMsg(data.payload.subarray(24), ssl_data.n);
					// this.adapter.log.debug("testDecode: " + JSON.stringify(testDecode));

					this.adapter.log.debug("data.payload photo: " + JSON.stringify(data.payload));
					// this.adapter.log.debug("data.payload base64 photo: " + JSON.stringify(Buffer.from(data.payload, "base64")));
					this.adapter.log.debug("data.payload.subarray(56): " + JSON.stringify(data.payload.subarray(56)));
					this.adapter.log.debug("data.payload.toString(\"hex\"): " + data.payload.subarray(56).toString("hex"));

					// const decrypted = this.decryptWithPrivateKey(ssl_data.privateKey, data.payload.subarray(24));


					// const iv = Buffer.alloc(16, 0);
					// const decipher = crypto.createDecipheriv("aes-128-cbc", nonce, iv);
					// this.adapter.log.debug("data.payload.subarray(72).length: " + data.payload.subarray(72).length);
					// let decrypted = Buffer.concat([decipher.update(data.payload.subarray(72)), decipher.final()]);
					// decrypted = zlib.gunzipSync(decrypted);

					// this.adapter.log.debug("rsa: " + JSON.stringify(decrypted));



					// const rr_rsa_decrypt_test = rr_rsa.decryptHexStringWithPrivateKey(data.payload.toString("hex"), JSON.stringify(this.pri));
					const rr_rsa_decrypt_test = rr_rsa.decryptBytesWithPrivateKey(data.payload.subarray(56), JSON.stringify(this.pri));
					this.adapter.log.debug("rr_rsa_decrypt_test: " + JSON.stringify(rr_rsa_decrypt_test));

					this.adapter.log.debug("data.payload.length: " + (data.payload.length - 56));


					// const rsaKey = {
					// 	"kty": "RSA",
					// 	"n": this.pri.n,
					// 	"e": this.pri.e,
					// 	"d": this.pri.d,
					// 	"p": this.pri.p,
					// 	"q": this.pri.q,
					// 	"dp": this.pri.dmp1,
					// 	"dq": this.pri.dmq1,
					// 	"qi": this.pri.coeff
					// };

					// jose.JWK.asKey(rsaKey, "json").then(jwkKey => {
					// 	const pemKey = jwkKey.toPEM(true); // Export the private key to PEM format

					// 	const key = new NodeRSA();
					// 	key.importKey(pemKey, "private");
					// 	key.setOptions({encryptionScheme: "pkcs1"});

					// 	const base64Data = data.payload.subarray(56);
						// const dataToDecrypt = Buffer.from(base64Data, "base64");
					// 	this.adapter.log.debug("dataToDecrypt: " + dataToDecrypt);

					// 	const decrypted = key.decrypt(dataToDecrypt, "utf8");
					// 	this.adapter.log.debug("Decrypted: " + decrypted);
					// }).catch(err => {
					// 	this.adapter.log.error(err);
					// });
					// const pemKey = jose.JWK.asKey(rsaKey, "pem");

					// const key = new NodeRSA();
					// key.importKey(this.pri, "components-private");
					// key.importKey(pemKey, "json");

					// Now you can use your key for decryption
					// const decrypted = key.decrypt(data.payload.subarray(56), "utf8");
					// console.log("Decrypted: " + decrypted);

					// rr.emit("response.301", duid, null, decrypted);
					rr.emit("response.301", duid, null, data.payload); // place holder until decryption is possible so this does not time out
				}
				else if (endpoint.startsWith(data2.endpoint)) {
					const iv = Buffer.alloc(16, 0);
					const decipher = crypto.createDecipheriv("aes-128-cbc", nonce, iv);
					let decrypted = Buffer.concat([decipher.update(data.payload.subarray(24)), decipher.final()]);
					decrypted = zlib.gunzipSync(decrypted);
					// this.adapter.log.debug("raw 301: " + decrypted);
					rr.emit("response.301", duid, data2.id, decrypted);
				}
			}
		});


		rr.on("response.raw", (duid, result) => {
			// this.adapter.log.debug("raw: " + JSON.stringify(result));
			this.adapter.log.debug("typeof raw: " + typeof(result));
			this.adapter.log.debug("result: " + JSON.stringify(result));
			try {
				if (result.payload) {
					if (result.protocol == 101) {
						this.adapter.log.debug("raw 101: " + JSON.stringify(JSON.parse(JSON.parse(result.payload).dps["101"])));
					}
					else if (result.protocol == 102) {
						// this.adapter.log.debug("raw: " + JSON.stringify(JSON.parse(result.payload)));
						this.adapter.log.debug("raw 102: " + JSON.stringify(JSON.parse(JSON.parse(result.payload).dps["102"])));
					}
					else if (result.protocol == 301) {
						const test = result.payload.slice(0, 64).toString("utf-8");
						this.adapter.log.debug("ssl 301 test: " + test);

						this.adapter.log.debug("result.payload.subarray(0, 8): " + result.payload.subarray(0, 8));
						if (result.payload.subarray(0, 8) == "ROBOROCK") {
							const actualEncryptedPayload = result.payload.subarray(64);
							const data2 = protocol301SSLParser.parse(result.payload.subarray(24, 48));

							this.adapter.log.debug("raw 301 data2: " + JSON.stringify(data2));
							this.adapter.log.debug("raw 301 ssl: " + actualEncryptedPayload);
						}
						else {
							const data2 = protocol301Parser.parse(result.payload.subarray(0, 24));
							if (endpoint.startsWith(data2.endpoint)) {
								const iv = Buffer.alloc(16, 0);
								const decipher = crypto.createDecipheriv("aes-128-cbc", nonce, iv);
								let decrypted = Buffer.concat([decipher.update(result.payload.subarray(24)), decipher.final()]);
								decrypted = zlib.gunzipSync(decrypted);
								// this.adapter.log.debug("raw 301: " + JSON.stringify(decrypted));
								this.adapter.log.debug("raw 301: " + decrypted);
							}
						}
					}
				}
			}
			catch (e) {
				this.adapter.log.error("Failed to parse raw response. Error: " + e);
				this.adapter.log.debug("failed raw: " + JSON.stringify(result));
			}
		});

		rr.on("foreign.message", (duid, result) => {

			for (const attribute in result) {
				this.adapter.log.debug("foreign.message attribute: " + attribute + " with value: " + JSON.stringify(result[attribute]));
				switch(attribute) {
					case "121":
						if (this.adapter.isCleaning(result[attribute])) {
							this.adapter.startMapUpdater(duid);
						}
						else {
							this.adapter.stopMapUpdater(duid);
						}
				}
			}
		});
	}

	_encodeTimestamp(timestamp) {
		const hex = timestamp.toString(16).padStart(8, "0").split("");
		return [5, 6, 3, 7, 1, 2, 0, 4].map(idx => hex[idx]).join("");
	}

	createRequestId() {
		let requestId = Math.floor(Math.random() * 9000) + 1000;
		while (this.adapter.messageQueue.has(requestId))
		{
			requestId = Math.floor(Math.random() * 9000) + 1000;
		}

		return requestId;
	}


	async sendRequest(deviceId, method, params, secure = false, photo = false) {
		const timestamp = Math.floor(Date.now() / 1000);
		const requestId = this.createRequestId();
		// this.adapter.log.debug("sendRequest started with: " + requestId);

		if (photo) {
			params.endpoint = endpoint;
			params.security = {
				"cipher_suite": 1,
				"pub_key": this.pub
				// "pub_key": {
				// 	"e": "10001",
				// 	"n": this.pri.n,
				// }
			};


			this.adapter.log.debug("rsa pub: " + JSON.stringify(this.pub));
			this.adapter.log.debug("rsa pri: " + JSON.stringify(this.pri));
			this.adapter.log.debug("rsa n: " + JSON.stringify(this.pri.n));
		}

		const inner = {
			id: requestId,
			method: method,
			params: params
		};
		if (secure) {
			if (photo) {
				// does not look like this is used when it's a photo. Might be wrong an i just couldn't figure out how to decipher this yet
				// inner.security = {
				// 	endpoint: endpoint,
				// 	nonce: nonce.toString("hex").toUpperCase()
				// };
			}
			else {
				inner.security = {
					endpoint: endpoint,
					nonce: nonce.toString("hex").toUpperCase()
				};
			}
		}
		const payload = JSON.stringify({
			t: timestamp,
			dps: {
				"101": JSON.stringify(inner)
			}
		});

		return new Promise((resolve, reject) => {
			const listener102 = (deviceId, id, result) => {
				if (id == requestId) {
					rr.off("response.102", listener102);
					this.adapter.clearTimeout(this.adapter.messageQueue.get(requestId)?.timeout102);
					this.adapter.clearTimeout(this.adapter.messageQueue.get(requestId)?.timeout102);
					(this.adapter.messageQueue.get(requestId) || {}).timeout102 = null;
					this.checkAndClearRequest(requestId);

					if (result.code) {
						reject(new Error("There was an error processing the request with id " + requestId + " error: " + JSON.stringify(result)));
					}
					else {
						if (secure) {
							if (result[0] !== "ok") {
								reject(result);
							}
						} else {
							resolve(result);
						}
					}
				}
			};

			const timeout102 = this.adapter.setTimeout(() => {
				rr.off("response.102", listener102);
				(this.adapter.messageQueue.get(requestId) || {}).timeout102 = null;
				(this.adapter.messageQueue.get(requestId) || {}).timeout301 = null;
				this.checkAndClearRequest(requestId);
				reject(new Error("Request with id " + requestId + " timed out after 10 seconds for response.102"));
			}, 10000);

			rr.on("response.102", listener102);

			let listener301, timeout301;
			if (secure) {
				listener301 = (deviceId, id, result) => {
					if (photo) {
						this.adapter.log.debug("photo data: " + JSON.stringify(result));
						this.adapter.log.debug("typeof photo data: " + typeof(result));
						// const decryptedBuffer = crypto.privateDecrypt(ssl_data.privateKey, result.subarray(32, result.length - 4));
						// const decryptedText = decryptedBuffer.toString("utf8");

						// this.adapter.log.debug("SSL photo decrypted text: " + JSON.stringify(decryptedText));

						// const decryptedData = this.decryptWithPrivateKey(ssl_data.privateKey, result);
						// this.adapter.log.debug("SSL photo decrypted text: " + JSON.stringify(decryptedData));


						// ######################################
						// ######################################
						// ######################################
						// this should be correct. Latest attempt so uncomment this for testing
						// const rr_rsa_decrypt_test = rr_rsa.decryptBytesWithPrivateKey(result.subarray(32, result.length - 4), this.pri);
						// this.adapter.log.debug("rr_rsa_decrypt_test: " + JSON.stringify(rr_rsa_decrypt_test));

						// rr.off("response.301", listener301);
						// this.adapter.clearTimeout(this.adapter.messageQueue.get(requestId)?.timeout301);
						// (this.adapter.messageQueue.get(requestId) || {}).timeout301 = null;
						// this.checkAndClearRequest(requestId);
						// resolve(result);
						reject(new Error("Cannot decrypt photos just yet."));
					}
					else if (id == requestId) {
						this.adapter.log.debug("301 ssl debug ID: " + id);

						rr.off("response.301", listener301);
						this.adapter.clearTimeout(this.adapter.messageQueue.get(requestId)?.timeout301);
						(this.adapter.messageQueue.get(requestId) || {}).timeout301 = null;
						this.checkAndClearRequest(requestId);

						if (result.code) {
							reject(new Error("There was an error processing the request with id " + requestId + " error: " + JSON.stringify(result)));
						}
						else {
							resolve(result);
						}
					}
				};

				timeout301 = this.adapter.setTimeout(() => {
					rr.off("response.301", listener301);
					(this.adapter.messageQueue.get(requestId) || {}).timeout102 = null;
					(this.adapter.messageQueue.get(requestId) || {}).timeout301 = null;
					this.checkAndClearRequest(requestId);
					reject(new Error("Request with " + requestId + " timed out after 10 seconds for response.301"));
				}, 10000);

				rr.on("response.301", listener301);
			}

			this.adapter.messageQueue.set(requestId, { timeout102, timeout301, listener102, listener301 });

			this.adapter.log.debug("Payload sent " + JSON.stringify(payload));
			this.sendMsgRaw(deviceId, 101, timestamp, payload);
			// this.adapter.log.debug("Promise for requestId " + requestId + " created.");
		});
	}

	checkAndClearRequest(requestId) {
		const request = this.adapter.messageQueue.get(requestId);
		if (!request?.timeout102 && !request?.timeout301) {
			this.adapter.messageQueue.delete(requestId);
			// this.adapter.log.debug("Cleared messageQueue");
		}
		else {
			this.adapter.log.debug("Not clearing messageQueue. " + request.timeout102 + " - " + request.timeout301);
		}
		this.adapter.log.debug("Length of message queue: " + this.adapter.messageQueue.size);
	}

	sendMsgRaw(deviceId, protocol, timestamp, payload) {
		const localKey = localKeys.get(deviceId);
		const aesKey = this.md5bin(this._encodeTimestamp(timestamp) + localKey + salt);
		const cipher = crypto.createCipheriv("aes-128-ecb", aesKey, null);
		const encrypted = Buffer.concat([cipher.update(payload), cipher.final()]);
		const msg = Buffer.alloc(23 + encrypted.length);
		msg.write("1.0");
		msg.writeUint32BE(seq++ & 0xffffffff, 3);
		msg.writeUint32BE(random++ & 0xffffffff, 7);
		msg.writeUint32BE(timestamp, 11);
		msg.writeUint16BE(protocol, 15);
		msg.writeUint16BE(encrypted.length, 17);
		encrypted.copy(msg, 19);
		const crc32 = CRC32.buf(msg.subarray(0, msg.length - 4)) >>> 0;
		msg.writeUint32BE(crc32, msg.length - 4);
		client.publish(`rr/m/i/${rriot.u}/${mqttUser}/${deviceId}`, msg);
	}

	reconnectClient() {
		if (client) {
			try {
				client.end();
				client.reconnect();
			}
			catch (e) {
				this.adapter.log.error("Failed to reconnect with error: " + e);
			}
		}
	}

	md5hex(str) {
		return crypto.createHash("md5").update(str).digest("hex");
	}

	md5bin(str) {
		return crypto.createHash("md5").update(str).digest();
	}

	decryptWithPrivateKey(privateKeyPem, encryptedData) {
		const privateKey = crypto.createPrivateKey({
			key: privateKeyPem,
			format: "pem",
			type: "pkcs8"
		});

		const decryptedData = crypto.privateDecrypt(
			{
				key: privateKey,
				padding: crypto.constants.RSA_PKCS1_PADDING
			},
			encryptedData
		);

		return decryptedData;
	}

}

module.exports = {
	roborock_mqtt_connector,
};
