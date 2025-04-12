import { connect } from 'cloudflare:sockets';

// --- MODIFIED: Removed proxyIP and socks5Address initialization ---
let userID = '';
// let proxyIP = ''; // Removed
// let sub = '';
let subConverter = atob('U1VCQVBJLkNNTGl1c3Nzcy5uZXQ=');
let subConfig = atob('aHR0cHM6Ly9yYXcuZ2l0aHVidXNlcmNvbnRlbnQuY29tL0FDTDRTU1IvQUNMNFNTUi9tYXN0ZXIvQ2xhc2gvY29uZmlnL0FDTDRTU1JfT25saW5lX01pbmlfTXVsdGlNb2RlLmluaQ==');
let subProtocol = 'https';
let subEmoji = 'true';
// let socks5Address = ''; // Removed
// let parsedSocks5Address = {}; // Removed
let enableSocks = false; // --- MODIFIED: Forced to false ---

let noTLS = 'false';
const expire = 4102329600; //2099-12-31
// let proxyIPs; // Removed if not used elsewhere, keep declaration if needed but logic using it is removed
// let socks5s; // Removed

// --- MODIFIED: Removed go2Socks5s ---
// let go2Socks5s = [ ... ]; // Removed

let addresses = [];
let addressesapi = [];
let addressesnotls = [];
let addressesnotlsapi = [];
let addressescsv = [];
let DLS = 8;
let remarkIndex = 1; //CSV备注所在列偏移量
let FileName = atob('ZWRnZXR1bm5lbA==');
let BotToken;
let ChatID;
let proxyhosts = [];
let proxyhostsURL = '';
// let RproxyIP = 'false'; // Removed

const httpPorts = ["8080", "8880", "2052", "2082", "2086", "2095"];
let httpsPorts = ["2053", "2083", "2087", "2096", "8443"];
let 有效时间 = 7;
let 更新时间 = 3;
let userIDLow;
let userIDTime = "";
// let proxyIPPool = []; // Removed
let path = '/?ed=2560';
let 动态UUID;
let link = [];
let banHosts = [atob('c3BlZWQuY2xvdWRmbGFyZS5jb20=')];

export default {
	async fetch(request, env, ctx) {
		try {
			const UA = request.headers.get('User-Agent') || 'null';
			const userAgent = UA.toLowerCase();
			userID = env.UUID || env.uuid || env.PASSWORD || env.pswd || userID;
			if (env.KEY || env.TOKEN || (userID && !isValidUUID(userID))) {
				动态UUID = env.KEY || env.TOKEN || userID;
				有效时间 = Number(env.TIME) || 有效时间;
				更新时间 = Number(env.UPTIME) || 更新时间;
				const userIDs = await 生成动态UUID(动态UUID);
				userID = userIDs[0];
				userIDLow = userIDs[1];
			}

			if (!userID) {
				return new Response('请设置你的UUID变量，或尝试重试部署，检查变量是否生效？', {
					status: 404,
					headers: {
						"Content-Type": "text/plain;charset=utf-8",
					}
				});
			}
			const currentDate = new Date();
			currentDate.setHours(0, 0, 0, 0);
			const timestamp = Math.ceil(currentDate.getTime() / 1000);
			const fakeUserIDMD5 = await 双重哈希(`${userID}${timestamp}`);
			const fakeUserID = [
				fakeUserIDMD5.slice(0, 8),
				fakeUserIDMD5.slice(8, 12),
				fakeUserIDMD5.slice(12, 16),
				fakeUserIDMD5.slice(16, 20),
				fakeUserIDMD5.slice(20)
			].join('-');
			const fakeHostName = `${fakeUserIDMD5.slice(6, 9)}.${fakeUserIDMD5.slice(13, 19)}`;

			// --- MODIFIED: Removed proxyIP and SOCKS5 setup from env ---
			// proxyIP = env.PROXYIP || env.proxyip || proxyIP; // Removed
			// proxyIPs = await 整理(proxyIP); // Removed if proxyIPs not needed elsewhere
			// proxyIP = proxyIPs[Math.floor(Math.random() * proxyIPs.length)]; // Removed

			// socks5Address = env.SOCKS5 || socks5Address; // Removed
			// socks5s = await 整理(socks5Address); // Removed
			// socks5Address = socks5s[Math.floor(Math.random() * socks5s.length)]; // Removed
			// socks5Address = socks5Address.split('//')[1] || socks5Address; // Removed
			// if (env.GO2SOCKS5) go2Socks5s = await 整理(env.GO2SOCKS5); // Removed
			if (env.CFPORTS) httpsPorts = await 整理(env.CFPORTS);
			if (env.BAN) banHosts = await 整理(env.BAN);

			// --- MODIFIED: Simplified this section as enableSocks is always false and RproxyIP is removed ---
			// if (socks5Address) { ... } else { ... } // Logic removed or simplified

			const upgradeHeader = request.headers.get('Upgrade');
			const url = new URL(request.url);
			if (!upgradeHeader || upgradeHeader !== 'websocket') {
				if (env.ADD) addresses = await 整理(env.ADD);
				if (env.ADDAPI) addressesapi = await 整理(env.ADDAPI);
				if (env.ADDNOTLS) addressesnotls = await 整理(env.ADDNOTLS);
				if (env.ADDNOTLSAPI) addressesnotlsapi = await 整理(env.ADDNOTLSAPI);
				if (env.ADDCSV) addressescsv = await 整理(env.ADDCSV);
				DLS = Number(env.DLS) || DLS;
				remarkIndex = Number(env.CSVREMARK) || remarkIndex;
				BotToken = env.TGTOKEN || BotToken;
				ChatID = env.TGID || ChatID;
				FileName = env.SUBNAME || FileName;
				subEmoji = env.SUBEMOJI || env.EMOJI || subEmoji;
				if (subEmoji == '0') subEmoji = 'false';
				if (env.LINK) link = await 整理(env.LINK);
				let sub = env.SUB || '';
				subConverter = env.SUBAPI || subConverter;
				if (subConverter.includes("http://")) {
					subConverter = subConverter.split("//")[1];
					subProtocol = 'http';
				} else {
					subConverter = subConverter.split("//")[1] || subConverter;
				}
				subConfig = env.SUBCONFIG || subConfig;
				if (url.searchParams.has('sub') && url.searchParams.get('sub') !== '') sub = url.searchParams.get('sub');
				if (url.searchParams.has('notls')) noTLS = 'true';

				// --- MODIFIED: Removed checks for proxyip/socks5 in URL parameters ---
				// if (url.searchParams.has('proxyip')) { ... }
				// else if (url.searchParams.has('socks5')) { ... }
				// else if (url.searchParams.has('socks')) { ... }
                path = url.pathname + url.search; // Keep original path/query

				const 路径 = url.pathname.toLowerCase();
				if (路径 == '/') {
					if (env.URL302) return Response.redirect(env.URL302, 302);
					else if (env.URL) return await 代理URL(env.URL, url);
					else return new Response(JSON.stringify(request.cf, null, 4), {
						status: 200,
						headers: {
							'content-type': 'application/json',
						},
					});
				} else if (路径 == `/${fakeUserID}`) {
                    // --- MODIFIED: Pass 'false' for RproxyIP equivalent ---
					const fakeConfig = await 生成配置信息(userID, request.headers.get('Host'), sub, 'CF-Workers-SUB', 'false', url, fakeUserID, fakeHostName, env);
					return new Response(`${fakeConfig}`, { status: 200 });
				} else if (url.pathname == `/${动态UUID}/edit` || 路径 == `/${userID}/edit`) {
					const html = await KV(request, env);
					return html;
				} else if (url.pathname == `/${动态UUID}` || 路径 == `/${userID}`) {
					await sendMessage(`#获取订阅 ${FileName}`, request.headers.get('CF-Connecting-IP'), `UA: ${UA}</tg-spoiler>\n域名: ${url.hostname}\n<tg-spoiler>入口: ${url.pathname + url.search}</tg-spoiler>`);
                    // --- MODIFIED: Pass 'false' for RproxyIP equivalent ---
					const 维列斯Config = await 生成配置信息(userID, request.headers.get('Host'), sub, UA, 'false', url, fakeUserID, fakeHostName, env);
					const now = Date.now();
					//const timestamp = Math.floor(now / 1000);
					const today = new Date(now);
					today.setHours(0, 0, 0, 0);
					const UD = Math.floor(((now - today.getTime()) / 86400000) * 24 * 1099511627776 / 2);
					let pagesSum = UD;
					let workersSum = UD;
					let total = 24 * 1099511627776;
					if (userAgent && userAgent.includes('mozilla')) {
						return new Response(维列斯Config, {
							status: 200,
							headers: {
								"Content-Type": "text/html;charset=utf-8",
								"Profile-Update-Interval": "6",
								"Subscription-Userinfo": `upload=${pagesSum}; download=${workersSum}; total=${total}; expire=${expire}`,
								"Cache-Control": "no-store",
							}
						});
					} else {
						return new Response(维列斯Config, {
							status: 200,
							headers: {
								"Content-Disposition": `attachment; filename=${FileName}; filename*=utf-8''${encodeURIComponent(FileName)}`,
								//"Content-Type": "text/plain;charset=utf-8",
								"Profile-Update-Interval": "6",
								"Subscription-Userinfo": `upload=${pagesSum}; download=${workersSum}; total=${total}; expire=${expire}`,
							}
						});
					}
				} else {
					if (env.URL302) return Response.redirect(env.URL302, 302);
					else if (env.URL) return await 代理URL(env.URL, url);
					else return new Response('不用怀疑！你UUID就是错的！！！', { status: 404 });
				}
			} else {
                // --- MODIFIED: Removed checks for proxyip/socks5 in URL parameters/path for websocket requests ---
				// socks5Address = url.searchParams.get('socks5') || socks5Address;
				// if (new RegExp('/socks5=', 'i').test(url.pathname)) ...
                // else if (new RegExp('/socks://', 'i').test(url.pathname) || ...) ...
                // if (socks5Address) { ... } else { enableSocks = false; }

                // if (url.searchParams.has('proxyip')) { ... }
                // else if (new RegExp('/proxyip=', 'i').test(url.pathname)) { ... }
                // else if (new RegExp('/proxyip.', 'i').test(url.pathname)) { ... }
                // else if (new RegExp('/pyip=', 'i').test(url.pathname)) { ... }

                // enableSocks is already hardcoded to false
				return await 维列斯OverWSHandler(request);
			}
		} catch (err) {
			let e = err;
			return new Response(e.toString());
		}
	},
};

async function 维列斯OverWSHandler(request) {
	const webSocketPair = new WebSocketPair();
	const [client, webSocket] = Object.values(webSocketPair);

	webSocket.accept();

	let address = '';
	let portWithRandomLog = '';
	const log = (/** @type {string} */ info, /** @type {string | undefined} */ event) => {
		console.log(`[${address}:${portWithRandomLog}] ${info}`, event || '');
	};
	const earlyDataHeader = request.headers.get('sec-websocket-protocol') || '';
	const readableWebSocketStream = makeReadableWebSocketStream(webSocket, earlyDataHeader, log);
	let remoteSocketWapper = {
		value: null,
	};
	let isDns = false;
	readableWebSocketStream.pipeTo(new WritableStream({
		async write(chunk, controller) {
			if (isDns) {
				return await handleDNSQuery(chunk, webSocket, null, log);
			}
			if (remoteSocketWapper.value) {
				const writer = remoteSocketWapper.value.writable.getWriter()
				await writer.write(chunk);
				writer.releaseLock();
				return;
			}

			const {
				hasError,
				message,
				addressType,
				portRemote = 443,
				addressRemote = '',
				rawDataIndex,
				维列斯Version = new Uint8Array([0, 0]),
				isUDP,
			} = process维列斯Header(chunk, userID);
			address = addressRemote;
			portWithRandomLog = `${portRemote}--${Math.random()} ${isUDP ? 'udp ' : 'tcp '} `;
			if (hasError) {
				throw new Error(message);
			}
			if (isUDP) {
				if (portRemote === 53) {
					isDns = true;
				} else {
					throw new Error('UDP 代理仅对 DNS（53 端口）启用');
				}
			}
			const 维列斯ResponseHeader = new Uint8Array([维列斯Version[0], 0]);
			const rawClientData = chunk.slice(rawDataIndex);

			if (isDns) {
				return handleDNSQuery(rawClientData, webSocket, 维列斯ResponseHeader, log);
			}
			if (!banHosts.includes(addressRemote)) {
				log(`处理 TCP 出站连接 ${addressRemote}:${portRemote}`);
				handleTCPOutBound(remoteSocketWapper, addressType, addressRemote, portRemote, rawClientData, webSocket, 维列斯ResponseHeader, log);
			} else {
				throw new Error(`黑名单关闭 TCP 出站连接 ${addressRemote}:${portRemote}`);
			}
		},
		close() {
			log(`readableWebSocketStream 已关闭`);
		},
		abort(reason) {
			log(`readableWebSocketStream 已中止`, JSON.stringify(reason));
		},
	})).catch((err) => {
		log('readableWebSocketStream 管道错误', err);
        // Ensure websocket is closed on pipe error
        safeCloseWebSocket(webSocket);
	});
	return new Response(null, {
		status: 101,
		webSocket: client,
	});
}

async function handleTCPOutBound(remoteSocket, addressType, addressRemote, portRemote, rawClientData, webSocket, 维列斯ResponseHeader, log,) {

    // --- MODIFIED: Removed useSocks5Pattern function ---
	// async function useSocks5Pattern(address) { ... } // Removed

	async function connectAndWrite(address, port) { // --- MODIFIED: Removed 'socks' parameter ---
		log(`connected to ${address}:${port}`);
        // --- MODIFIED: Removed SOCKS5 connection logic ---
		// const tcpSocket = socks ? await socks5Connect(addressType, address, port, log) : connect({ ... });
        const tcpSocket = connect({
            hostname: address,
            port: port,
        });
		remoteSocket.value = tcpSocket;
		const writer = tcpSocket.writable.getWriter();
		await writer.write(rawClientData);
		writer.releaseLock();
		return tcpSocket;
	}

    /**
     * --- MODIFIED: Reworked retry function ---
     * 重试函数：当 Cloudflare 的 TCP Socket 没有传入数据时调用。
     * 在此修改版中，它不再尝试通过 proxyIP 或 SOCKS5 连接，
     * 而是直接记录失败并关闭 WebSocket。
     */
    async function retry() {
        log(`Direct connection to ${addressRemote}:${portRemote} failed or timed out. No fallback configured.`);
        safeCloseWebSocket(webSocket); // Close the client connection
    }

    // --- MODIFIED: Simplified connection logic, removed useSocks ---
	// let useSocks = false; // Removed
	// if (go2Socks5s.length > 0 && enableSocks) useSocks = await useSocks5Pattern(addressRemote); // Removed

	// 首次尝试直接连接远程服务器
	let tcpSocket = await connectAndWrite(addressRemote, portRemote); // Pass only address and port

	// 建立从远程服务器到 WebSocket 的数据流
	// 如果连接失败或无数据，修改后的 retry 函数将被调用进行处理（即关闭连接）
	remoteSocketToWS(tcpSocket, webSocket, 维列斯ResponseHeader, retry, log);
}

// ... (makeReadableWebSocketStream, process维列斯Header functions remain largely the same) ...
// ... (Helper functions like base64ToArrayBuffer, isValidUUID, safeCloseWebSocket, stringify utils remain) ...
// ... (handleDNSQuery remains the same) ...

// --- MODIFIED: Removed SOCKS5 related functions ---
// async function socks5Connect(...) { ... } // Removed
// function socks5AddressParser(...) { ... } // Removed


function makeReadableWebSocketStream(webSocketServer, earlyDataHeader, log) {
	let readableStreamCancel = false;
	const stream = new ReadableStream({
		start(controller) {
			webSocketServer.addEventListener('message', (event) => {
				if (readableStreamCancel) {
					return;
				}
				const message = event.data;
				controller.enqueue(message);
			});
			webSocketServer.addEventListener('close', () => {
				safeCloseWebSocket(webSocketServer);
				if (readableStreamCancel) {
					return;
				}
				controller.close();
			});
			webSocketServer.addEventListener('error', (err) => {
				log('WebSocket 服务器发生错误');
				controller.error(err);
			});
			const { earlyData, error } = base64ToArrayBuffer(earlyDataHeader);
			if (error) {
				controller.error(error);
			} else if (earlyData) {
				controller.enqueue(earlyData);
			}
		},
		pull(controller) {
		},
		cancel(reason) {
			if (readableStreamCancel) {
				return;
			}
			log(`可读流被取消，原因是 ${reason}`);
			readableStreamCancel = true;
			safeCloseWebSocket(webSocketServer);
		}
	});
	return stream;
}

function process维列斯Header(维列斯Buffer, userID) {
	if (维列斯Buffer.byteLength < 24) {
		return {
			hasError: true,
			message: 'invalid data',
		};
	}
	const version = new Uint8Array(维列斯Buffer.slice(0, 1));
	let isValidUser = false;
	let isUDP = false;
	function isUserIDValid(userID, userIDLow, buffer) {
		const userIDArray = new Uint8Array(buffer.slice(1, 17));
		const userIDString = stringify(userIDArray);
		return userIDString === userID || userIDString === userIDLow;
	}
	isValidUser = isUserIDValid(userID, userIDLow, 维列斯Buffer);
	if (!isValidUser) {
		return {
			hasError: true,
			message: `invalid user ${(new Uint8Array(维列斯Buffer.slice(1, 17)))}`,
		};
	}
	const optLength = new Uint8Array(维列斯Buffer.slice(17, 18))[0];
	const command = new Uint8Array(
		维列斯Buffer.slice(18 + optLength, 18 + optLength + 1)
	)[0];
	if (command === 1) {
	} else if (command === 2) {
		isUDP = true;
	} else {
		return {
			hasError: true,
			message: `command ${command} is not support, command 01-tcp,02-udp,03-mux`,
		};
	}
	const portIndex = 18 + optLength + 1;
	const portBuffer = 维列斯Buffer.slice(portIndex, portIndex + 2);
	const portRemote = new DataView(portBuffer).getUint16(0);
	let addressIndex = portIndex + 2;
	const addressBuffer = new Uint8Array(
		维列斯Buffer.slice(addressIndex, addressIndex + 1)
	);
	const addressType = addressBuffer[0];
	let addressLength = 0;
	let addressValueIndex = addressIndex + 1;
	let addressValue = '';
	switch (addressType) {
		case 1:
			addressLength = 4;
			addressValue = new Uint8Array(
				维列斯Buffer.slice(addressValueIndex, addressValueIndex + addressLength)
			).join('.');
			break;
		case 2:
			addressLength = new Uint8Array(
				维列斯Buffer.slice(addressValueIndex, addressValueIndex + 1)
			)[0];
			addressValueIndex += 1;
			addressValue = new TextDecoder().decode(
				维列斯Buffer.slice(addressValueIndex, addressValueIndex + addressLength)
			);
			break;
		case 3:
			addressLength = 16;
			const dataView = new DataView(
				维列斯Buffer.slice(addressValueIndex, addressValueIndex + addressLength)
			);
			const ipv6 = [];
			for (let i = 0; i < 8; i++) {
				ipv6.push(dataView.getUint16(i * 2).toString(16));
			}
			addressValue = ipv6.join(':');
			break;
		default:
			return {
				hasError: true,
				message: `invild addressType is ${addressType}`,
			};
	}
	if (!addressValue) {
		return {
			hasError: true,
			message: `addressValue is empty, addressType is ${addressType}`,
		};
	}
	return {
		hasError: false,
		addressRemote: addressValue,
		addressType,
		portRemote,
		rawDataIndex: addressValueIndex + addressLength,
		维列斯Version: version,
		isUDP,
	};
}

async function remoteSocketToWS(remoteSocket, webSocket, 维列斯ResponseHeader, retry, log) {
	let remoteChunkCount = 0;
	let chunks = [];
	let 维列斯Header = 维列斯ResponseHeader;
	let hasIncomingData = false;
	await remoteSocket.readable
		.pipeTo(
			new WritableStream({
				start() {
				},
				async write(chunk, controller) {
					hasIncomingData = true;
					if (webSocket.readyState !== WS_READY_STATE_OPEN) {
						controller.error(
							'webSocket.readyState is not open, maybe close'
						);
					}
					if (维列斯Header) {
						webSocket.send(await new Blob([维列斯Header, chunk]).arrayBuffer());
						维列斯Header = null;
					} else {
						webSocket.send(chunk);
					}
				},
				close() {
					log(`remoteConnection!.readable is close with hasIncomingData is ${hasIncomingData}`);
					// safeCloseWebSocket(webSocket); // Let the client close it.
				},
				abort(reason) {
					console.error(`remoteConnection!.readable abort`, reason);
				},
			})
		)
		.catch((error) => {
			console.error(
				`remoteSocketToWS has exception `,
				error.stack || error
			);
			safeCloseWebSocket(webSocket);
		});

	// --- MODIFIED: The retry function itself now handles the failure case ---
	if (hasIncomingData === false && retry) {
		log(`No incoming data from remote socket.`);
		retry(); // Call the modified retry function which will log and close.
	}
}

function base64ToArrayBuffer(base64Str) {
	if (!base64Str) {
		return { earlyData: undefined, error: null };
	}
	try {
		base64Str = base64Str.replace(/-/g, '+').replace(/_/g, '/');
		const decode = atob(base64Str);
		const arryBuffer = Uint8Array.from(decode, (c) => c.charCodeAt(0));
		return { earlyData: arryBuffer.buffer, error: null };
	} catch (error) {
		return { earlyData: undefined, error };
	}
}

function isValidUUID(uuid) {
	const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[4][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
	return uuidRegex.test(uuid);
}

const WS_READY_STATE_OPEN = 1;
const WS_READY_STATE_CLOSING = 2;

function safeCloseWebSocket(socket) {
	try {
		if (socket.readyState === WS_READY_STATE_OPEN || socket.readyState === WS_READY_STATE_CLOSING) {
			socket.close();
		}
	} catch (error) {
		console.error('safeCloseWebSocket error', error);
	}
}

const byteToHex = [];
for (let i = 0; i < 256; ++i) {
	byteToHex.push((i + 256).toString(16).slice(1));
}

function unsafeStringify(arr, offset = 0) {
	return (byteToHex[arr[offset + 0]] + byteToHex[arr[offset + 1]] + byteToHex[arr[offset + 2]] + byteToHex[arr[offset + 3]] + "-" +
		byteToHex[arr[offset + 4]] + byteToHex[arr[offset + 5]] + "-" +
		byteToHex[arr[offset + 6]] + byteToHex[arr[offset + 7]] + "-" +
		byteToHex[arr[offset + 8]] + byteToHex[arr[offset + 9]] + "-" +
		byteToHex[arr[offset + 10]] + byteToHex[arr[offset + 11]] + byteToHex[arr[offset + 12]] +
		byteToHex[arr[offset + 13]] + byteToHex[arr[offset + 14]] + byteToHex[arr[offset + 15]]).toLowerCase();
}

function stringify(arr, offset = 0) {
	const uuid = unsafeStringify(arr, offset);
	if (!isValidUUID(uuid)) {
		throw TypeError(`生成的 UUID 不符合规范 ${uuid}`);
	}
	return uuid;
}

async function handleDNSQuery(udpChunk, webSocket, 维列斯ResponseHeader, log) {
	try {
        // Using Cloudflare DNS instead of Google
		const dnsServer = '1.1.1.1'; // Cloudflare DNS
		const dnsPort = 53;
		let 维列斯Header = 维列斯ResponseHeader;
		const tcpSocket = connect({
			hostname: dnsServer,
			port: dnsPort,
		});
		log(`连接到 ${dnsServer}:${dnsPort}`);
		const writer = tcpSocket.writable.getWriter();
		await writer.write(udpChunk);
		writer.releaseLock();
		await tcpSocket.readable.pipeTo(new WritableStream({
			async write(chunk) {
				if (webSocket.readyState === WS_READY_STATE_OPEN) {
					if (维列斯Header) {
						webSocket.send(await new Blob([维列斯Header, chunk]).arrayBuffer());
						维列斯Header = null;
					} else {
						webSocket.send(chunk);
					}
				}
			},
			close() {
				log(`DNS 服务器(${dnsServer}) TCP 连接已关闭`);
			},
			abort(reason) {
				console.error(`DNS 服务器(${dnsServer}) TCP 连接异常中断`, reason);
			},
		}));
	} catch (error) {
		console.error(
			`handleDNSQuery 函数发生异常，错误信息: ${error.message}`
		);
	}
}


function 恢复伪装信息(content, userID, hostName, fakeUserID, fakeHostName, isBase64) {
	if (isBase64) content = atob(content);
	content = content.replace(new RegExp(fakeUserID, 'g'), userID)
		.replace(new RegExp(fakeHostName, 'g'), hostName);
	if (isBase64) content = btoa(content);
	return content;
}

async function 双重哈希(文本) {
	const 编码器 = new TextEncoder();
	const 第一次哈希 = await crypto.subtle.digest('MD5', 编码器.encode(文本));
	const 第一次哈希数组 = Array.from(new Uint8Array(第一次哈希));
	const 第一次十六进制 = 第一次哈希数组.map(字节 => 字节.toString(16).padStart(2, '0')).join('');
	const 第二次哈希 = await crypto.subtle.digest('MD5', 编码器.encode(第一次十六进制.slice(7, 27)));
	const 第二次哈希数组 = Array.from(new Uint8Array(第二次哈希));
	const 第二次十六进制 = 第二次哈希数组.map(字节 => 字节.toString(16).padStart(2, '0')).join('');
	return 第二次十六进制.toLowerCase();
}

async function 代理URL(代理网址, 目标网址) {
	const 网址列表 = await 整理(代理网址);
	const 完整网址 = 网址列表[Math.floor(Math.random() * 网址列表.length)];
	let 解析后的网址 = new URL(完整网址);
	console.log(解析后的网址);
	let 协议 = 解析后的网址.protocol.slice(0, -1) || 'https';
	let 主机名 = 解析后的网址.hostname;
	let 路径名 = 解析后的网址.pathname;
	let 查询参数 = 解析后的网址.search;
	if (路径名.charAt(路径名.length - 1) == '/') {
		路径名 = 路径名.slice(0, -1);
	}
	路径名 += 目标网址.pathname;
	let 新网址 = `${协议}://${主机名}${路径名}${查询参数}`;
	let 响应 = await fetch(新网址);
	let 新响应 = new Response(响应.body, {
		status: 响应.status,
		statusText: 响应.statusText,
		headers: 响应.headers
	});
	新响应.headers.set('X-New-URL', 新网址);
	return 新响应;
}

const 啥啥啥_写的这是啥啊 = atob('ZG14bGMzTT0='); // Decodes to 'vless'

function 配置信息(UUID, 域名地址) {
	const 协议类型 = atob(啥啥啥_写的这是啥啊); // vless
	const 别名 = FileName;
	let 地址 = 域名地址;
	let 端口 = 443;
	const 用户ID = UUID;
	const 加密方式 = 'none';
	const 传输层协议 = 'ws';
	const 伪装域名 = 域名地址;
	const 路径 = path; // Use the global path variable
	let 传输层安全 = ['tls', true];
	const SNI = 域名地址;
	const 指纹 = 'randomized';

	if (域名地址.includes('.workers.dev') || noTLS === 'true') { // Also consider noTLS flag
		地址 = atob('dmlzYS5jbg=='); // visa.cn ? Likely a placeholder/example.
		端口 = 80;
		传输层安全 = ['', false];
	}

    // Ensure path starts with /
    const encodedPath = encodeURIComponent(路径.startsWith('/') ? 路径 : '/' + 路径);

	const 威图瑞 = `${协议类型}://${用户ID}@${地址}:${端口}?encryption=${加密方式}&security=${传输层安全[0]}&sni=${SNI}&fp=${指纹}&type=${传输层协议}&host=${伪装域名}&path=${encodedPath}#${encodeURIComponent(别名)}`;
	const 猫猫猫 = `- {name: ${FileName}, server: ${地址}, port: ${端口}, type: ${协议类型}, uuid: ${用户ID}, tls: ${传输层安全[1]}, alpn: [h2, http/1.1], udp: false, sni: ${SNI}, network: ${传输层协议}, ws-opts: {path: "${路径.startsWith('/') ? 路径 : '/' + 路径}", headers: {Host: ${伪装域名}}}, client-fingerprint: ${指纹}}`; // Adjusted clash format slightly
	return [威图瑞, 猫猫猫];
}

let subParams = ['sub', 'base64', 'b64', 'clash', 'singbox', 'sb'];
const cmad = decodeURIComponent(atob('dGVsZWdyYW0lMjAlRTQlQkElQTQlRTYlQjUlODElRTclQkUlQTQlMjAlRTYlOEElODAlRTYlOUMlQUYlRTUlQTQlQTclRTQlQkQlQUMlN0UlRTUlOUMlQTglRTclQkElQkYlRTUlOEYlOTElRTclODklOEMhJTNDYnIlM0UKJTNDYSUyMGhyZWYlM0QlMjdodHRwcyUzQSUyRiUyRnQubWUlMkZDTUxpdXNzc3MlMjclM0VodHRwcyUzQSUyRiUyRnQubWUlMkZDTUxpdXNzc3MlM0MlMkZhJTNFJTNDYnIlM0UKLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tJTNDYnIlM0UKZ2l0aHViJTIwJUU5JUExJUI5JUU3JTlCJUFFJUU1JTlDJUIwJUU1JTlEJTgwJTIwU3RhciFTdGFyIVN0YXIhISElM0NiciUzRQolM0NhJTIwaHJlZiUzRCUyN2h0dHBzJTNBJTJGJTJGZ2l0aHViLmNvbSUyRmNtbGl1JTJGZWRnZXR1bm5lbCUyNyUzRWh0dHBzJTNBJTJGJTJGZ2l0aHViLmNvbSUyRmNtbGl1JTJGZWRnZXR1bm5lbCUzQyUyRmElM0UlM0NiciUzRQotLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0lM0NiciUzRQolMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjM='));

async function 生成配置信息(userID, hostName, sub, UA, RproxyIP_ignored, _url, fakeUserID, fakeHostName, env) { // RproxyIP parameter ignored
	if (sub) {
		const match = sub.match(/^(?:https?:\/\/)?([^\/]+)/);
		if (match) {
			sub = match[1];
		}
		const subs = await 整理(sub);
		if (subs.length > 1) sub = subs[0];
	} else {
		if (env.KV) {
			await 迁移地址列表(env);
			const 优选地址列表 = await env.KV.get('ADD.txt');
			if (优选地址列表) {
				const 优选地址数组 = await 整理(优选地址列表);
				const 分类地址 = {
					接口地址: new Set(),
					链接地址: new Set(),
					优选地址: new Set()
				};
				for (const 元素 of 优选地址数组) {
					if (元素.startsWith('https://')) {
						分类地址.接口地址.add(元素);
					} else if (元素.includes('://')) {
						分类地址.链接地址.add(元素);
					} else {
						分类地址.优选地址.add(元素);
					}
				}
				addressesapi = [...分类地址.接口地址];
				link = [...分类地址.链接地址];
				addresses = [...分类地址.优选地址];
			}
		}

		if ((addresses.length + addressesapi.length + addressesnotls.length + addressesnotlsapi.length + addressescsv.length) == 0) {
			let cfips = [ /* ... CIDR list ... */ ]; // Keeping this for node generation
            // ... (code to generate random IPs remains) ...
            function generateRandomIPFromCIDR(cidr) {
				const [base, mask] = cidr.split('/');
				const baseIP = base.split('.').map(Number);
				const subnetMask = 32 - parseInt(mask, 10);
				const maxHosts = Math.pow(2, subnetMask) - 1;
				const randomHost = Math.floor(Math.random() * maxHosts);
				const randomIP = baseIP.map((octet, index) => {
					if (index < 2) return octet;
					if (index === 2) return (octet & (255 << (subnetMask - 8))) + ((randomHost >> 8) & 255);
					return (octet & (255 << subnetMask)) + (randomHost & 255);
				});
				return randomIP.join('.');
			}
			addresses = addresses.concat('127.0.0.1:1234#CFnat');
			let counter = 1;
			if (hostName.includes("worker") || hostName.includes("notls") || noTLS === 'true') {
				const randomPorts = httpPorts.concat('80');
				addressesnotls = addressesnotls.concat(
					cfips.map(cidr => generateRandomIPFromCIDR(cidr) + ':' + randomPorts[Math.floor(Math.random() * randomPorts.length)] + '#CF随机节点' + String(counter++).padStart(2, '0'))
				);
			} else {
				const randomPorts = httpsPorts.concat('443');
				addresses = addresses.concat(
					cfips.map(cidr => generateRandomIPFromCIDR(cidr) + ':' + randomPorts[Math.floor(Math.random() * randomPorts.length)] + '#CF随机节点' + String(counter++).padStart(2, '0'))
				);
			}
		}
	}

	const uuid = (_url.pathname == `/${动态UUID}`) ? 动态UUID : userID;
	const userAgent = UA.toLowerCase();
	const Config = 配置信息(userID, hostName);
	const v2ray = Config[0];
	const clash = Config[1];
	let proxyhost = "";
	if (hostName.includes(".workers.dev")) {
		if (proxyhostsURL && (!proxyhosts || proxyhosts.length == 0)) {
			try {
				const response = await fetch(proxyhostsURL);
				if (!response.ok) {
					console.error('获取地址时出错:', response.status, response.statusText);
				} else {
    				const text = await response.text();
	    			const lines = text.split('\n');
		    		const nonEmptyLines = lines.filter(line => line.trim() !== '');
			    	proxyhosts = proxyhosts.concat(nonEmptyLines);
                }
			} catch (error) {
				//console.error('获取地址时出错:', error);
			}
		}
		if (proxyhosts.length != 0) proxyhost = proxyhosts[Math.floor(Math.random() * proxyhosts.length)] + "/";
	}

    // --- MODIFIED: Simplified the HTML output, removed proxy/socks mentions ---
	if (userAgent.includes('mozilla') && !subParams.some(_searchParams => _url.searchParams.has(_searchParams))) {
		let 订阅器 = '<br>';
		if (sub) {
            订阅器 += `CFCDN（访问方式）: 直连<br>`; // Indicate direct connection
			订阅器 += `<br>SUB（优选订阅生成器）: ${sub}`;
		} else {
            订阅器 += `CFCDN（访问方式）: 直连<br>`; // Indicate direct connection
			let 判断是否绑定KV空间 = '';
			if (env.KV) 判断是否绑定KV空间 = ` <a href='${_url.pathname}/edit'>编辑优选列表</a>`;
			订阅器 += `<br>您的订阅内容由 内置 addresses/ADD* 参数变量提供${判断是否绑定KV空间}<br>`;
			if (addresses.length > 0) 订阅器 += `ADD（TLS优选域名&IP）: <br>&nbsp;&nbsp;${addresses.join('<br>&nbsp;&nbsp;')}<br>`;
			if (addressesnotls.length > 0) 订阅器 += `ADDNOTLS（noTLS优选域名&IP）: <br>&nbsp;&nbsp;${addressesnotls.join('<br>&nbsp;&nbsp;')}<br>`;
			if (addressesapi.length > 0) 订阅器 += `ADDAPI（TLS优选域名&IP 的 API）: <br>&nbsp;&nbsp;${addressesapi.join('<br>&nbsp;&nbsp;')}<br>`;
			if (addressesnotlsapi.length > 0) 订阅器 += `ADDNOTLSAPI（noTLS优选域名&IP 的 API）: <br>&nbsp;&nbsp;${addressesnotlsapi.join('<br>&nbsp;&nbsp;')}<br>`;
			if (addressescsv.length > 0) 订阅器 += `ADDCSV（IPTest测速csv文件 限速 ${DLS} ）: <br>&nbsp;&nbsp;${addressescsv.join('<br>&nbsp;&nbsp;')}<br>`;
		}

		if (动态UUID && _url.pathname !== `/${动态UUID}`) 订阅器 = '';
		else 订阅器 += `<br>SUBAPI（订阅转换后端）: ${subProtocol}://${subConverter}<br>SUBCONFIG（订阅转换配置文件）: ${subConfig}`;
		const 动态UUID信息 = (uuid != userID) ?
			`TOKEN: ${uuid}<br>UUIDNow: ${userID}<br>UUIDLow: ${userIDLow}<br>${userIDTime}TIME（动态UUID有效时间）: ${有效时间} 天<br>UPTIME（动态UUID更新时间）: ${更新时间} 时（北京时间）<br><br>` : `${userIDTime}`;
		const 节点配置页 = `
			################################################################<br>
			Subscribe / sub 订阅地址, 点击链接自动 <strong>复制订阅链接</strong> 并 <strong>生成订阅二维码</strong> <br>
			---------------------------------------------------------------<br>
			自适应订阅地址:<br>
			<a href="javascript:void(0)" onclick="copyToClipboard('https://${proxyhost}${hostName}/${uuid}','qrcode_0')" style="color:blue;text-decoration:underline;cursor:pointer;">https://${proxyhost}${hostName}/${uuid}</a><br>
			<div id="qrcode_0" style="margin: 10px 10px 10px 10px;"></div>
			Base64订阅地址:<br>
			<a href="javascript:void(0)" onclick="copyToClipboard('https://${proxyhost}${hostName}/${uuid}?b64','qrcode_1')" style="color:blue;text-decoration:underline;cursor:pointer;">https://${proxyhost}${hostName}/${uuid}?b64</a><br>
			<div id="qrcode_1" style="margin: 10px 10px 10px 10px;"></div>
			clash订阅地址:<br>
			<a href="javascript:void(0)" onclick="copyToClipboard('https://${proxyhost}${hostName}/${uuid}?clash','qrcode_2')" style="color:blue;text-decoration:underline;cursor:pointer;">https://${proxyhost}${hostName}/${uuid}?clash</a><br>
			<div id="qrcode_2" style="margin: 10px 10px 10px 10px;"></div>
			singbox订阅地址:<br>
			<a href="javascript:void(0)" onclick="copyToClipboard('https://${proxyhost}${hostName}/${uuid}?sb','qrcode_3')" style="color:blue;text-decoration:underline;cursor:pointer;">https://${proxyhost}${hostName}/${uuid}?sb</a><br>
			<div id="qrcode_3" style="margin: 10px 10px 10px 10px;"></div>
			loon订阅地址:<br>
			<a href="javascript:void(0)" onclick="copyToClipboard('https://${proxyhost}${hostName}/${uuid}?loon','qrcode_5')" style="color:blue;text-decoration:underline;cursor:pointer;">https://${proxyhost}${hostName}/${uuid}?loon</a><br>
			<div id="qrcode_5" style="margin: 10px 10px 10px 10px;"></div>
            <strong><a href="javascript:void(0);" id="noticeToggle" onclick="toggleNotice()">实用订阅技巧∨</a></strong><br>
				<div id="noticeContent" class="notice-content" style="display: none;">
					<strong>1.</strong> 如您使用的是 PassWall、PassWall2 路由插件，订阅编辑的 <strong>用户代理(User-Agent)</strong> 设置为 <strong>PassWall</strong> 即可；<br>
					<br>
					<strong>2.</strong> 如您使用的是 SSR+ 路由插件，推荐使用 <strong>Base64订阅地址</strong> 进行订阅；<br>
					<br>
					<strong>3.</strong> 快速切换 <a href='${atob('aHR0cHM6Ly9naXRodWIuY29tL2NtbGl1L1dvcmtlclZsZXNzMnN1Yg==')}'>优选订阅生成器</a> 至：sub.google.com，您可将"?sub=sub.google.com"参数添加到链接末尾，例如：<br>
					&nbsp;&nbsp;https://${proxyhost}${hostName}/${uuid}<strong>?sub=sub.google.com</strong><br>
                    <br>
					<strong>4.</strong> 如需指定多个参数则需要使用'&'做间隔，例如：<br>
					&nbsp;&nbsp;https://${proxyhost}${hostName}/${uuid}?sub=sub.google.com<strong>&</strong>param=value<br>
				</div>
			<script src="https://cdn.jsdelivr.net/npm/@keeex/qrcodejs-kx@1.0.2/qrcode.min.js"></script>
			<script>
			function copyToClipboard(text, qrcode) {
				navigator.clipboard.writeText(text).then(() => {
					alert('已复制到剪贴板');
				}).catch(err => {
					console.error('复制失败:', err);
				});
				const qrcodeDiv = document.getElementById(qrcode);
                qrcodeDiv.innerHTML = ''; // Clear previous QR code
				new QRCode(qrcodeDiv, {
					text: text,
					width: 220,
					height: 220,
					colorDark: "#000000",
					colorLight: "#ffffff",
					correctLevel: QRCode.CorrectLevel.Q,
					scale: 1
				});
			}
			function toggleNotice() {
				const noticeContent = document.getElementById('noticeContent');
				const noticeToggle = document.getElementById('noticeToggle');
				if (noticeContent.style.display === 'none') {
					noticeContent.style.display = 'block';
					noticeToggle.textContent = '实用订阅技巧∧';
				} else {
					noticeContent.style.display = 'none';
					noticeToggle.textContent = '实用订阅技巧∨';
				}
			}
			</script>
			---------------------------------------------------------------<br>
			################################################################<br>
			${FileName} 配置信息<br>
			---------------------------------------------------------------<br>
			${动态UUID信息}HOST: ${hostName}<br>
			UUID: ${userID}<br>
			FKID: ${fakeUserID}<br>
			UA: ${UA}<br>
			${订阅器}<br>
			---------------------------------------------------------------<br>
			################################################################<br>
			v2ray<br>
			---------------------------------------------------------------<br>
			<a href="javascript:void(0)" onclick="copyToClipboard('${v2ray}','qrcode_v2ray')" style="color:blue;text-decoration:underline;cursor:pointer;">${v2ray}</a><br>
			<div id="qrcode_v2ray" style="margin: 10px 10px 10px 10px;"></div>
			---------------------------------------------------------------<br>
			################################################################<br>
			clash-meta<br>
			---------------------------------------------------------------<br>
			${clash}<br>
			---------------------------------------------------------------<br>
			################################################################<br>
			${cmad}
			`;
		return `<div style="font-size:13px;">${节点配置页}</div>`;
	} else {
		if (typeof fetch != 'function') {
			return 'Error: fetch is not available in this environment.';
		}

		let newAddressesapi = [];
		let newAddressescsv = [];
		let newAddressesnotlsapi = [];
		let newAddressesnotlscsv = [];
		if (hostName.includes(".workers.dev")) {
			noTLS = 'true';
			fakeHostName = `${fakeHostName}.workers.dev`;
			newAddressesnotlsapi = await 整理优选列表(addressesnotlsapi, false); // Pass proxyip=false
			newAddressesnotlscsv = await 整理测速结果('FALSE');
		} else if (hostName.includes(".pages.dev")) {
			fakeHostName = `${fakeHostName}.pages.dev`;
		} else if (hostName.includes("worker") || hostName.includes("notls") || noTLS == 'true') {
			noTLS = 'true';
			fakeHostName = `notls${fakeHostName}.net`;
			newAddressesnotlsapi = await 整理优选列表(addressesnotlsapi, false); // Pass proxyip=false
			newAddressesnotlscsv = await 整理测速结果('FALSE');
		} else {
			fakeHostName = `${fakeHostName}.xyz`
		}
		console.log(`虚假HOST: ${fakeHostName}`);
        // --- MODIFIED: Removed proxyip from generated sub URL ---
		let url = `${subProtocol}://${sub}/sub?host=${fakeHostName}&uuid=${fakeUserID + atob('JmVkZ2V0dW5uZWw9Y21saXU=')}&path=${encodeURIComponent(path)}`;
		let isBase64 = true;
		if (!sub || sub == "") {
			if (hostName.includes('workers.dev')) {
                // ... (fetch proxyhosts logic remains) ...
				if (proxyhostsURL && (!proxyhosts || proxyhosts.length == 0)) {
					try {
						const response = await fetch(proxyhostsURL);
						if (!response.ok) {
							console.error('获取地址时出错:', response.status, response.statusText);
						} else {
                            const text = await response.text();
						    const lines = text.split('\n');
						    const nonEmptyLines = lines.filter(line => line.trim() !== '');
    						proxyhosts = proxyhosts.concat(nonEmptyLines);
                        }
					} catch (error) {
						console.error('获取地址时出错:', error);
					}
				}
				proxyhosts = [...new Set(proxyhosts)];
			}

			newAddressesapi = await 整理优选列表(addressesapi, false); // Pass proxyip=false
			newAddressescsv = await 整理测速结果('TRUE');
			url = `https://${hostName}/${fakeUserID + _url.search}`;
			if (hostName.includes("worker") || hostName.includes("notls") || noTLS == 'true') {
				if (_url.search) url += '&notls';
				else url += '?notls';
			}
			console.log(`虚假订阅: ${url}`);
		}

		if (!userAgent.includes(('CF-Workers-SUB').toLowerCase()) && !_url.searchParams.has('b64') && !_url.searchParams.has('base64')) {
			if ((userAgent.includes('clash') && !userAgent.includes('nekobox')) || (_url.searchParams.has('clash') && !userAgent.includes('subconverter'))) {
				url = `${subProtocol}://${subConverter}/sub?target=clash&url=${encodeURIComponent(url)}&insert=false&config=${encodeURIComponent(subConfig)}&emoji=${subEmoji}&list=false&tfo=false&scv=true&fdn=false&sort=false&new_name=true`;
				isBase64 = false;
			} else if (userAgent.includes('sing-box') || userAgent.includes('singbox') || ((_url.searchParams.has('singbox') || _url.searchParams.has('sb')) && !userAgent.includes('subconverter'))) {
				url = `${subProtocol}://${subConverter}/sub?target=singbox&url=${encodeURIComponent(url)}&insert=false&config=${encodeURIComponent(subConfig)}&emoji=${subEmoji}&list=false&tfo=false&scv=true&fdn=false&sort=false&new_name=true`;
				isBase64 = false;
			} else if (userAgent.includes('loon') || (_url.searchParams.has('loon') && !userAgent.includes('subconverter'))) {
				url = `${subProtocol}://${subConverter}/sub?target=loon&url=${encodeURIComponent(url)}&insert=false&config=${encodeURIComponent(subConfig)}&emoji=${subEmoji}&list=false&tfo=false&scv=true&fdn=false&sort=false&new_name=true`;
				isBase64 = false;
			}
		}

		try {
			let content;
			if ((!sub || sub == "") && isBase64 == true) {
				content = await 生成本地订阅(fakeHostName, fakeUserID, noTLS, newAddressesapi, newAddressescsv, newAddressesnotlsapi, newAddressesnotlscsv);
			} else {
				const response = await fetch(url, {
					headers: {
						'User-Agent': UA + atob('IENGLVdvcmtlcnMtZWRnZXR1bm5lbC9jbWxpdQ==')
					}
				});
				content = await response.text();
			}

			if (_url.pathname == `/${fakeUserID}`) return content;

			return 恢复伪装信息(content, userID, hostName, fakeUserID, fakeHostName, isBase64);

		} catch (error) {
			console.error('Error fetching content:', error);
			return `Error fetching content: ${error.message}`;
		}
	}
}

// --- MODIFIED: Added 'useProxyIPParam' argument to prevent adding to pool ---
async function 整理优选列表(api, useProxyIPParam = true) {
	if (!api || api.length === 0) return [];
	let newapi = "";
	const controller = new AbortController();
	const timeout = setTimeout(() => {
		controller.abort();
	}, 2000);
	try {
		const responses = await Promise.allSettled(api.map(apiUrl => fetch(apiUrl, {
			method: 'get',
			headers: {
				'Accept': 'text/html,application/xhtml+xml,application/xml;',
				'User-Agent': atob('Q0YtV29ya2Vycy1lZGdldHVubmVsL2NtbGl1')
			},
			signal: controller.signal
		}).then(response => response.ok ? response.text() : Promise.reject())));
		for (const [index, response] of responses.entries()) {
			if (response.status === 'fulfilled') {
				const content = await response.value;
				const lines = content.split(/\r?\n/);
				let 节点备注 = '';
				let 测速端口 = '443';
				if (lines[0].split(',').length > 3) {
					const idMatch = api[index].match(/id=([^&]*)/);
					if (idMatch) 节点备注 = idMatch[1];
					const portMatch = api[index].match(/port=([^&]*)/);
					if (portMatch) 测速端口 = portMatch[1];
					for (let i = 1; i < lines.length; i++) {
						const columns = lines[i].split(',')[0];
						if (columns) {
							newapi += `${columns}:${测速端口}${节点备注 ? `#${节点备注}` : ''}\n`;
                            // --- MODIFIED: Removed adding to proxyIPPool ---
							// if (useProxyIPParam && api[index].includes('proxyip=true')) proxyIPPool.push(`${columns}:${测速端口}`);
						}
					}
				} else {
                    // --- MODIFIED: Removed adding to proxyIPPool ---
					// if (useProxyIPParam && api[index].includes('proxyip=true')) { ... }
					newapi += content + '\n';
				}
			}
		}
	} catch (error) {
		console.error(error);
	} finally {
		clearTimeout(timeout);
	}
	const newAddressesapi = await 整理(newapi);
	return newAddressesapi;
}

// --- MODIFIED: Added 'useProxyIPParam' argument to prevent adding to pool ---
async function 整理测速结果(tls, useProxyIPParam = true) {
	if (!addressescsv || addressescsv.length === 0) {
		return [];
	}
	let newAddressescsv = [];
	for (const csvUrl of addressescsv) {
		try {
			const response = await fetch(csvUrl);
			if (!response.ok) {
				console.error('获取CSV地址时出错:', response.status, response.statusText);
				continue;
			}
			const text = await response.text();
			let lines;
			if (text.includes('\r\n')) {
				lines = text.split('\r\n');
			} else {
				lines = text.split('\n');
			}
			const header = lines[0].split(',');
			const tlsIndex = header.indexOf('TLS');
			const ipAddressIndex = 0;
			const portIndex = 1;
			const dataCenterIndex = tlsIndex + remarkIndex;
			if (tlsIndex === -1) {
				console.error('CSV文件缺少必需的字段');
				continue;
			}
			for (let i = 1; i < lines.length; i++) {
				const columns = lines[i].split(',');
				const speedIndex = columns.length - 1;
				if (columns.length > speedIndex && columns[tlsIndex] && columns[tlsIndex].toUpperCase() === tls && parseFloat(columns[speedIndex]) > DLS) { // Added checks for columns length and existence
					const ipAddress = columns[ipAddressIndex];
					const port = columns[portIndex];
					const dataCenter = columns[dataCenterIndex];
					const formattedAddress = `${ipAddress}:${port}#${dataCenter}`;
					newAddressescsv.push(formattedAddress);
                    // --- MODIFIED: Removed adding to proxyIPPool ---
					// if (useProxyIPParam && csvUrl.includes('proxyip=true') && columns[tlsIndex].toUpperCase() == 'TRUE' && !httpsPorts.includes(port)) {
					//	proxyIPPool.push(`${ipAddress}:${port}`);
					// }
				}
			}
		} catch (error) {
			console.error('获取CSV地址时出错:', error);
			continue;
		}
	}
	return newAddressescsv;
}

function 生成本地订阅(host, UUID, noTLS, newAddressesapi, newAddressescsv, newAddressesnotlsapi, newAddressesnotlscsv) {
	const regex = /^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|\[.*\]):?(\d+)?#?(.*)?$/;
	addresses = addresses.concat(newAddressesapi);
	addresses = addresses.concat(newAddressescsv);
	let notlsresponseBody = '';
	if (noTLS == 'true') {
		addressesnotls = addressesnotls.concat(newAddressesnotlsapi);
		addressesnotls = addressesnotls.concat(newAddressesnotlscsv);
		const uniqueAddressesnotls = [...new Set(addressesnotls)];
		notlsresponseBody = uniqueAddressesnotls.map(addressLine => { // Renamed 'address' to 'addressLine' to avoid conflict
			let port = "-1";
            let address = addressLine; // Use 'address' for the IP/domain part
			let addressid = addressLine; // Use 'addressid' for remark

			const match = addressid.match(regex);
			if (!match) {
				// Simplified parsing logic
                if (addressLine.includes('#')) {
                    const parts = addressLine.split('#');
                    addressid = parts[1]; // Remark is after #
                    address = parts[0]; // Address part is before #
                    if (address.includes(':')) {
                        const addrParts = address.split(':');
                        address = addrParts[0];
                        port = addrParts[1];
                    }
                } else if (addressLine.includes(':')) {
                    const parts = addressLine.split(':');
                    address = parts[0];
                    port = parts[1];
                    addressid = address; // Use address as remark if no #
                } else {
                     address = addressLine; // Assume it's just address/domain
                     addressid = address;
                }
			} else {
				address = match[1]; // IP/Domain
				port = match[2] || port; // Port
				addressid = match[3] || address; // Remark or IP/Domain if no remark
			}

			if (!isValidIPv4(address) && port == "-1") {
				for (let httpPort of httpPorts) {
					if (addressLine.includes(httpPort)) { // Check original line for port hints if parsing failed
						port = httpPort;
						break;
					}
				}
			}
			if (port == "-1") port = "80"; // Default HTTP port for noTLS

			let 伪装域名 = host;
			let 最终路径 = path; // Use global path
			let 节点备注 = addressid; // Use parsed remark
            const 协议类型 = atob(啥啥啥_写的这是啥啊); // vless

			// --- MODIFIED: Ensure path starts with / ---
            const encodedPath = encodeURIComponent(最终路径.startsWith('/') ? 最终路径 : '/' + 最终路径);
			const 维列斯Link = `${协议类型}://${UUID}@${address}:${port}?encryption=none&security=&type=ws&host=${伪装域名}&path=${encodedPath}#${encodeURIComponent(节点备注)}`;
			return 维列斯Link;
		}).join('\n');
	}

	const uniqueAddresses = [...new Set(addresses)];
	const responseBody = uniqueAddresses.map(addressLine => { // Renamed 'address' to 'addressLine'
        let port = "-1";
        let address = addressLine;
        let addressid = addressLine;

        const match = addressid.match(regex);
		if (!match) {
			// Simplified parsing logic (same as above)
            if (addressLine.includes('#')) {
                const parts = addressLine.split('#');
                addressid = parts[1];
                address = parts[0];
                if (address.includes(':')) {
                    const addrParts = address.split(':');
                    address = addrParts[0];
                    port = addrParts[1];
                }
            } else if (addressLine.includes(':')) {
                const parts = addressLine.split(':');
                address = parts[0];
                port = parts[1];
                addressid = address;
            } else {
                 address = addressLine;
                 addressid = address;
            }
		} else {
			address = match[1];
			port = match[2] || port;
			addressid = match[3] || address;
		}

		if (!isValidIPv4(address) && port == "-1") {
			for (let httpsPort of httpsPorts) {
				if (addressLine.includes(httpsPort)) {
					port = httpsPort;
					break;
				}
			}
		}
		if (port == "-1") port = "443"; // Default HTTPS port

		let 伪装域名 = host;
		let 最终路径 = path; // Use global path
		let 节点备注 = addressid; // Use parsed remark

        // --- MODIFIED: Removed proxyIPPool check and path modification ---
		// const matchingProxyIP = proxyIPPool.find(proxyIP => proxyIP.includes(address));
		// if (matchingProxyIP) 最终路径 = `/?proxyip=${matchingProxyIP}`;

		if (proxyhosts.length > 0 && (伪装域名.includes('.workers.dev'))) {
            // This logic seems designed for workers.dev domains, keeping it
			最终路径 = `/${伪装域名}${最终路径}`;
			伪装域名 = proxyhosts[Math.floor(Math.random() * proxyhosts.length)];
			节点备注 += ` (proxied via ${伪装域名})`; // Modify remark instead of path
		}

		const 协议类型 = atob(啥啥啥_写的这是啥啊); // vless
        // --- MODIFIED: Ensure path starts with / ---
        const encodedPath = encodeURIComponent(最终路径.startsWith('/') ? 最终路径 : '/' + 最终路径);
		const 维列斯Link = `${协议类型}://${UUID}@${address}:${port}?encryption=none&security=tls&sni=${伪装域名}&fp=random&type=ws&host=${伪装域名}&path=${encodedPath}#${encodeURIComponent(节点备注)}`;
		return 维列斯Link;
	}).join('\n');

	let base64Response = responseBody;
	if (noTLS == 'true' && notlsresponseBody) base64Response += `\n${notlsresponseBody}`; // Combine if noTLS
	if (link.length > 0) base64Response += '\n' + link.join('\n');
	return btoa(base64Response);
}


async function 整理(内容) {
	if (!内容) return [];
	var 替换后的内容 = 内容.replace(/[	|"'\r\n]+/g, ',').replace(/,+/g, ',');
	if (替换后的内容.charAt(0) == ',') 替换后的内容 = 替换后的内容.slice(1);
	if (替换后的内容.charAt(替换后的内容.length - 1) == ',') 替换后的内容 = 替换后的内容.slice(0, 替换后的内容.length - 1);
	const 地址数组 = 替换后的内容.split(',');
	return 地址数组.filter(addr => addr.trim() !== ''); // Filter out empty strings
}

async function sendMessage(type, ip, add_data = "") {
	if (!BotToken || !ChatID) return;
	try {
		let msg = "";
		const response = await fetch(`http://ip-api.com/json/${ip}?lang=zh-CN`);
		if (response.ok) {
			const ipInfo = await response.json();
			msg = `${type}\nIP: ${ip}\n国家: ${ipInfo.country}\n<tg-spoiler>城市: ${ipInfo.city}\n组织: ${ipInfo.org}\nASN: ${ipInfo.as}\n${add_data}`;
		} else {
			msg = `${type}\nIP: ${ip}\n<tg-spoiler>${add_data}`;
		}
		const url = `https://api.telegram.org/bot${BotToken}/sendMessage?chat_id=${ChatID}&parse_mode=HTML&text=${encodeURIComponent(msg)}`;
		return fetch(url, {
			method: 'GET',
			headers: {
				'Accept': 'text/html,application/xhtml+xml,application/xml;',
				'Accept-Encoding': 'gzip, deflate, br',
				'User-Agent': 'Mozilla/5.0 Chrome/90.0.4430.72'
			}
		});
	} catch (error) {
		console.error('Error sending message:', error);
	}
}

function isValidIPv4(address) {
	const ipv4Regex = /^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
	return ipv4Regex.test(address);
}

function 生成动态UUID(密钥) {
	const 时区偏移 = 8;
	const 起始日期 = new Date(2007, 6, 7, 更新时间, 0, 0);
	const 一周的毫秒数 = 1000 * 60 * 60 * 24 * 有效时间;
	function 获取当前周数() {
		const 现在 = new Date();
		const 调整后的现在 = new Date(现在.getTime() + 时区偏移 * 60 * 60 * 1000);
		const 时间差 = Number(调整后的现在) - Number(起始日期);
		return Math.ceil(时间差 / 一周的毫秒数);
	}
	function 生成UUID(基础字符串) {
		const 编码器 = new TextEncoder();
		const 哈希缓冲区 = 编码器.encode(基础字符串);
		return crypto.subtle.digest('SHA-256', 哈希缓冲区).then((哈希) => {
			const 哈希数组 = Array.from(new Uint8Array(哈希));
			const 十六进制哈希 = 哈希数组.map(b => b.toString(16).padStart(2, '0')).join('');
			return `${十六进制哈希.substr(0, 8)}-${十六进制哈希.substr(8, 4)}-4${十六进制哈希.substr(13, 3)}-${(parseInt(十六进制哈希.substr(16, 2), 16) & 0x3f | 0x80).toString(16)}${十六进制哈希.substr(18, 2)}-${十六进制哈希.substr(20, 12)}`;
		});
	}
	const 当前周数 = 获取当前周数();
	const 结束时间 = new Date(起始日期.getTime() + 当前周数 * 一周的毫秒数);
	const 当前UUIDPromise = 生成UUID(密钥 + 当前周数);
	const 上一个UUIDPromise = 生成UUID(密钥 + (当前周数 - 1));
	const 到期时间UTC = new Date(结束时间.getTime() - 时区偏移 * 60 * 60 * 1000);
	const 到期时间字符串 = `到期时间(UTC): ${到期时间UTC.toISOString().slice(0, 19).replace('T', ' ')} (UTC+8): ${结束时间.toISOString().slice(0, 19).replace('T', ' ')}\n`;
	return Promise.all([当前UUIDPromise, 上一个UUIDPromise, 到期时间字符串]);
}

async function 迁移地址列表(env, txt = 'ADD.txt') {
	const 旧数据 = await env.KV.get(`/${txt}`);
	const 新数据 = await env.KV.get(txt);
	if (旧数据 && !新数据) {
		await env.KV.put(txt, 旧数据);
		await env.KV.delete(`/${txt}`);
		return true;
	}
	return false;
}

async function KV(request, env, txt = 'ADD.txt') {
	try {
		// POST请求处理
		if (request.method === "POST") {
			if (!env.KV) return new Response("未绑定KV空间", { status: 400 });
			try {
				const content = await request.text();
				await env.KV.put(txt, content);
				return new Response("保存成功");
			} catch (error) {
				console.error('保存KV时发生错误:', error);
				return new Response("保存失败: " + error.message, { status: 500 });
			}
		}

		// GET请求部分
		let content = '';
		let hasKV = !!env.KV;
		if (hasKV) {
			try {
				content = await env.KV.get(txt) || '';
			} catch (error) {
				console.error('读取KV时发生错误:', error);
				content = '读取数据时发生错误: ' + error.message;
			}
		}

        // Store initial content for comparison later
        const initialKVContent = content;

		const html = `
			<!DOCTYPE html>
			<html>
			<head>
				<title>优选订阅列表</title>
				<meta charset="utf-8">
				<meta name="viewport" content="width=device-width, initial-scale=1">
				<style>
					body { margin: 0; padding: 15px; box-sizing: border-box; font-size: 13px; font-family: sans-serif; }
					.editor-container { width: 100%; max-width: 100%; margin: 0 auto; }
					.editor { width: 100%; height: 520px; margin: 15px 0; padding: 10px; box-sizing: border-box; border: 1px solid #ccc; border-radius: 4px; font-size: 13px; line-height: 1.5; overflow-y: auto; resize: vertical; font-family: monospace; }
					.save-container { margin-top: 8px; display: flex; align-items: center; gap: 10px; flex-wrap: wrap; }
					.save-btn, .back-btn { padding: 6px 15px; color: white; border: none; border-radius: 4px; cursor: pointer; font-size: 13px; }
					.save-btn { background: #4CAF50; }
					.save-btn:hover { background: #45a049; }
                    .save-btn:disabled { background: #cccccc; cursor: not-allowed; }
					.back-btn { background: #666; }
					.back-btn:hover { background: #555; }
					.save-status { color: #666; font-size: 12px; flex-basis: 100%; margin-top: 5px; }
					.notice-content { display: none; margin-top: 10px; font-size: 13px; color: #333; border: 1px solid #eee; padding: 10px; border-radius: 4px; background-color: #f9f9f9; }
                    a { color: #007bff; text-decoration: none; }
                    a:hover { text-decoration: underline; }
                    strong a { font-weight: bold; cursor: pointer; }
                    pre { white-space: pre-wrap; word-wrap: break-word; }
				</style>
			</head>
			<body>
                <pre>
################################################################<br>
${FileName} 优选订阅列表:<br>
---------------------------------------------------------------<br>
&nbsp;&nbsp;<strong><a href="javascript:void(0);" id="noticeToggle" onclick="toggleNotice()">注意事项∨</a></strong><br>
                </pre>
				<div id="noticeContent" class="notice-content">
                    &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<strong>1.</strong> ADDAPI/ADDCSV 中不支持 proxyip=true 参数 (相关功能已移除)。<br>
					&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<strong>2.</strong> 格式: IP/域名[:端口][#备注], 每行一个, 例如:<br>
                    &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;1.2.3.4:443#节点1<br>
                    &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;example.com#节点2<br>
                    &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;[::1]:2053#节点3<br>
				</div>
				<div class="editor-container">
					${hasKV ? `
					<textarea class="editor"
						placeholder="${decodeURIComponent(atob('QUREJUU3JUE0JUJBJUU0JUJFJThCJUVGJUJDJTlBCnZpc2EuY24lMjMlRTQlQkMlOTglRTklODAlODklRTUlOUYlOUYlRTUlOTAlOEQKMTI3LjAuMC4xJTNBMTIzNCUyM0NGbmF0CiU1QjI2MDYlM0E0NzAwJTNBJTNBJTVEJTNBMjA1MyUyM0lQdjYKCiVFNiVCMyVBOCVFNiU4NCU4RiVFRiVCQyU5QQolRTYlQUYlOEYlRTglQTElOEMlRTQlQjglODAlRTQlQjglQUElRTUlOUMlQjAlRTUlOUQlODAlRUYlQkMlOEMlRTYlQTAlQkMlRTUlQkMlOEYlRTQlQjglQkElMjAlRTUlOUMlQjAlRTUlOUQlODAlM0ElRTclQUIlQUYlRTUlOEYlQTMlMjMlRTUlQTQlODclRTYlQjMlQTgKSVB2NiVFNSU5QyVCMCVFNSU5RCU4MCVFOSU5QyU4MCVFOCVBNiU4MSVFNyU5NCVBOCVFNCVCOCVBRCVFNiU4QiVBQyVFNSU4RiVCNyVFNiU4QiVBQyVFOCVCNSVCNyVFNiU5RCVBNSVFRiVCQyU4QyVFNSVBNiU4MiVFRiVCQyU5QSU1QjI2MDYlM0E0NzAwJTNBJTNBJTVEJTNBMjA1MwolRTclQUIlQUYlRTUlOEYlQTMlRTQlQjglOEQlRTUlODYlOTklRUYlQkMlOEMlRTklQkIlOTglRTglQUUlQTQlRTQlQjglQkElMjA0NDMlMjAlRTclQUIlQUYlRTUlOEYlQTMlRUYlQkMlOEMlRTUlQTYlODIlRUYlQkMlOUF2aXNhLmNuJTIzJUU0JUJDJTk4JUU5JTgwJTg5JUU1JTlGJTlGJUU1JTkwJThECgoKQUREQVBJJUU3JUE0JUJBJUU0JUJFJThCJUVGJUJDJTlBCmh0dHBzJTNBJTJGJTJGcmF3LmdpdGh1YnVzZXJjb250ZW50LmNvbSUyRmNtbGl1JTJGV29ya2VyVmxlc3Myc3ViJTJGcmVmcyUyRmhlYWRzJTJGbWFpbiUyRmFkZHJlc3Nlc2FwaS50eHQKCiVFNiVCMyVBOCVFNiU4NCU4RiVFRiVCQyU5QUFEREFQSSVFNyU5QiVCNCVFNiU4RSVBNSVFNiVCNyVCQiVFNSU4QSVBMCVFNyU5QiVCNCVFOSU5MyVCRSVFNSU4RCVCMyVFNSU4RiVBRg=='))}"
						id="content">${content}</textarea>
					<div class="save-container">
						<button class="back-btn" onclick="goBack()">返回配置页</button>
						<button class="save-btn" onclick="saveContent(this)">保存</button>
						<span class="save-status" id="saveStatus"></span>
					</div>
                    <pre>
<br>
################################################################<br>
${cmad}
                    </pre>
					` : '<p>未绑定KV空间</p>'}
				</div>

				<script>
				// Use a closure to keep track of the initial content loaded from KV
                const initialContentFromKV = ${hasKV ? JSON.stringify(initialKVContent) : '""'};
                let currentContent = initialContentFromKV; // Track current saved state
                let saveTimer;

				if (document.querySelector('.editor')) {
					const textarea = document.getElementById('content');
                    const saveButton = document.querySelector('.save-btn');
                    const statusElem = document.getElementById('saveStatus');

					function goBack() {
						const currentUrl = window.location.href;
						const parentUrl = currentUrl.substring(0, currentUrl.lastIndexOf('/edit')); // Go back from /edit path
						window.location.href = parentUrl || '/'; // Go to parent or root
					}

                    // Function to replace full-width colons, useful for input method users
					function replaceFullwidthColon() {
                        if (textarea.value.includes('：')) {
						    textarea.value = textarea.value.replace(/：/g, ':');
                        }
					}

                    // Function to update status message
                    const updateStatus = (message, isError = false) => {
                        if (statusElem) {
                            statusElem.textContent = message;
                            statusElem.style.color = isError ? 'red' : '#4CAF50'; // Green for success
                        }
                    };

                    // Function to handle saving content
					function saveContent(button) {
                        clearTimeout(saveTimer); // Clear any pending save timer
                        const newContent = textarea.value || '';

                        // Only save if content has actually changed from the last saved state
						if (newContent !== currentContent) {
                            button.textContent = '保存中...';
                            button.disabled = true;
                            updateStatus('正在保存...');

							fetch(window.location.href, {
								method: 'POST',
								body: newContent,
								headers: {
									'Content-Type': 'text/plain;charset=UTF-8'
								},
								cache: 'no-cache' // Prevent caching POST request
							})
							.then(response => {
								if (!response.ok) {
                                    // Try to get error message from response body for more details
                                    return response.text().then(text => {
                                        // *** THIS IS THE CORRECTED LINE ***
                                        throw new Error(\`HTTP error! status: \${response.status}, message: \${text || 'No details'}\`);
                                    });
								}
								return response.text(); // Expecting "保存成功" from server
							})
                            .then(responseText => {
                                const now = new Date().toLocaleString();
                                document.title = \`列表已保存 \${now}\`;
                                updateStatus(\`\${responseText} ${now}\`, false);
                                currentContent = newContent; // Update the current saved state
                            })
							.catch(error => {
								console.error('Save error:', error);
								updateStatus(\`保存失败: \${error.message}\`, true);
							})
							.finally(() => {
                                button.textContent = '保存';
                                button.disabled = false;
							});
						} else {
							updateStatus('内容未变化'); // Inform user if no change
						}
					}

					// Auto-save functionality with debounce
					textarea.addEventListener('input', () => {
                        replaceFullwidthColon(); // Clean input as user types
						clearTimeout(saveTimer); // Reset timer on input
                        updateStatus('输入中...');
						saveTimer = setTimeout(() => {
                            saveContent(saveButton);
                        }, 3000); // Save 3 seconds after user stops typing
					});

                    // Save on leaving the page (best effort)
                    window.addEventListener('beforeunload', (event) => {
                        clearTimeout(saveTimer); // Clear any pending timer
                        if (textarea.value !== currentContent) {
                             // Attempt a synchronous save if needed, though generally discouraged
                             // Or simply warn the user
                             // event.preventDefault(); // Standard way to prompt user
                             // event.returnValue = ''; // For older browsers
                             // For simplicity here, we won't block unload but maybe save one last time
                             // Note: fetch in beforeunload is unreliable
                             console.log("Content changed, consider saving before leaving.");
                        }
                    });

				} // End of if(.editor) check

                // Toggle for notice section
				function toggleNotice() {
					const noticeContent = document.getElementById('noticeContent');
					const noticeToggle = document.getElementById('noticeToggle');
					if (noticeContent.style.display === 'none' || noticeContent.style.display === '') {
						noticeContent.style.display = 'block';
						noticeToggle.textContent = '注意事项∧';
					} else {
						noticeContent.style.display = 'none';
						noticeToggle.textContent = '注意事项∨';
					}
				}

				// Initialize notice display and potentially other UI elements
				document.addEventListener('DOMContentLoaded', () => {
                    if(document.getElementById('noticeContent')) {
					    document.getElementById('noticeContent').style.display = 'none';
                    }
				});
				</script>
			</body>
			</html>
		`;
		return new Response(html, {
			headers: { "Content-Type": "text/html;charset=utf-8" }
		});
	} catch (error) {
		console.error('处理 KV 请求时发生错误:', error);
		return new Response("服务器错误: " + error.message, {
			status: 500,
			headers: { "Content-Type": "text/plain;charset=utf-8" }
		});
	}
}
