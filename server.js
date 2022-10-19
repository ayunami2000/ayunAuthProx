const http = require("http");
const httpProxy = require("http-proxy");

const hasUser = process.argv.length > 2;
const hasPass = process.argv.length > 3;
const hasTarget = process.argv.length > 4;
const hasPort = process.argv.length > 5;
const hasRealm = process.argv.length > 6;

const user = process.env.AUTHPROXUSER || (hasUser ? process.argv[2] : "user");
const pass = process.env.AUTHPROXPASS || (hasPass ? process.argv[3] : "pass");
const target = process.env.AUTHPROXDEST || (hasTarget ? process.argv[4] : "http://localhost:9000");
const port = process.env.AUTHPROXPORT || (hasPort ? +process.argv[5] : 8888);
const realm = process.env.AUTHPROXREALM || (hasRealm ? process.argv[6] : "GBJ");

const unauthHead = { "Content-Type": "text/plain", "WWW-Authenticate": "Basic realm=" + JSON.stringify(realm) };

const proxy = httpProxy.createProxyServer({ target: target, ws: true });

proxy.on("error", (err, req, res) => {
	res.writeHead(500, { "Content-Type": "text/plain" });
	res.end("500 Internal Server Error");
});

function checkAuth(req) {
	const auth = req.headers.authorization;
	if (auth) {
		const pieces = auth.split(" ");
		if (pieces.length != 2) return;
		if (pieces[0] != "Basic") return;
		const encoded = pieces[1];
		let decoded = "";
		try {
			decoded = Buffer.from(encoded, "base64").toString();
		} catch (e) {
			return;
		}
		if (!decoded.includes(":")) return;
		const givenUser = decoded.slice(0, decoded.indexOf(":"));
		const givenPass = decoded.slice(decoded.indexOf(":") + 1);
		if (givenUser != user || givenPass != pass) return;
		return true;
	}
}

const server = http.createServer((req, res) => {
	if (checkAuth(req)) {
		proxy.web(req, res);
	} else {
		res.writeHead(401, unauthHead);
		res.end("401 Unauthorized");
	}
});

server.on("upgrade", (req, socket, head) => {
	if (checkAuth(req)) {
		proxy.ws(req, socket, head);
	} else {
		socket.end();
	}
});

server.listen(port);

console.log("It has begun.");