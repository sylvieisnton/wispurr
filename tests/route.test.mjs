import assert from "node:assert/strict";
import { once } from "node:events";
import { createServer } from "node:http";
import { Socket } from "node:net";
import { copyFileSync, existsSync, unlinkSync } from "node:fs";
import { after, test } from "node:test";
import { wispurr } from "../dist/index.js";

const configPath = new URL("../dist/config.json", import.meta.url);
const createdConfig = !existsSync(configPath);
if (createdConfig) copyFileSync(new URL("../example.config.json", import.meta.url), configPath);
after(() => { if (createdConfig) unlinkSync(configPath); });

async function fixture(t, handler) {
	const server = createServer();
	server.on("upgrade", handler);
	server.listen(0, "127.0.0.1");
	await once(server, "listening");
	t.after(() => new Promise(resolve => server.close(resolve)));
	const wrapper = new wispurr({ logLevel: "none" });
	wrapper.processes = [];
	wrapper.processPorts = [server.address().port];
	return wrapper;
}

const request = { url: "/wisp", method: "GET", headers: { connection: "Upgrade", upgrade: "websocket" } };

test("client error before upgrade is handled and cancels the worker request", async t => {
	let closed;
	const upstreamClosed = new Promise(resolve => { closed = resolve; });
	const wrapper = await fixture(t, (_req, socket) => {
		t.after(() => socket.destroy());
		socket.on("error", () => {});
		socket.on("close", closed);
		socket.on("end", () => socket.end());
		socket.resume();
		client.emit("error", new Error("read ECONNRESET"));
	});
	const client = new Socket();
	wrapper.route(request, client, Buffer.alloc(0));
	await upstreamClosed;
	assert.equal(client.destroyed, true);
});

test("client close before upgrade cancels the worker connection", async t => {
	let closed;
	const upstreamClosed = new Promise(resolve => { closed = resolve; });
	const wrapper = await fixture(t, (_req, socket) => {
		t.after(() => socket.destroy());
		socket.on("error", () => {});
		socket.on("close", closed);
		socket.on("end", () => socket.end());
		socket.resume();
		client.destroy();
	});
	const client = new Socket();
	wrapper.route(request, client, Buffer.alloc(0));
	await upstreamClosed;
	assert.equal(client.destroyed, true);
});
