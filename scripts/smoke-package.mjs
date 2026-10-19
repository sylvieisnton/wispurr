import assert from "node:assert/strict";
import { wispurr } from "wispurr";

const server = new wispurr({
	host: "127.0.0.1",
	port: 16001,
	reputation: { enabled: false },
});

try {
	await server.start();
	const response = await fetch(`http://127.0.0.1:${server.ports[0]}/health`, {
		signal: AbortSignal.timeout(5000),
	});
	assert.equal(response.status, 200);
	assert.deepEqual(await response.json(), { status: "ok" });
} finally {
	await server.stop();
}
assert.equal(server.isRunning, false);
console.log(`Packed npm package works on ${process.platform}-${process.arch}.`);
