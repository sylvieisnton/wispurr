import { spawn, type ChildProcess } from "node:child_process";
import { binPath, configPath } from "./path.js";
import * as fs from "node:fs";
import { detect } from "detect-port";
import { Logger } from "./logger.js";
import { request, type IncomingMessage } from "node:http";
import type { Socket } from "node:net";
import { createInterface } from "node:readline";
import type { wispurrConfig, wispurrOptions } from "./config.js";

export type { wispurrConfig, wispurrOptions } from "./config.js";

type Process = Array<{
	process: ChildProcess;
	index: number;
}>;

let cachedDefaultConfig: wispurrConfig | undefined;

function loadDefaultConfig(): wispurrConfig {
	if (cachedDefaultConfig) return cachedDefaultConfig;
	try {
		cachedDefaultConfig = JSON.parse(fs.readFileSync(configPath, "utf-8"));
		return cachedDefaultConfig as wispurrConfig;
	} catch (err) {
		throw new Error(
			`wispurr: failed to read bundled config at ${configPath}`,
			{ cause: err },
		);
	}
}

export class wispurr {
	config: wispurrConfig;
	processes: Process | undefined;
	private reqIndex = 0;
	private processPorts: number[] = [];
	private readonly logger: Logger;

	get isRunning(): boolean {
		return Boolean(this.processes?.length);
	}

	get ports(): readonly number[] {
		return [...this.processPorts];
	}

	constructor(config?: wispurrOptions) {
		this.config = structuredClone(loadDefaultConfig());
		this.processes = undefined;
		if (config) {
			this.config = {
				...this.config,
				...config,
				blacklist: { ...this.config.blacklist, ...config.blacklist },
				whitelist: { ...this.config.whitelist, ...config.whitelist },
				floodProtection: {
					...this.config.floodProtection,
					...config.floodProtection,
					synFloodSignature: {
						...this.config.floodProtection.synFloodSignature,
						...config.floodProtection?.synFloodSignature,
					} as NonNullable<wispurrConfig["floodProtection"]["synFloodSignature"]>,
				},
				reputation: {
					...this.config.reputation,
					...config.reputation,
					thresholds: {
						...this.config.reputation.thresholds,
						...config.reputation?.thresholds,
					} as NonNullable<wispurrConfig["reputation"]["thresholds"]>,
					weights: { ...this.config.reputation.weights, ...config.reputation?.weights },
					destinationWeights: {
						...this.config.reputation.destinationWeights,
						...config.reputation?.destinationWeights,
					},
				},
			};
		}
		this.logger = new Logger(this.config.logLevel);
	}

	async getAvailablePort(port: number): Promise<number> {
		for (let candidate = port; candidate <= 65535; candidate++) {
			if (!this.processPorts.includes(candidate) && (await detect(candidate)) === candidate) {
				return candidate;
			}
		}
		throw new Error(`wispurr: no available port at or above ${port}`);
	}

	async start(count: number = 1) {
		if (!Number.isInteger(count) || count < 1) {
			throw new RangeError("wispurr: worker count must be a positive integer");
		}
		if (this.processes?.length) {
			throw new Error("wispurr: already running; stop it before starting again");
		}
		this.processes = [];
		this.processPorts = [];

		for (let i = 0; i < count; i++) {
			const nextPort = Array.isArray(this.config.port)
				? (this.config.port[i] ?? this.config.port[this.config.port.length - 1])
				: this.config.port;
			if (!Number.isInteger(nextPort) || nextPort! < 1 || nextPort! > 65535) {
				if (this.processes.length) this.signal("SIGKILL");
				throw new Error("wispurr: port must be an integer between 1 and 65535");
			}
			let port: number;
			try {
				port = await this.getAvailablePort(nextPort!);
			} catch (err) {
				if (this.processes.length) this.signal("SIGKILL");
				throw err;
			}
			const { port: _port, ...config } = this.config;

			const proc = spawn(
				binPath,
				["--config", JSON.stringify(config), "--port", port.toString()],
				{ stdio: "pipe" },
			);
			await new Promise<void>((resolve, reject) => {
				proc.once("spawn", resolve);
				proc.once("error", reject);
			}).catch((err: unknown) => {
				if (this.processes?.length) this.signal("SIGKILL");
				throw err;
			});

			this.processes.push({ process: proc, index: i });
			this.processPorts.push(port);

			const handleLine = (msg: string) => {
				const levelMatch = msg.match(/^\[(DEBUG|INFO|WARN|ERROR)\]/);
				if (levelMatch) {
					switch (levelMatch[1]) {
						case "DEBUG": this.logger.debug(msg, i); break;
						case "INFO": this.logger.info(msg, i); break;
						case "WARN": this.logger.warn(msg, i); break;
						case "ERROR": this.logger.error(msg, i); break;
					}
				} else {
					this.logger.error(msg, i);
				}
			};

			if (proc.stdout) createInterface({ input: proc.stdout }).on("line", handleLine);
			if (proc.stderr) createInterface({ input: proc.stderr }).on("line", handleLine);
			proc.on("error", (err) => this.logger.error(`worker ${i} error: ${err.message}`));

			proc.on("close", (code) => {
				this.logger.info(`child process ${i} exited with code ${code}`);
				if (this.processes) {
					const idx = this.processes.findIndex((p) => p.index === i);
					if (idx !== -1) {
						this.processes.splice(idx, 1);
						this.processPorts.splice(idx, 1);
					}
				}
				if (this.processes?.length === 0) {
					this.processes = undefined;
				}
			});

			try {
				await this.waitForWorker(port, proc);
			} catch (err) {
				this.signal("SIGKILL");
				throw err;
			}
		}
		return this;
	}

	private async waitForWorker(port: number, proc: ChildProcess): Promise<void> {
		const deadline = Date.now() + 10_000;
		while (Date.now() < deadline) {
			if (proc.exitCode !== null) {
				throw new Error(`wispurr: worker exited before becoming ready: code ${proc.exitCode})`);
			}
			const healthy = await new Promise<boolean>((resolve) => {
				const healthReq = request({ hostname: "127.0.0.1", port, path: "/health", timeout: 500 }, (res) => {
					res.resume();
					resolve(res.statusCode === 200);
				});
				healthReq.once("timeout", () => { healthReq.destroy(); resolve(false); });
				healthReq.once("error", () => resolve(false));
				healthReq.end();
			});
			if (healthy) return;
			await new Promise((resolve) => setTimeout(resolve, 50));
		}
		throw new Error(`wispurr: worker on port ${port} did not become ready within 10 seconds`);
	}

	private nextPort(): number | null {
		if (!this.processes) return null;
		const len = this.processPorts.length;
		if (len === 0) return null;
		const idx = this.reqIndex % len;
		const port = this.processPorts[idx] ?? null;
		this.reqIndex = (this.reqIndex + 1) % len;
		return port;
	}

	route(req: IncomingMessage, socket: Socket, head: Buffer) {
		const port = this.nextPort();
		if (port === null) {
			this.logger.error("wispurr is not running");
			socket.destroy();
			return;
		}

		const proxyReq = request({
			hostname: "127.0.0.1",
			port,
			path: req.url,
			method: req.method,
			headers: req.headers,
		});

		proxyReq.on("upgrade", (proxyRes, proxySocket, proxyHead) => {
			socket.write(
				`HTTP/1.1 101 Switching Protocols\r\n` +
				Object.entries(proxyRes.headers)
					.map(([k, v]) => `${k}: ${v}`)
					.join("\r\n") +
				"\r\n\r\n",
			);

			if (proxyHead?.length) proxySocket.unshift(proxyHead);
			if (head?.length) socket.unshift(head);

			proxySocket.pipe(socket);
			socket.pipe(proxySocket);

			proxySocket.on("error", () => socket.destroy());
			socket.on("error", () => proxySocket.destroy());
		});
		proxyReq.setTimeout(10_000, () => {
			proxyReq.destroy(new Error("worker upgrade timed out"));
		});

		proxyReq.on("response", (proxyRes) => {
			const status = proxyRes.statusCode ?? 502;
			const reason = proxyRes.statusMessage ?? "Bad Gateway";
			const headers = Object.entries(proxyRes.headers)
				.filter(([, value]) => value !== undefined)
				.map(([key, value]) => `${key}: ${Array.isArray(value) ? value.join(", ") : value}`)
				.join("\r\n");
			socket.write(`HTTP/1.1 ${status} ${reason}\r\n${headers}\r\nConnection: close\r\n\r\n`);
			proxyRes.pipe(socket);
			proxyRes.on("end", () => socket.end());
		});

		proxyReq.on("error", (err) => {
			this.logger.error(`proxy request error: ${err.message}`);
			socket.destroy();
		});

		proxyReq.end();
	}

	async stop(timeoutMs = 10_000): Promise<void> {
		if (!Number.isFinite(timeoutMs) || timeoutMs < 0) {
			throw new RangeError("wispurr: stop timeout must be a positive number");
		}
		const workers = this.processes ? [...this.processes] : [];
		if (workers.length === 0) {
			this.logger.warn("wispurr is not running");
			return;
		}

		const allExited = Promise.all(workers.map(({ process }) => {
			if (process.exitCode !== null || process.signalCode !== null) return Promise.resolve();
			return new Promise<void>((resolve) => process.once("close", () => resolve()));
		}));
		for (const { process } of workers) process.kill("SIGTERM");

		let timer: ReturnType<typeof setTimeout> | undefined;
		const graceful = await Promise.race([
			allExited.then(() => true),
			new Promise<boolean>((resolve) => { timer = setTimeout(() => resolve(false), timeoutMs); }),
		]);
		if (timer) clearTimeout(timer);
		if (!graceful) {
			for (const { process } of workers) {
				if (process.exitCode === null && process.signalCode === null) process.kill("SIGKILL");
			}
		}
		this.processes = undefined;
		this.processPorts = [];
	}

	kill() { this.signal("SIGKILL"); }

	private signal(sig: "SIGTERM" | "SIGKILL") {
		if (this.processes) {
			for (const { process } of this.processes) process.kill(sig);
			this.processes = undefined;
			this.processPorts = [];
		} else {
			this.logger.warn("wispurr is not running");
		}
	}
}
