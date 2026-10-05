import type { IncomingMessage, Server } from "node:http";
import type { Http2SecureServer } from "node:http2";
import { Socket } from "node:net";
import { wispurr, type wispurrOptions } from "./index.js";

type ViteServer = {
	httpServer: Server | Http2SecureServer | null;
	config: { logger: { warn(msg: string): void } };
};

export type wispurrVitePlugin = {
	name: string;
	configureServer(server: ViteServer): Promise<void>;
	configurePreviewServer(server: ViteServer): Promise<void>;
};

export type wispurrViteOptions = {
	path: string | ((req: IncomingMessage) => boolean);
	config?: wispurrOptions;
	workers?: number;
	apply?: "serve" | "preview" | "both";
};

export function wispurrVite(options: wispurrViteOptions): wispurrVitePlugin {
	const apply = options.apply ?? "both";
	const matches =
		typeof options.path === "function"
			? options.path
			: (req: IncomingMessage) =>
					new URL(req.url ?? "/", "http://localhost").pathname.startsWith(
						options.path as string,
					);

	async function attach(server: ViteServer) {
		const { httpServer } = server;
		if (!httpServer) {
			server.config.logger.warn(
				"[wispurr] Vite has no HTTP server (middleware mode); attach wisp.route() to your own server instead.",
			);
			return;
		}
		const wisp = new wispurr({ host: "127.0.0.1", ...options.config });
		await wisp.start(options.workers ?? 1);

		httpServer.on("upgrade", (req, socket, head) => {
			if (socket instanceof Socket && matches(req)) wisp.route(req, socket, head);
		});

		const killWorkers = () => {
			if (wisp.isRunning) wisp.kill();
		};
		process.once("exit", killWorkers);
		httpServer.once("close", () => {
			process.removeListener("exit", killWorkers);
			if (wisp.isRunning) void wisp.stop();
		});
	}

	return {
		name: "wispurr",
		async configureServer(server) {
			if (apply !== "preview") await attach(server);
		},
		async configurePreviewServer(server) {
			if (apply !== "serve") await attach(server);
		},
	};
}
