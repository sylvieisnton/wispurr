import chalk from "chalk";

export type LogLevel = "debug" | "info" | "warn" | "error" | "none";

const levelPriority: Record<LogLevel, number> = {
	debug: 0,
	info: 1,
	warn: 2,
	error: 3,
	none: 4,
};

export class Logger {
	constructor(public level: LogLevel = "info") {}

	private shouldLog(method: Exclude<LogLevel, "none">): boolean {
		return levelPriority[method] >= levelPriority[this.level];
	}

	private write(message: string, color: string, index?: number) {
		const tag = index !== undefined ? `mrrowisp-${index}` : "mrrowisp";
		console.log(chalk.bold(chalk.hex(color)(`[${tag}]: ${message}`)));
	}

	info(message: string, index?: number) {
		if (!this.shouldLog("info")) return;
		this.write(message, "#ebaaee", index);
	}
	error(message: string, index?: number) {
		if (!this.shouldLog("error")) return;
		this.write(message, "#f38fad", index);
	}
	warn(message: string, index?: number) {
		if (!this.shouldLog("warn")) return;
		this.write(message, "#f9dca1", index);
	}
	debug(message: string, index?: number) {
		if (!this.shouldLog("debug")) return;
		this.write(message, "#89b4fa", index);
	}
}
