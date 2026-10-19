import { chmodSync, copyFileSync, mkdirSync, rmSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const root = fileURLToPath(new URL("../", import.meta.url));
process.chdir(root);
rmSync("bin", { recursive: true, force: true });

for (const [platform, goos] of [["linux", "linux"], ["darwin", "darwin"], ["win32", "windows"]]) {
	for (const [arch, goarch] of [["x64", "amd64"], ["arm64", "arm64"]]) {
		const directory = `bin/${platform}-${arch}`;
		const binary = `${directory}/wispurr${platform === "win32" ? ".exe" : ""}`;
		mkdirSync(directory, { recursive: true });
		const result = spawnSync("go", ["build", "-o", binary, "main.go"], {
			stdio: "inherit",
			env: { ...process.env, CGO_ENABLED: "0", GOOS: goos, GOARCH: goarch },
		});
		if (result.error) throw result.error;
		if (result.status !== 0) process.exit(result.status ?? 1);
		chmodSync(binary, 0o755);
	}
}

mkdirSync("dist", { recursive: true });
copyFileSync("example.config.json", "dist/config.json");
console.log("Built native binaries for Linux, macOS, and Windows (x64/arm64).");
