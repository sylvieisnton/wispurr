export type PortEntry = number | [number, number];

export type FilterList = {
	hostnames: string[] | Record<string, unknown>;
	ports: PortEntry[] | Record<string, unknown>;
};

export type FloodProtectionConfig = {
	enabled: boolean;
	maxConnectsPerSourceIPPerSecond?: number;
	maxConnectsPerDestPerSecond?: number;
	maxConnectsPerDestPerMinute?: number;
	maxInFlightSyns?: number;
	maxConcurrentStreamsPerConnection?: number;
	maxConcurrentConnections?: number;
	synFloodSignature?: {
		enabled: boolean;
		windowMs: number;
		minSamples: number;
		failedHandshakeRatio: number;
	};
	wsCloseAfterViolations?: number;
	logBlockedDials?: boolean;
};

export type ReputationConfig = {
	enabled: boolean;
	storePath?: string;
	saveIntervalSeconds?: number;
	scoreDecayPerHour?: number;
	evictAfterDays?: number;
	thresholds?: { warn: number; throttle: number; strict: number };
	weights?: Record<string, number>;
	destinationWeights?: Record<string, number>;
};

export type wispurrConfig = {
	port: number | number[];
	allowTCP: boolean;
	allowUDP: boolean;
	allowDirectIP: boolean;
	allowPrivateIPs: boolean;
	allowLoopbackIPs: boolean;
	tcpBufferSize: number;
	bufferRemainingLength: number;
	tcpNoDelay: boolean;
	socketBufferSize: number;
	pendingQueueSize: number;
	blacklist: FilterList;
	whitelist: FilterList;
	websocketPermessageDeflate: boolean;
	dnsServers: string[];
	dnsMethod: "lookup" | "resolve";
	dnsResultOrder: "ipv4first" | "ipv6first" | "verbatim";
	enableTwisp: boolean;
	enableV2: boolean;
	handshakeTimeoutSeconds: number;
	motd: string;
	passwordAuth: boolean;
	passwordAuthRequired: boolean;
	passwordUsers: Record<string, string>;
	parseRealIP: boolean;
	trustedProxies: string[];
	trustedHeaders: string[];
	nonWSResponse: string;
	logLevel: "debug" | "info" | "warn" | "error" | "none";
	proxy: string;
	maxMessageSize: number;
	staticDir: string;
	bandwidthLimitKbps: number;
	connectionsLimitPerIP: number;
	connectionWindowSeconds: number;
	floodProtection: FloodProtectionConfig;
	reputation: ReputationConfig;
};

export type wispurrOptions = Omit<Partial<wispurrConfig>, "blacklist" | "whitelist" | "floodProtection" | "reputation"> & {
	blacklist?: Partial<FilterList>;
	whitelist?: Partial<FilterList>;
	floodProtection?: Partial<Omit<FloodProtectionConfig, "synFloodSignature">> & {
		synFloodSignature?: Partial<NonNullable<FloodProtectionConfig["synFloodSignature"]>>;
	};
	reputation?: Partial<Omit<ReputationConfig, "thresholds">> & {
		thresholds?: Partial<NonNullable<ReputationConfig["thresholds"]>>;
	};
};
