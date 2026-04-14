export function safeJsonParse<T>(value: unknown, fallback: T): T {
	if (value === null || value === undefined) return fallback;
	if (typeof value === "object") return value as T;
	if (typeof value !== "string") return fallback;
	try {
		return JSON.parse(value) as T;
	} catch {
		return fallback;
	}
}
