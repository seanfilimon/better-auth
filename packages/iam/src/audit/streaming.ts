import type { AuditEvent } from "../types";

export type EventHandler = (event: AuditEvent) => void | Promise<void>;

export function createEventStreamer(handlers: EventHandler[]) {
	return {
		async emit(event: AuditEvent) {
			await Promise.allSettled(handlers.map((h) => h(event)));
		},
		addHandler(handler: EventHandler) {
			handlers.push(handler);
		},
	};
}
