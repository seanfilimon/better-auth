import type { IamAdapter } from "../adapter";
import { REDACTED_FIELDS_DEFAULT } from "../constants";
import type {
	AuditEvent,
	AuditEventSource,
	AuditResponseStatus,
} from "../types";
import type { EventHandler } from "./streaming";
import { createEventStreamer } from "./streaming";

export function createAuditLogger(
	iamAdapter: IamAdapter,
	config: {
		enabled: boolean;
		redactedFields?: string[];
		onEvent?: (event: AuditEvent) => void | Promise<void>;
		eventHandlers?: EventHandler[];
	},
) {
	const redactedFields = new Set([
		...REDACTED_FIELDS_DEFAULT,
		...(config.redactedFields ?? []),
	]);

	const streamerHandlers: EventHandler[] = [...(config.eventHandlers ?? [])];
	if (config.onEvent) {
		streamerHandlers.push(config.onEvent);
	}
	const streamer =
		streamerHandlers.length > 0 ? createEventStreamer(streamerHandlers) : null;

	function redactParams(
		params: Record<string, unknown>,
	): Record<string, unknown> {
		const redacted: Record<string, unknown> = {};
		for (const [key, value] of Object.entries(params)) {
			if (redactedFields.has(key)) {
				redacted[key] = "[REDACTED]";
			} else if (value && typeof value === "object" && !Array.isArray(value)) {
				redacted[key] = redactParams(value as Record<string, unknown>);
			} else {
				redacted[key] = value;
			}
		}
		return redacted;
	}

	return {
		async log(params: {
			eventType: string;
			eventSource: AuditEventSource;
			principalId: string;
			principalType: string;
			action: string;
			resource?: string;
			sourceIp?: string;
			userAgent?: string;
			requestParams?: Record<string, unknown>;
			responseStatus: AuditResponseStatus;
			errorCode?: string;
			sessionId?: string;
			mfaAuthenticated?: boolean;
		}) {
			if (!config.enabled) return;

			const id = crypto.randomUUID();
			const event: AuditEvent = {
				id,
				eventTime: new Date(),
				eventType: params.eventType,
				eventSource: params.eventSource,
				principalId: params.principalId,
				principalType: params.principalType,
				action: params.action,
				resource: params.resource ?? "",
				sourceIp: params.sourceIp ?? "",
				userAgent: params.userAgent ?? "",
				requestParams: params.requestParams
					? redactParams(params.requestParams)
					: {},
				responseStatus: params.responseStatus,
				errorCode: params.errorCode,
				sessionId: params.sessionId,
				mfaAuthenticated: params.mfaAuthenticated ?? false,
			};

			try {
				await iamAdapter.createAuditLog({
					id: event.id,
					eventTime: event.eventTime,
					eventType: event.eventType,
					eventSource: event.eventSource,
					principalId: event.principalId,
					principalType: event.principalType,
					action: event.action,
					resource: event.resource,
					sourceIp: event.sourceIp,
					userAgent: event.userAgent,
					requestParams: event.requestParams,
					responseStatus: event.responseStatus,
					errorCode: event.errorCode,
					sessionId: event.sessionId,
					mfaAuthenticated: event.mfaAuthenticated,
				});
			} catch {
				// Audit logging should not break the request
			}

			if (streamer) {
				try {
					await streamer.emit(event);
				} catch {
					// External event delivery should not break the request
				}
			}
		},
	};
}

export type AuditLogger = ReturnType<typeof createAuditLogger>;
