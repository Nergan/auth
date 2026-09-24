import { signPayload, setStoredCounter, getAndIncrementCounter, generateRandomNonce } from './crypto.js';

export class LockTimeoutError extends Error {
    constructor(message = "CrossTabCounterMutex lock acquisition timeout") {
        super(message);
        this.name = "LockTimeoutError";
    }
}

class CrossTabCounterMutex {
    async acquireCounter(userId) {
        if (typeof navigator !== "undefined" && navigator.locks && navigator.locks.request) {
            return navigator.locks.request(`counter_lock_${userId}`, async () => {
                return getAndIncrementCounter(userId);
            });
        }
        return getAndIncrementCounter(userId);
    }

    async setCounter(userId, nextCounter) {
        const bigIntCounter = BigInt(nextCounter);
        if (typeof navigator !== "undefined" && navigator.locks && navigator.locks.request) {
            return navigator.locks.request(`counter_lock_${userId}`, async () => {
                await setStoredCounter(userId, bigIntCounter);
            });
        }
        await setStoredCounter(userId, bigIntCounter);
    }
}

const counterMutex = new CrossTabCounterMutex();

export function normalizeContentType(contentType) {
    if (!contentType) return "";
    const parts = contentType.split(";").map(p => p.trim()).filter(Boolean);
    if (parts.length === 0) return "";

    const essence = parts[0].toLowerCase();
    const params = [];

    for (let i = 1; i < parts.length; i++) {
        const param = parts[i];
        if (param.includes("=")) {
            const [k, ...v] = param.split("=");
            params.push([k.trim().toLowerCase(), v.join("=").trim().replace(/^"|"$/g, '')]);
        }
    }

    params.sort((a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0));
    if (params.length === 0) return essence;

    const paramStr = params.map(([k, v]) => `${k}=${v}`).join(";");
    return `${essence};${paramStr}`;
}

export function normalizeHost(host) {
    if (!host) return "";
    const clean = host.trim().toLowerCase();
    if (clean.startsWith("[")) {
        const closingIndex = clean.indexOf("]");
        if (closingIndex !== -1) {
            const bracketed = clean.slice(0, closingIndex + 1);
            const rest = clean.slice(closingIndex + 1);
            if (rest.startsWith(":")) {
                const port = rest.slice(1);
                if (port === "80" || port === "443") return bracketed;
                return `${bracketed}:${port}`;
            }
            return bracketed;
        }
    } else if (clean.includes(":")) {
        const parts = clean.split(":");
        if (parts.length === 2) {
            const [hostname, port] = parts;
            if (port === "80" || port === "443") return hostname;
        }
    }
    return clean;
}

export function removeDotSegments(path) {
    if (!path) return "/";
    let input = path;
    const output = [];

    while (input.length > 0) {
        if (input.startsWith("../")) input = input.slice(3);
        else if (input.startsWith("./")) input = input.slice(2);
        else if (input.startsWith("/./")) input = "/" + input.slice(3);
        else if (input === "/.") input = "/";
        else if (input.startsWith("/../")) {
            input = "/" + input.slice(4);
            if (output.length > 0) output.pop();
        } else if (input === "/..") {
            input = "/";
            if (output.length > 0) output.pop();
        } else if (input === "." || input === "..") input = "";
        else {
            let nextSlash = input.startsWith("/") ? input.indexOf("/", 1) : input.indexOf("/");
            if (nextSlash !== -1) {
                output.push(input.slice(0, nextSlash));
                input = input.slice(nextSlash);
            } else {
                output.push(input);
                input = "";
            }
        }
    }

    let result = output.join("");
    if (!result.startsWith("/")) result = "/" + result;
    return result;
}

const UNRESERVED = new Set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_.~".split("").map(c => c.charCodeAt(0)));

export function normalizePercentEncoding(str) {
    return str.replace(/%([0-9a-fA-F]{2})/g, (match, hex) => {
        const byteVal = parseInt(hex, 16);
        return UNRESERVED.has(byteVal) ? String.fromCharCode(byteVal) : "%" + hex.toUpperCase();
    });
}

export function normalizePath(path) {
    if (!path) return "/";
    let normalized = normalizePercentEncoding(path.trim());
    normalized = removeDotSegments(normalized);
    normalized = normalized.replace(/\/+/g, "/");
    if (!normalized.startsWith("/")) normalized = "/" + normalized;
    return normalizePercentEncoding(normalized);
}

export function rfc3986Encode(str) {
    return encodeURIComponent(str).replace(/[!'()*]/g, c => `%${c.charCodeAt(0).toString(16).toUpperCase()}`);
}

export function normalizeQuery(queryInput) {
    if (!queryInput) return "";
    let searchParams = typeof queryInput === "string" ? new URLSearchParams(queryInput.startsWith("?") ? queryInput.slice(1) : queryInput) : queryInput;
    const params = [];
    searchParams.forEach((val, key) => params.push([key, val]));
    params.sort((a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : a[1] < b[1] ? -1 : a[1] > b[1] ? 1 : 0));
    return params.map(([k, v]) => `${rfc3986Encode(k)}=${rfc3986Encode(v)}`).join("&");
}

export function buildCanonicalPayload(host, method, path, query, timestamp, counter, bodyHash, contentType = "") {
    const normHost = normalizeHost(host);
    const normMethod = method.trim().toUpperCase();
    const normPath = normalizePath(path);
    const normQuery = normalizeQuery(query);
    const normCt = normalizeContentType(contentType);

    const components = [
        normHost,
        normMethod,
        normPath,
        normQuery,
        timestamp.toString(),
        `counter:${counter.toString()}`,
        normCt,
        bodyHash
    ];
    return components.map(c => `${new TextEncoder().encode(c).length}:${c}\n`).join('');
}

export function buildSyncCanonicalPayload(host, method, path, query, timestamp, syncNonce, bodyHash, contentType = "") {
    const normHost = normalizeHost(host);
    const normMethod = method.trim().toUpperCase();
    const normPath = normalizePath(path);
    const normQuery = normalizeQuery(query);
    const normCt = normalizeContentType(contentType);

    const components = [
        normHost,
        normMethod,
        normPath,
        normQuery,
        timestamp.toString(),
        `sync:${syncNonce}`,
        normCt,
        bodyHash
    ];
    return components.map(c => `${new TextEncoder().encode(c).length}:${c}\n`).join('');
}

async function serializeBody(body, explicitContentType) {
    if (body === undefined || body === null) {
        return { bodyBytes: new Uint8Array(0), inferredContentType: explicitContentType || "" };
    }
    if (typeof body === "string") {
        return { bodyBytes: new TextEncoder().encode(body), inferredContentType: explicitContentType || "application/json" };
    }
    if (body instanceof Uint8Array) {
        return { bodyBytes: body, inferredContentType: explicitContentType || "application/octet-stream" };
    }
    return { bodyBytes: new TextEncoder().encode(JSON.stringify(body)), inferredContentType: explicitContentType || "application/json" };
}

export async function fetchWithAuth(url, options = {}, userId, maxRetries = 3) {
    return executeRequest(url, options, userId, 0, maxRetries);
}

async function executeRequest(url, options, userId, retryCount = 0, maxRetries = 3) {
    const method = (options.method || "GET").toUpperCase();
    const urlObj = new URL(url, window.location.origin);

    const host = urlObj.host;
    const path = urlObj.pathname;
    const query = normalizeQuery(urlObj.searchParams);
    const timestamp = Math.floor(Date.now() / 1000);

    const nonceCounter = await counterMutex.acquireCounter(userId);

    const requestHeaders = new Headers(options.headers || {});
    const explicitContentType = requestHeaders.get("Content-Type") || "";

    const { bodyBytes, inferredContentType } = await serializeBody(options.body, explicitContentType);
    const bodyHashBuffer = await window.crypto.subtle.digest('SHA-256', bodyBytes);
    const bodyHash = Array.from(new Uint8Array(bodyHashBuffer))
        .map(b => b.toString(16).padStart(2, '0'))
        .join('');

    const payload = buildCanonicalPayload(host, method, path, query, timestamp, nonceCounter, bodyHash, inferredContentType);
    const signature = await signPayload(userId, payload);

    requestHeaders.set("X-User-Id", userId);
    requestHeaders.set("X-Timestamp", timestamp.toString());
    requestHeaders.set("X-Nonce-Counter", nonceCounter.toString());
    requestHeaders.set("X-Signature", signature);

    if (inferredContentType && !requestHeaders.has("Content-Type")) {
        requestHeaders.set("Content-Type", inferredContentType);
    }

    const fetchOptions = {
        ...options,
        headers: requestHeaders,
        body: (method !== "GET" && method !== "HEAD" && bodyBytes.byteLength > 0) ? bodyBytes : undefined
    };

    const response = await fetch(url, fetchOptions);

    if (response.status === 409 && retryCount < maxRetries) {
        const errorData = await response.clone().json().catch(() => ({}));
        if (errorData.detail?.code === "nonce_conflict" && errorData.detail.expected !== undefined) {
            await counterMutex.setCounter(userId, BigInt(errorData.detail.expected));
            return executeRequest(url, options, userId, retryCount + 1, maxRetries);
        }
    }

    return response;
}

export async function syncNonceWithServer(url, userId) {
    const urlObj = new URL(url, window.location.origin);
    const host = urlObj.host;
    const path = urlObj.pathname;
    const query = normalizeQuery(urlObj.searchParams);
    const timestamp = Math.floor(Date.now() / 1000);
    const syncNonce = generateRandomNonce(16);

    const bodyHash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    const payload = buildSyncCanonicalPayload(host, "GET", path, query, timestamp, syncNonce, bodyHash, "");
    const signature = await signPayload(userId, payload);

    const headers = new Headers({
        "X-User-Id": userId,
        "X-Timestamp": timestamp.toString(),
        "X-Sync-Nonce": syncNonce,
        "X-Signature": signature
    });

    const response = await fetch(url, { method: "GET", headers });
    if (response.ok) {
        const data = await response.json();
        await counterMutex.setCounter(userId, BigInt(data.nonce_counter));
        return BigInt(data.nonce_counter);
    }
    throw new Error(`Sync failed with status ${response.status}`);
}