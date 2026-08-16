import { signPayload, getStoredCounter, setStoredCounter, getAndIncrementCounter, generateRandomNonce } from './crypto.js';

export class LockTimeoutError extends Error {
    constructor(message = "CrossTabCounterMutex lock acquisition timeout") {
        super(message);
        this.name = "LockTimeoutError";
    }
}

function isLocalStorageAvailable() {
    try {
        if (typeof window === "undefined" || !window.localStorage) {
            return false;
        }
        const testKey = "__storage_test__";
        window.localStorage.setItem(testKey, "1");
        window.localStorage.removeItem(testKey);
        return true;
    } catch {
        return false;
    }
}

class CrossTabCounterMutex {
    constructor() {
        this._taskQueue = [];
        this._isProcessing = false;
    }

    async acquireCounter(userId) {
        if (typeof navigator !== "undefined" && navigator.locks && navigator.locks.request) {
            return navigator.locks.request(`counter_lock_${userId}`, async () => {
                return getAndIncrementCounter(userId);
            });
        }

        return this._enqueue(userId, async () => {
            return this._withCrossTabLock(userId, async () => {
                return getAndIncrementCounter(userId);
            });
        });
    }

    async setCounter(userId, nextCounter) {
        const bigIntCounter = BigInt(nextCounter);
        if (typeof navigator !== "undefined" && navigator.locks && navigator.locks.request) {
            return navigator.locks.request(`counter_lock_${userId}`, async () => {
                await setStoredCounter(userId, bigIntCounter);
            });
        }

        return this._enqueue(userId, async () => {
            return this._withCrossTabLock(userId, async () => {
                await setStoredCounter(userId, bigIntCounter);
            });
        });
    }

    _enqueue(userId, task) {
        return new Promise((resolve, reject) => {
            this._taskQueue.push({ task, resolve, reject });
            this._processQueue();
        });
    }

    async _processQueue() {
        if (this._isProcessing) return;
        this._isProcessing = true;

        while (this._taskQueue.length > 0) {
            const item = this._taskQueue.shift();
            try {
                const result = await item.task();
                item.resolve(result);
            } catch (err) {
                item.reject(err);
            }
        }

        this._isProcessing = false;
    }

    async _withCrossTabLock(userId, action) {
        if (!isLocalStorageAvailable()) {
            return action();
        }

        const lockKey = `__tab_counter_lock_${userId}`;
        const lockToken = Math.random().toString(36).substring(2) + Date.now().toString(36);
        const lockTimeout = 5000;
        const pollInterval = 25;
        const maxWaitTime = 10000;
        const startTime = Date.now();
        let lockAcquired = false;

        while (true) {
            const now = Date.now();
            let currentLock = null;

            try {
                currentLock = localStorage.getItem(lockKey);
            } catch {
                return action();
            }

            if (!currentLock) {
                try {
                    localStorage.setItem(lockKey, JSON.stringify({ token: lockToken, expires: now + lockTimeout }));
                } catch {
                    return action();
                }

                await new Promise(res => setTimeout(res, 5 + Math.floor(Math.random() * 15)));

                try {
                    const verify = JSON.parse(localStorage.getItem(lockKey) || "{}");
                    if (verify.token === lockToken) {
                        lockAcquired = true;
                        break;
                    }
                } catch {
                    // Retry on parse error
                }
            } else {
                try {
                    const parsed = JSON.parse(currentLock);
                    if (parsed.expires && now > parsed.expires) {
                        localStorage.removeItem(lockKey);
                        continue;
                    }
                } catch {
                    try {
                        localStorage.removeItem(lockKey);
                    } catch {
                        return action();
                    }
                    continue;
                }
            }

            if (now - startTime > maxWaitTime) {
                throw new LockTimeoutError(`Failed to acquire cross-tab lock for user ${userId} within ${maxWaitTime}ms`);
            }
            await new Promise(res => setTimeout(res, pollInterval));
        }

        try {
            return await action();
        } finally {
            if (lockAcquired) {
                try {
                    const existing = JSON.parse(localStorage.getItem(lockKey) || "{}");
                    if (existing.token === lockToken) {
                        localStorage.removeItem(lockKey);
                    }
                } catch {
                    // Ignore storage release errors
                }
            }
        }
    }
}

const counterMutex = new CrossTabCounterMutex();

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
                if (port === "80" || port === "443") {
                    return bracketed;
                }
                return `${bracketed}:${port}`;
            }
            return bracketed;
        }
    } else if (clean.includes(":")) {
        const parts = clean.split(":");
        if (parts.length === 2) {
            const [hostname, port] = parts;
            if (port === "80" || port === "443") {
                return hostname;
            }
        }
    }
    return clean;
}

export function removeDotSegments(path) {
    if (!path) return "/";
    let input = path;
    const output = [];

    while (input.length > 0) {
        if (input.startsWith("../")) {
            input = input.slice(3);
        } else if (input.startsWith("./")) {
            input = input.slice(2);
        } else if (input.startsWith("/./")) {
            input = "/" + input.slice(3);
        } else if (input === "/.") {
            input = "/";
        } else if (input.startsWith("/../")) {
            input = "/" + input.slice(4);
            if (output.length > 0) output.pop();
        } else if (input === "/..") {
            input = "/";
            if (output.length > 0) output.pop();
        } else if (input === "." || input === "..") {
            input = "";
        } else {
            let nextSlash = -1;
            if (input.startsWith("/")) {
                nextSlash = input.indexOf("/", 1);
            } else {
                nextSlash = input.indexOf("/");
            }
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
        if (UNRESERVED.has(byteVal)) {
            return String.fromCharCode(byteVal);
        }
        return "%" + hex.toUpperCase();
    });
}

export function normalizePath(path) {
    if (!path) return "/";
    // Canonical ordering: decode unreserved percent-encodings first before removing dot segments
    let normalized = normalizePercentEncoding(path.trim());
    normalized = removeDotSegments(normalized);
    normalized = normalized.replace(/\/+/g, "/");
    if (!normalized.startsWith("/")) normalized = "/" + normalized;
    return normalizePercentEncoding(normalized);
}

export function rfc3986Encode(str) {
    return encodeURIComponent(str).replace(/[!'()*]/g, c => `%${c.charCodeAt(0).toString(16).toUpperCase()}`);
}

function codePointCompare(a, b) {
    const cpA = Array.from(a).map(c => c.codePointAt(0));
    const cpB = Array.from(b).map(c => c.codePointAt(0));
    const len = Math.min(cpA.length, cpB.length);
    for (let i = 0; i < len; i++) {
        if (cpA[i] !== cpB[i]) return cpA[i] - cpB[i];
    }
    return cpA.length - cpB.length;
}

export function normalizeQuery(queryInput) {
    if (!queryInput) return "";
    let searchParams;

    if (typeof queryInput === "string") {
        const clean = queryInput.startsWith("?") ? queryInput.slice(1) : queryInput;
        searchParams = new URLSearchParams(clean);
    } else if (typeof URLSearchParams !== "undefined" && queryInput instanceof URLSearchParams) {
        searchParams = queryInput;
    } else if (typeof queryInput === "object") {
        searchParams = new URLSearchParams();
        for (const [k, v] of Object.entries(queryInput)) {
            if (Array.isArray(v)) {
                v.forEach(val => searchParams.append(k, String(val)));
            } else if (v !== undefined && v !== null) {
                searchParams.append(k, String(v));
            }
        }
    } else {
        return "";
    }

    const params = [];
    searchParams.forEach((val, key) => {
        params.push([key, val]);
    });
    params.sort((a, b) => {
        const keyCmp = codePointCompare(a[0], b[0]);
        if (keyCmp !== 0) return keyCmp;
        return codePointCompare(a[1], b[1]);
    });
    return params.map(([k, v]) => `${rfc3986Encode(k)}=${rfc3986Encode(v)}`).join("&");
}

export function buildCanonicalPayload(host, method, path, query, timestamp, counter, bodyHash) {
    const normHost = normalizeHost(host);
    const normMethod = method.trim().toUpperCase();
    const normPath = normalizePath(path);
    const normQuery = normalizeQuery(query);

    const components = [normHost, normMethod, normPath, normQuery, timestamp.toString(), `counter:${counter.toString()}`, bodyHash];
    return components.map(c => `${new TextEncoder().encode(c).length}:${c}\n`).join('');
}

export function buildSyncCanonicalPayload(host, method, path, query, timestamp, syncNonce, bodyHash) {
    const normHost = normalizeHost(host);
    const normMethod = method.trim().toUpperCase();
    const normPath = normalizePath(path);
    const normQuery = normalizeQuery(query);

    const components = [normHost, normMethod, normPath, normQuery, timestamp.toString(), `sync:${syncNonce}`, bodyHash];
    return components.map(c => `${new TextEncoder().encode(c).length}:${c}\n`).join('');
}

async function serializeBody(body, explicitContentType) {
    if (body === undefined || body === null) {
        return { bodyBytes: new Uint8Array(0), inferredContentType: null };
    }
    if (typeof ReadableStream !== "undefined" && body instanceof ReadableStream) {
        throw new Error("ReadableStream cannot be signed deterministically; buffer into Uint8Array first.");
    }
    if (typeof body === "string") {
        return {
            bodyBytes: new TextEncoder().encode(body),
            inferredContentType: explicitContentType || "application/json"
        };
    }
    if (body instanceof Uint8Array) {
        return { bodyBytes: body, inferredContentType: explicitContentType || "application/octet-stream" };
    }
    if (body instanceof ArrayBuffer) {
        return { bodyBytes: new Uint8Array(body), inferredContentType: explicitContentType || "application/octet-stream" };
    }
    if (typeof Blob !== "undefined" && body instanceof Blob) {
        return { bodyBytes: new Uint8Array(await body.arrayBuffer()), inferredContentType: explicitContentType || body.type || "application/octet-stream" };
    }
    if (typeof URLSearchParams !== "undefined" && body instanceof URLSearchParams) {
        return { bodyBytes: new TextEncoder().encode(body.toString()), inferredContentType: "application/x-www-form-urlencoded;charset=UTF-8" };
    }
    if (typeof FormData !== "undefined" && body instanceof FormData) {
        throw new Error("FormData cannot be signed deterministically; convert to JSON or binary bytes first.");
    }
    return { bodyBytes: new TextEncoder().encode(JSON.stringify(body)), inferredContentType: "application/json" };
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

    const existingHeaders = new Headers(options.headers || {});
    const explicitContentType = existingHeaders.get("Content-Type");

    const { bodyBytes, inferredContentType } = await serializeBody(options.body, explicitContentType);
    const bodyHashBuffer = await window.crypto.subtle.digest('SHA-256', bodyBytes);
    const bodyHash = Array.from(new Uint8Array(bodyHashBuffer))
        .map(b => b.toString(16).padStart(2, '0'))
        .join('');

    const payload = buildCanonicalPayload(host, method, path, query, timestamp, nonceCounter, bodyHash);
    const signature = await signPayload(userId, payload);

    existingHeaders.set("X-User-Id", userId);
    existingHeaders.set("X-Timestamp", timestamp.toString());
    existingHeaders.set("X-Nonce-Counter", nonceCounter.toString());
    existingHeaders.set("X-Signature", signature);

    if (inferredContentType && !existingHeaders.has("Content-Type")) {
        existingHeaders.set("Content-Type", inferredContentType);
    }

    const fetchOptions = {
        ...options,
        headers: existingHeaders,
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
    const payload = buildSyncCanonicalPayload(host, "GET", path, query, timestamp, syncNonce, bodyHash);
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