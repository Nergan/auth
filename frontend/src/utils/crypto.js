const DB_NAME = "AuthDB";
const KEY_STORE_NAME = "Keys";
const COUNTER_STORE_NAME = "Counters";

let dbInstancePromise = null;

export async function getDB() {
    if (dbInstancePromise) {
        return dbInstancePromise;
    }
    dbInstancePromise = new Promise((resolve, reject) => {
        const request = indexedDB.open(DB_NAME, 4);
        request.onupgradeneeded = (event) => {
            const db = event.target.result;
            if (!db.objectStoreNames.contains(KEY_STORE_NAME)) {
                db.createObjectStore(KEY_STORE_NAME, { keyPath: "id" });
            }
            if (!db.objectStoreNames.contains(COUNTER_STORE_NAME)) {
                db.createObjectStore(COUNTER_STORE_NAME, { keyPath: "id" });
            }
        };
        request.onsuccess = () => {
            const db = request.result;
            db.onversionchange = () => {
                db.close();
                dbInstancePromise = null;
            };
            db.onclose = () => {
                dbInstancePromise = null;
            };
            db.onerror = () => {
                dbInstancePromise = null;
            };
            resolve(db);
        };
        request.onerror = () => {
            dbInstancePromise = null;
            reject(request.error);
        };
    });
    return dbInstancePromise;
}

export function uint8ArrayToBase64(bytes) {
    let binary = '';
    const len = bytes.byteLength;
    const chunkSize = 0x8000;
    for (let i = 0; i < len; i += chunkSize) {
        binary += String.fromCharCode.apply(
            null,
            bytes.subarray(i, Math.min(i + chunkSize, len))
        );
    }
    return btoa(binary);
}

/**
 * Generates a cryptographically secure random hexadecimal nonce.
 * Clamps byte count to 8-32 bytes producing 16-64 hex characters to adhere to API constraints.
 * @param {number} byteLength - Number of random bytes (default 16 bytes = 32 hex chars).
 * @returns {string} Hexadecimal string representation.
 */
export function generateRandomNonce(byteLength = 16) {
    const clampedBytes = Math.max(8, Math.min(32, byteLength));
    const bytes = new Uint8Array(clampedBytes);
    window.crypto.getRandomValues(bytes);
    return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

export async function generateKey() {
    const algorithm = "RSA-PSS-SHA256";
    const keyPair = await window.crypto.subtle.generateKey(
        {
            name: "RSA-PSS",
            modulusLength: 2048,
            publicExponent: new Uint8Array([1, 0, 1]),
            hash: "SHA-256",
        },
        false,
        ["sign", "verify"]
    );

    const spki = await window.crypto.subtle.exportKey("spki", keyPair.publicKey);
    const rawKeyBytes = new Uint8Array(spki);
    const b64 = uint8ArrayToBase64(rawKeyBytes);
    const exportedPubKey = `-----BEGIN PUBLIC KEY-----\n${b64.match(/.{1,64}/g).join('\n')}\n-----END PUBLIC KEY-----`;

    return { keyPair, exportedPubKey, rawKeyBytes, algorithm };
}

export async function signRegistrationProof(privateKey, algorithm, canonicalKeyBytes, timestamp, clientNonce) {
    const keyHex = Array.from(canonicalKeyBytes).map(b => b.toString(16).padStart(2, '0')).join('');
    const components = ["register_pop", algorithm, keyHex, timestamp.toString(), clientNonce];
    const challenge = components.map(c => `${new TextEncoder().encode(c).length}:${c}\n`).join('');

    const data = new TextEncoder().encode(challenge);
    const signature = await window.crypto.subtle.sign(
        { name: "RSA-PSS", saltLength: 32 },
        privateKey,
        data
    );
    return uint8ArrayToBase64(new Uint8Array(signature));
}

export async function storeKey(userId, keyPair, algorithm) {
    const db = await getDB();
    return new Promise((resolve, reject) => {
        const tx = db.transaction(KEY_STORE_NAME, "readwrite");
        const store = tx.objectStore(KEY_STORE_NAME);

        tx.oncomplete = () => resolve();
        tx.onerror = () => reject(tx.error);
        tx.onabort = () => reject(new Error("IndexedDB transaction aborted"));

        store.put({
            id: userId,
            privateKey: keyPair.privateKey,
            algorithm
        });
    });
}

export async function getStoredCounter(userId) {
    const db = await getDB();
    return new Promise((resolve, reject) => {
        const tx = db.transaction(COUNTER_STORE_NAME, "readonly");
        const store = tx.objectStore(COUNTER_STORE_NAME);
        const req = store.get(userId);

        req.onsuccess = () => {
            if (!req.result || req.result.counter === undefined || req.result.counter === null) {
                resolve(1n);
            } else {
                try {
                    resolve(BigInt(req.result.counter));
                } catch {
                    resolve(1n);
                }
            }
        };
        req.onerror = () => reject(req.error);
        tx.onabort = () => reject(new Error("IndexedDB transaction aborted"));
    });
}

export async function getAndIncrementCounter(userId) {
    const db = await getDB();
    return new Promise((resolve, reject) => {
        const tx = db.transaction(COUNTER_STORE_NAME, "readwrite");
        const store = tx.objectStore(COUNTER_STORE_NAME);
        const req = store.get(userId);

        req.onsuccess = () => {
            let current = 1n;
            if (req.result && req.result.counter !== undefined && req.result.counter !== null) {
                try {
                    current = BigInt(req.result.counter);
                } catch {
                    current = 1n;
                }
            }
            const next = current + 1n;
            const putReq = store.put({ id: userId, counter: next.toString() });
            putReq.onsuccess = () => resolve(current);
            putReq.onerror = () => reject(putReq.error);
        };
        req.onerror = () => reject(req.error);
        tx.onabort = () => reject(new Error("IndexedDB transaction aborted"));
    });
}

export async function setStoredCounter(userId, counter) {
    const db = await getDB();
    return new Promise((resolve, reject) => {
        const tx = db.transaction(COUNTER_STORE_NAME, "readwrite");
        const store = tx.objectStore(COUNTER_STORE_NAME);
        const req = store.get(userId);

        req.onsuccess = () => {
            let current = 0n;
            if (req.result && req.result.counter !== undefined && req.result.counter !== null) {
                try {
                    current = BigInt(req.result.counter);
                } catch {
                    current = 0n;
                }
            }
            const counterBigInt = BigInt(counter);
            // Strict monotonicity guarantee: never roll back to a lower counter
            if (counterBigInt > current) {
                const putReq = store.put({ id: userId, counter: counterBigInt.toString() });
                putReq.onsuccess = () => resolve();
                putReq.onerror = () => reject(putReq.error);
            } else {
                resolve();
            }
        };
        req.onerror = () => reject(req.error);
        tx.onabort = () => reject(new Error("IndexedDB transaction aborted"));
    });
}

export async function signPayload(userId, payload) {
    const db = await getDB();
    const keyRecord = await new Promise((resolve, reject) => {
        const tx = db.transaction(KEY_STORE_NAME, "readonly");
        const store = tx.objectStore(KEY_STORE_NAME);
        const req = store.get(userId);

        req.onsuccess = () => resolve(req.result);
        req.onerror = () => reject(req.error);
        tx.onabort = () => reject(new Error("IndexedDB transaction aborted"));
    });

    if (!keyRecord) throw new Error(`Private key not found for user: ${userId}`);

    const data = new TextEncoder().encode(payload);
    const signature = await window.crypto.subtle.sign(
        { name: "RSA-PSS", saltLength: 32 },
        keyRecord.privateKey,
        data
    );
    return uint8ArrayToBase64(new Uint8Array(signature));
}