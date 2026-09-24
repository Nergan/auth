const DB_NAME = "AuthDB";
const KEY_STORE_NAME = "Keys";
const COUNTER_STORE_NAME = "Counters";

let dbInstancePromise = null;

export async function getDB() {
    if (dbInstancePromise) {
        return dbInstancePromise;
    }
    dbInstancePromise = new Promise((resolve, reject) => {
        const request = indexedDB.open(DB_NAME, 5);
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

export function generateRandomNonce(byteLength = 16) {
    const clampedBytes = Math.max(8, Math.min(32, byteLength));
    const bytes = new Uint8Array(clampedBytes);
    window.crypto.getRandomValues(bytes);
    return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

export async function generateEd25519Key() {
    const algorithm = "Ed25519";
    const keyPair = await window.crypto.subtle.generateKey(
        { name: "Ed25519" },
        false, // Private key remains non-extractable via Web Crypto API
        ["sign", "verify"]
    );

    let rawKeyBytes;
    try {
        const rawBuffer = await window.crypto.subtle.exportKey("raw", keyPair.publicKey);
        rawKeyBytes = new Uint8Array(rawBuffer);
    } catch {
        const spkiBuffer = await window.crypto.subtle.exportKey("spki", keyPair.publicKey);
        const spkiBytes = new Uint8Array(spkiBuffer);
        rawKeyBytes = spkiBytes.length === 44 ? spkiBytes.slice(12) : spkiBytes;
    }

    const spkiBuffer = await window.crypto.subtle.exportKey("spki", keyPair.publicKey);
    const b64 = uint8ArrayToBase64(new Uint8Array(spkiBuffer));
    const exportedPubKey = `-----BEGIN PUBLIC KEY-----\n${b64.match(/.{1,64}/g).join('\n')}\n-----END PUBLIC KEY-----`;

    return { keyPair, exportedPubKey, rawKeyBytes, algorithm };
}

export async function signRegistrationProof(privateKey, algorithm, canonicalKeyBytes, timestamp, clientNonce) {
    const keyHex = Array.from(canonicalKeyBytes).map(b => b.toString(16).padStart(2, '0')).join('');
    const components = ["register_pop", algorithm, keyHex, timestamp.toString(), clientNonce];
    const challenge = components.map(c => `${new TextEncoder().encode(c).length}:${c}\n`).join('');

    const data = new TextEncoder().encode(challenge);
    const signature = await window.crypto.subtle.sign(
        { name: "Ed25519" },
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

        const privateKey = (keyPair && keyPair.privateKey) ? keyPair.privateKey : keyPair;
        store.put({
            id: userId,
            privateKey,
            algorithm
        });
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
        { name: "Ed25519" },
        keyRecord.privateKey,
        data
    );
    return uint8ArrayToBase64(new Uint8Array(signature));
}