const sodium = require('libsodium-wrappers-sumo');
const crypto = require('crypto');
const bs58 = require('bs58');
const fs = require('fs');


/**
 * Convert Uint8Array to string.
 * @param {Uint8Array} array - The array to convert.
 * @param {string} [encoding='module.exports.defaultEncoding'] - The result encoding.
 * @return {string} - The string.
 */
function toString(array, encoding=module.exports.defaultEncoding) {
    if (encoding === 'base58') {
        return bs58.encode(array);
    } else {
        return Buffer.from(array).toString(encoding);
    }
}


// Keep the original function.
let origin = Buffer.prototype.toString;
/**
 * Convert Buffer to string.
 * Adding the 'base58' encoding.
 * @param {string} encoding - The encoding, it can be 'base58'.
 * @returns {string}
 */
Buffer.prototype.toString = function (encoding='utf8') {
    if (encoding === 'base58') {
        return bs58.encode(this);
    } else {
        return origin.apply(this, arguments);
    }
};


/**
 * Convert Buffer to Uint8Array.
 * @return {Uint8Array}
 */
Buffer.prototype.toUint8Array = function () {
    return this.toString('base64').base64ToUint8Array();
}


/**
 * Convert Uint8Array to String.
 * @param {string} [encoding='module.exports.defaultEncoding'] - The returned string encoding.
 * @return {string}
 */
Uint8Array.prototype.toString = function (encoding=module.exports.defaultEncoding) {
    return Buffer.from(this).toString(encoding);
};


/**
 * Do nothing.
 * @returns {Uint8Array}
 */
Uint8Array.prototype.toUint8Array = () => { return this; }


/**
 * Convert base58 string to Uint8Array.
 * @return {Uint8Array} - The Uint8Array.
 */
String.prototype.base58ToUint8Array = function () {
    return bs58.decode(this.toString());
}


/**
 * Convert base64 string to Uint8Array.
 * @return {Uint8Array} - The Uint8Array.
 */
String.prototype.base64ToUint8Array = function () {
    return sodium.from_base64(this.toString(), sodium.base64_variants.ORIGINAL);
}


/**
 * Convert hexadecimal string to Uint8Array.
 * @return {Uint8Array} - The Uint8Array.
 */
String.prototype.hexToUint8Array = function () {
    return sodium.from_hex(this.toString());
}


/**
 * Convert string to Uint8Array.
 * @param {string} [encoding=module.exports.defaultEncoding] - The string encoding.
 * @return {Uint8Array} - The Uint8Array.
 */
String.prototype.toUint8Array = function (encoding=module.exports.defaultEncoding) {
    if (encoding === 'base58') {
        return this.toString().base58ToUint8Array();
    } else if (encoding === 'base64') {
        return this.toString().base64ToUint8Array();
    } else if (encoding === 'hex') {
        return this.toString().hexToUint8Array();
    } else {
        // TODO : Handle this
    }
}


/**
 * Read private key from file and generate public key.
 *
 * @param {string} file - The file path.
 * @param {boolean} [createIfNotFound=false] - Generate and write key pair if true and file not found, raise an error if false.
 */
async function read(file, createIfNotFound=false) {
    try {
        let privateKey = await fs.promises.readFile(`${file}`);
        return {
            'publicKey': sodium.crypto_sign_ed25519_sk_to_pk(privateKey),
            'privateKey': privateKey.toString('base64').base64ToUint8Array()
        };
    } catch (error) {
        if (createIfNotFound) {
            return generate(file);
        } else {
            throw error;
        }
    }
}


/**
 * Generate an Ed25519 key pair.
 * 32 bytes public key and 64 bytes private key.
 *
 * @param {string} [file=undefined] - An optional path where you want to save the generated key pair.
 * @returns {Promise<{publicKey: Uint8Array, privateKey: Uint8Array}>}
 */
async function generate(file=undefined) {
    let key = sodium.crypto_sign_keypair();
    if (file !== undefined) {
        await fs.promises.writeFile(`${file}`, key.privateKey);
    }
    return {
        publicKey: key.publicKey,
        privateKey: key.privateKey
    }
}


/**
 * Generate an Ed25519 key pair synchronously.
 * 32 bytes public key and 64 bytes private key.
 *
 * @param {string} [file=undefined] - An optional path where you want to save the generated key pair.
 * @returns {{publicKey: Uint8Array, privateKey: Uint8Array}}
 */
function generateSync(file=undefined) {
    let key = sodium.crypto_sign_keypair();
    return {
        publicKey: key.publicKey,
        privateKey: key.privateKey
    }
}


/**
 * Generate an Ed25519 key pair.
 * 32 bytes public key and 64 bytes private key.
 * @param {string} [encoding=module.exports.defaultEncoding] - The string encoding.
 * @return {{publicKey: string, privateKey: string}} - The key pair.
 */
function generateS(encoding=module.exports.defaultEncoding) {
    let key = generate();
    return {
        publicKey: toString(key.publicKey, encoding),
        privateKey: toString(key.privateKey, encoding)
    }
}


/**
 * Generate a shared key from 2 Ed25519 key.
 * This function convert the Ed25519 key in Curve25519 key suitable for DH.
 * WARNING : This conversion is dangerous.
 *
 * @param {Uint8Array|Buffer} publicKey - The remote public key.
 * @param {Uint8Array|Buffer} privateKey - The local private key.
 * @returns {Uint8Array} - The 32 bytes shared key.
 */
function computeSharedKey(publicKey, privateKey) {
    publicKey = sodium.crypto_sign_ed25519_pk_to_curve25519(publicKey);
    privateKey = sodium.crypto_sign_ed25519_sk_to_curve25519(privateKey);
    // WARNING : https://libsodium.gitbook.io/doc/advanced/scalar_multiplication
    // The hash need to contain the 2 public keys. The result of 'crypto_scalarmult' is in a small space.
    return sodium.crypto_generichash(32, sodium.crypto_scalarmult(privateKey, publicKey));
}

/**
 * Compute shared key and call `createStreamCipher`.
 * The header is needed to decipher, you must send it to the remote peer.
 *
 * @param {Uint8Array|Buffer} publicKey - The remote public key.
 * @param {Uint8Array|Buffer} privateKey - The local private key.
 * @returns {state: number, header: Uint8Array} - The state to cipher message and the header to decipher.
 */
function createStreamCipherFromAsymmetricKeys(publicKey, privateKey) {
    return createStreamCipher(
        computeSharedKey(publicKey, privateKey)
    );
}


/**
 * Create XChaCha20 stream cipher.
 *
 * @param {Uint8Array|Buffer} key - The key used to cipher.
 * @returns {state: number, header: Uint8Array} - The state to cipher message and the 24 bytes header to decipher.
 */
function createStreamCipher(key) {
    return sodium.crypto_secretstream_xchacha20poly1305_init_push(key);
}


/**
 * Compute shared key and call `createStreamDecipher`.
 *
 * @param {Uint8Array} header - The 24 bytes header.
 * @param {Uint8Array|Buffer} publicKey - The remote public key.
 * @param {Uint8Array|Buffer} privateKey - The local private key.
 * @returns {number} - The `state` to decipher.
 */
function createStreamDecipherFromAsymmetricKeys(header, publicKey, privateKey) {
    return createStreamDecipher(header,
        computeSharedKey(publicKey, privateKey)
    );
}


/**
 * Create XChaCha20 stream decipher.
 *
 * @param {Uint8Array|string} header - The 24 bytes header.
 * @param {Uint8Array|Buffer} key - The key used to cipher.
 * @returns {number} - The `state` to decipher.
 */
function createStreamDecipher(header, key) {
    header.toUint8Array();
    return sodium.crypto_secretstream_xchacha20poly1305_init_pull(header, key);
}


/**
 * Cipher a message.
 * @param {number} state - The state.
 * @param {string|Buffer} message - The message.
 * @returns {Uint8Array} - The cipher.
 */
function cipher(state, message) {
    return sodium.crypto_secretstream_xchacha20poly1305_push(state, message, null, sodium.crypto_secretstream_xchacha20poly1305_TAG_MESSAGE)
}


/**
 * Decipher a message.
 * @param {number} state - The state.
 * @param {Uint8Array|Buffer} cipher - The cipher.
 * @returns {Uint8Array} - The message.
 */
function decipher(state, cipher)  {
    let result = sodium.crypto_secretstream_xchacha20poly1305_pull(state, cipher);
    if (result === false) {
        throw Error('Decryption failed.');
    } else {
        return result.message;
    }
}


/**
 * Generate the signature of a message.
 * @param {Buffer|string} message - The message to sign.
 * @param {Buffer|Uint8Array} privateKey - The private key.
 * @returns {Uint8Array} - The signature generated.
 */
function sign(message, privateKey) {
    return sodium.crypto_sign_detached(message, privateKey);
}


/**
 * Verify the signature of a message.
 * @param {Buffer|Uint8Array} signature - The signature.
 * @param {Buffer|string} message - The message.
 * @param {Buffer|Uint8Array} publicKey - The public key.
 * @returns {boolean} - True if the signature correspond.
 */
function verify(signature, message, publicKey) {
    return sodium.crypto_sign_verify_detached(signature, message, publicKey);
}


/**
 * Generate a unique random nonce timestamp based.
 * @returns {string}
 */
function generateNonce() {
    return Date.now() + '' + crypto.randomInt(1000, 9999);
}


module.exports = {
    toString,
    read,
    generate,
    generateSync,
    generateS,
    computeSharedKey,
    createStreamCipherFromAsymmetricKeys,
    createStreamCipher,
    createStreamDecipherFromAsymmetricKeys,
    createStreamDecipher,
    cipher,
    decipher,
    sign,
    verify,
    generateNonce,
    Uint8Array,
    String,
    nonceLength: 17,
    publicKeyLength: 32,
    headerLength: 24,
    defaultEncoding: 'base58',
    ready: sodium.ready
};
