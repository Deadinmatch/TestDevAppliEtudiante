var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
/* Source: https://gist.github.com/groundrace/b5141062b47dd96a5c21c93839d4b954 */
/* Available functions:

    # Key/nonce generation:
    generateAssymetricKeysForEncryption(): Promise<CryptoKey[]>
    generateAssymetricKeysForSignature(): Promise<CryptoKey[]>
    generateSymetricKey(): Promise<CryptoKey>
    generateNonce(): string

    # Assymetric key Encryption/Decryption/Signature/Signature verification
    encryptWithPublicKey(pkey: CryptoKey, message: string): Promise<string>
    decryptWithPrivateKey(skey: CryptoKey, message: string): Promise<string>
    signWithPrivateKey(privateKey: CryptoKey, message: string): Promise<string>
    verifySignatureWithPublicKey(publicKey: CryptoKey, messageInClear: string, signedMessage: string): Promise<boolean>

    # Symmetric key Encryption/Decryption
    encryptWithSymmetricKey(key: CryptoKey, message: string): Promise<string[]>
    decryptWithSymmetricKey(key: CryptoKey, message: string, initVector: string): Promise<string>

    # Importing keys from string
    stringToPublicKeyForEncryption(pkeyInBase64: string): Promise<CryptoKey>
    stringToPrivateKeyForEncryption(skeyInBase64: string): Promise<CryptoKey>
    stringToPublicKeyForSignature(pkeyInBase64: string): Promise<CryptoKey>
    stringToPrivateKeyForSignature(skeyInBase64: string): Promise<CryptoKey>
    stringToSymmetricKey(skeyBase64: string): Promise<CryptoKey>

    # Exporting keys to string
    publicKeyToString(key: CryptoKey): Promise<string>
    privateKeyToString(key: CryptoKey): Promise<string>
    symmetricKeyToString(key: CryptoKey): Promise<string>

    # Hashing
    hash(text: string): Promise<string>
*/
// LibCrypto---------------------------------------------------------------------------
/*
Imports the given public key (for encryption) from the import space.
The SubtleCrypto imposes to use the "spki" format for exporting public keys.
*/
function stringToPublicKeyForEncryption(pkeyBase64) {
    return __awaiter(this, void 0, void 0, function* () {
        try {
            const keyArrayBuffer = this.base64StringToArrayBuffer(pkeyBase64);
            const key = yield window.crypto.subtle.importKey("spki", keyArrayBuffer, {
                name: "RSA-OAEP",
                hash: "SHA-256",
            }, true, ["encrypt"]);
            return key;
        }
        catch (e) {
            if (e instanceof DOMException) {
                console.log("String for the public key (for encryption) is ill-formed!");
            }
            else if (e instanceof KeyStringCorrupted) {
                console.log("String for the public key (for encryption) is ill-formed!");
            }
            else {
                console.log(e);
            }
            throw e;
        }
    });
}
/*
Imports the given public key (for signature verification) from the import space.
The SubtleCrypto imposes to use the "spki" format for exporting public keys.
*/
function stringToPublicKeyForSignature(pkeyBase64) {
    return __awaiter(this, void 0, void 0, function* () {
        try {
            const keyArrayBuffer = this.base64StringToArrayBuffer(pkeyBase64);
            const key = yield window.crypto.subtle.importKey("spki", keyArrayBuffer, {
                name: "RSASSA-PKCS1-v1_5",
                hash: "SHA-256",
            }, true, ["verify"]);
            return key;
        }
        catch (e) {
            if (e instanceof DOMException) {
                console.log("String for the public key (for signature verification) is ill-formed!");
            }
            else if (e instanceof KeyStringCorrupted) {
                console.log("String for the public key (for signature verification) is ill-formed!");
            }
            else {
                console.log(e);
            }
            throw e;
        }
    });
}
/*
Imports the given private key (in string) as a valid private key (for decryption)
The SubtleCrypto imposes to use the "pkcs8" ?? format for importing public keys.
*/
function stringToPrivateKeyForEncryption(skeyBase64) {
    return __awaiter(this, void 0, void 0, function* () {
        try {
            const keyArrayBuffer = this.base64StringToArrayBuffer(skeyBase64);
            const key = yield window.crypto.subtle.importKey("pkcs8", keyArrayBuffer, {
                name: "RSA-OAEP",
                hash: "SHA-256",
            }, true, ["decrypt"]);
            return key;
        }
        catch (e) {
            if (e instanceof DOMException) {
                console.log("String for the private key (for decryption) is ill-formed!");
            }
            else if (e instanceof KeyStringCorrupted) {
                console.log("String for the private key (for decryption) is ill-formed!");
            }
            else {
                console.log(e);
            }
            throw e;
        }
    });
}
/*
Imports the given private key (in string) as a valid private key (for signature)
The SubtleCrypto imposes to use the "pkcs8" ?? format for importing public keys.
*/
function stringToPrivateKeyForSignature(skeyBase64) {
    return __awaiter(this, void 0, void 0, function* () {
        try {
            const keyArrayBuffer = this.base64StringToArrayBuffer(skeyBase64);
            const key = yield window.crypto.subtle.importKey("pkcs8", keyArrayBuffer, {
                name: "RSASSA-PKCS1-v1_5",
                hash: "SHA-256",
            }, true, ["sign"]);
            return key;
        }
        catch (e) {
            if (e instanceof DOMException) {
                console.log("String for the private key (for signature) is ill-formed!");
            }
            else if (e instanceof KeyStringCorrupted) {
                console.log("String for the private key (for signature) is ill-formed!");
            }
            else {
                console.log(e);
            }
            throw e;
        }
    });
}
/*
Exports the given public key into a valid string.
The SubtleCrypto imposes to use the "spki" format for exporting public keys.
*/
function publicKeyToString(key) {
    return __awaiter(this, void 0, void 0, function* () {
        const exportedKey = yield window.crypto.subtle.exportKey("spki", key);
        return this.arrayBufferToBase64String(exportedKey);
    });
}
/*
Exports the given public key into a valid string.
The SubtleCrypto imposes to use the "spki" format for exporting public keys.
*/
function privateKeyToString(key) {
    return __awaiter(this, void 0, void 0, function* () {
        const exportedKey = yield window.crypto.subtle.exportKey("pkcs8", key);
        return this.arrayBufferToBase64String(exportedKey);
    });
}
/* Generates a pair of public and private RSA keys for encryption/decryption */
function generateAssymetricKeysForEncryption() {
    return __awaiter(this, void 0, void 0, function* () {
        const keypair = yield window.crypto.subtle.generateKey({
            name: "RSA-OAEP",
            modulusLength: 2048,
            publicExponent: new Uint8Array([1, 0, 1]),
            hash: "SHA-256",
        }, true, ["encrypt", "decrypt"]);
        return [keypair.publicKey, keypair.privateKey];
    });
}
/* Generates a pair of public and private RSA keys for signing/verifying */
function generateAssymetricKeysForSignature() {
    return __awaiter(this, void 0, void 0, function* () {
        const keypair = yield window.crypto.subtle.generateKey({
            name: "RSASSA-PKCS1-v1_5",
            modulusLength: 2048,
            publicExponent: new Uint8Array([1, 0, 1]),
            hash: "SHA-256",
        }, true, ["sign", "verify"]);
        return [keypair.publicKey, keypair.privateKey];
    });
}
/* Generates a random nonce */
function generateNonce() {
    const nonceArray = new Uint32Array(1);
    self.crypto.getRandomValues(nonceArray);
    return nonceArray[0].toString();
}
/* Encrypts a message with a public key */
function encryptWithPublicKey(publicKey, message) {
    return __awaiter(this, void 0, void 0, function* () {
        console.log("Encrypt with " + publicKey + " message= " + message);
        try {
            const messageToArrayBuffer = textToArrayBuffer(message);
            const cypheredMessageAB = yield window.crypto.subtle.encrypt({ name: "RSA-OAEP" }, publicKey, messageToArrayBuffer);
            return this.arrayBufferToBase64String(cypheredMessageAB);
        }
        catch (e) {
            if (e instanceof DOMException) {
                console.log(e);
                console.log("Encryption failed!");
            }
            else if (e instanceof KeyStringCorrupted) {
                console.log("Public key or message to encrypt is ill-formed");
            }
            else {
                console.log(e);
            }
            throw e;
        }
    });
}
/* Sign a message with a private key */
function signWithPrivateKey(privateKey, message) {
    return __awaiter(this, void 0, void 0, function* () {
        console.log("Sign with " + privateKey + " message= " + message);
        try {
            const messageToArrayBuffer = textToArrayBuffer(message);
            const signedMessageAB = yield window.crypto.subtle.sign("RSASSA-PKCS1-v1_5", privateKey, messageToArrayBuffer);
            return this.arrayBufferToBase64String(signedMessageAB);
        }
        catch (e) {
            if (e instanceof DOMException) {
                console.log(e);
                console.log("Signature failed!");
            }
            else if (e instanceof KeyStringCorrupted) {
                console.log("Private key or message to sign is ill-formed");
            }
            else {
                console.log(e);
            }
            throw e;
        }
    });
}
/* Decrypts a message with a private key */
function decryptWithPrivateKey(privateKey, message) {
    return __awaiter(this, void 0, void 0, function* () {
        try {
            const decrytpedMessageAB = yield window.crypto.subtle.decrypt({ name: "RSA-OAEP" }, privateKey, this.base64StringToArrayBuffer(message));
            return this.arrayBufferToText(decrytpedMessageAB);
        }
        catch (e) {
            if (e instanceof DOMException) {
                console.log("Invalid key, message or algorithm for decryption");
            }
            else if (e instanceof KeyStringCorrupted) {
                console.log("Private key or message to decrypt is ill-formed");
            }
            else
                console.log("Decryption failed");
            throw e;
        }
    });
}
/* Verification of a signature on a message with a public key */
function verifySignatureWithPublicKey(publicKey, messageInClear, signedMessage) {
    return __awaiter(this, void 0, void 0, function* () {
        try {
            const signedToArrayBuffer = base64StringToArrayBuffer(signedMessage);
            const messageInClearToArrayBuffer = textToArrayBuffer(messageInClear);
            const verified = yield window.crypto.subtle.verify("RSASSA-PKCS1-v1_5", publicKey, signedToArrayBuffer, messageInClearToArrayBuffer);
            return verified;
        }
        catch (e) {
            if (e instanceof DOMException) {
                console.log("Invalid key, message or algorithm for signature verification");
            }
            else if (e instanceof KeyStringCorrupted) {
                console.log("Public key or signed message to verify is ill-formed");
            }
            else
                console.log("Decryption failed");
            throw e;
        }
    });
}
/* Generates a symmetric AES-GCM key */
function generateSymetricKey() {
    return __awaiter(this, void 0, void 0, function* () {
        const key = yield window.crypto.subtle.generateKey({
            name: "AES-GCM",
            length: 256,
        }, true, ["encrypt", "decrypt"]);
        return key;
    });
}
/* a symmetric AES key into a string */
function symmetricKeyToString(key) {
    return __awaiter(this, void 0, void 0, function* () {
        const exportedKey = yield window.crypto.subtle.exportKey("raw", key);
        return arrayBufferToBase64String(exportedKey);
    });
}
/* Imports the given key (in string) as a valid AES key */
function stringToSymmetricKey(skeyBase64) {
    return __awaiter(this, void 0, void 0, function* () {
        try {
            const keyArrayBuffer = base64StringToArrayBuffer(skeyBase64);
            const key = yield window.crypto.subtle.importKey("raw", keyArrayBuffer, "AES-GCM", true, ["encrypt", "decrypt"]);
            return key;
        }
        catch (e) {
            if (e instanceof DOMException) {
                console.log("String for the symmetric key is ill-formed!");
            }
            else if (e instanceof KeyStringCorrupted) {
                console.log("String for the symmetric key is ill-formed!");
            }
            else {
                console.log(e);
            }
            throw e;
        }
    });
}
// When cyphering a message with a key in AES, we obtain a cyphered message and an "initialisation vector".
// In this implementation, the output is a two elements array t such that t[0] is the cyphered message
// and t[1] is the initialisation vector. To simplify, the initialisation vector is represented by a string.
// The initialisation vectore is used for protecting the encryption, i.e, 2 encryptions of the same message 
// with the same key will never result into the same encrypted message.
// 
// Note that for decyphering, the **same** initialisation vector will be needed.
// This vector can safely be transferred in clear with the encrypted message.
function encryptWithSymmetricKey(key, message) {
    return __awaiter(this, void 0, void 0, function* () {
        console.log("Encrypt with " + key + " message= " + message);
        try {
            const messageToArrayBuffer = textToArrayBuffer(message);
            const iv = window.crypto.getRandomValues(new Uint8Array(12));
            const ivText = arrayBufferToBase64String(iv);
            const cypheredMessageAB = yield window.crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, messageToArrayBuffer);
            return [arrayBufferToBase64String(cypheredMessageAB), ivText];
        }
        catch (e) {
            if (e instanceof DOMException) {
                console.log(e);
                console.log("Encryption failed!");
            }
            else if (e instanceof KeyStringCorrupted) {
                console.log("Symmetric key or message to encrypt is ill-formed");
            }
            else {
                console.log(e);
            }
            throw e;
        }
    });
}
// For decyphering, we need the key, the cyphered message and the initialization vector. See above the 
// comments for the encryptWithSymmetricKey function
function decryptWithSymmetricKey(key, message, initVector) {
    return __awaiter(this, void 0, void 0, function* () {
        const decodedInitVector = base64StringToArrayBuffer(initVector);
        try {
            const decrytpedMessageAB = yield window.crypto.subtle.decrypt({ name: "AES-GCM", iv: decodedInitVector }, key, base64StringToArrayBuffer(message));
            return this.arrayBufferToText(decrytpedMessageAB);
        }
        catch (e) {
            if (e instanceof DOMException) {
                console.log("Invalid key, message or algorithm for decryption");
            }
            else if (e instanceof KeyStringCorrupted) {
                console.log("Symmetric key or message to decrypt is ill-formed");
            }
            else
                console.log("Decryption failed");
            throw e;
        }
    });
}
// SHA-256 Hash from a text
function hash(text) {
    return __awaiter(this, void 0, void 0, function* () {
        const text2arrayBuf = textToArrayBuffer(text);
        const hashedArray = yield window.crypto.subtle.digest("SHA-256", text2arrayBuf);
        return arrayBufferToBase64String(hashedArray);
    });
}
class KeyStringCorrupted extends Error {
}
// ArrayBuffer to a Base64 string
function arrayBufferToBase64String(arrayBuffer) {
    var byteArray = new Uint8Array(arrayBuffer);
    var byteString = '';
    for (var i = 0; i < byteArray.byteLength; i++) {
        byteString += String.fromCharCode(byteArray[i]);
    }
    return btoa(byteString);
}
// Base64 string to an arrayBuffer
function base64StringToArrayBuffer(b64str) {
    try {
        var byteStr = atob(b64str);
        var bytes = new Uint8Array(byteStr.length);
        for (var i = 0; i < byteStr.length; i++) {
            bytes[i] = byteStr.charCodeAt(i);
        }
        return bytes.buffer;
    }
    catch (e) {
        console.log(`String starting by '${b64str.substring(0, 10)}' cannot be converted to a valid key or message`);
        throw new KeyStringCorrupted;
    }
}
// String to array buffer
function textToArrayBuffer(str) {
    var buf = encodeURIComponent(str); // 2 bytes for each char
    var bufView = new Uint8Array(buf.length);
    for (var i = 0; i < buf.length; i++) {
        bufView[i] = buf.charCodeAt(i);
    }
    return bufView;
}
// Array buffers to string
function arrayBufferToText(arrayBuffer) {
    var byteArray = new Uint8Array(arrayBuffer);
    var str = '';
    for (var i = 0; i < byteArray.byteLength; i++) {
        str += String.fromCharCode(byteArray[i]);
    }
    return decodeURIComponent(str);
}
/* Source: https://gist.github.com/groundrace/b5141062b47dd96a5c21c93839d4b954 */
/* tsc --inlineSourceMap true -outFile JS/calculette.js src/libCrypto.ts src/calculette.ts --target es2015  */
// import {
//     stringToPublicKey, stringToPrivateKey, encryptWithPublicKey, decryptWithPrivateKey,
//     generateAssymetricKeys, generateSymetricKey, generateNonce, encryptWithSymmetricKey, decryptWithSymmetricKey,
//     stringToSymmetricKey, publicKeyToString, privateKeyToString, symmetricKeyToString
// } from './libCrypto'
/* Application --------------------------------------------------------- */
/* getting the main objects from the dom */
/* Buttons */
const rsaEncryptButton = document.getElementById("rsa-encrypt-button");
const rsaDecryptButton = document.getElementById("rsa-decrypt-button");
const rsaSignButton = document.getElementById("rsa-sign-button");
const rsaVerifyButton = document.getElementById("rsa-verify-button");
const generateAsymEncKeysButton = document.getElementById("generate-asym-enc-keys-button");
//const generateAsymSignKeysButton = document.getElementById("generate-asym-sign-keys-button") as HTMLButtonElement
const generateNonceButton = document.getElementById("generate-nonce-button");
const hashButton = document.getElementById("hash-button");
const generateSymKeyButton = document.getElementById("generate-symkey-button");
const aesEncryptButton = document.getElementById("aes-encrypt-button");
const aesDecryptButton = document.getElementById("aes-decrypt-button");
/* labels and input fields */
const publicKeyEncElement = document.getElementById("gen-public-key-enc");
const privateKeyEncElement = document.getElementById("gen-private-key-enc");
const publicKeySignElement = document.getElementById("gen-public-key-sign");
const privateKeySignElement = document.getElementById("gen-private-key-sign");
const symmetricKeyElement = document.getElementById("gen-symmetric-key");
const aesKeyEncrypt = document.getElementById("aes-encrypt-key");
const aesKeyDecrypt = document.getElementById("aes-decrypt-key");
const rsaMessageBox = document.getElementById("rsa-oaep-message");
const aesEncryptMessageBox = document.getElementById("aes-encrypt-message");
const aesDecryptMessageBox = document.getElementById("aes-decrypt-message");
const publicKeyEncBox = document.getElementById("rsa-pubkey-enc");
const privateKeyEncBox = document.getElementById("rsa-privkey-enc");
const publicKeySignBox = document.getElementById("rsa-pubkey-sign");
const privateKeySignBox = document.getElementById("rsa-privkey-sign");
const aesEncryptKey = document.getElementById("aes-encrypt-key");
const aesDecryptKey = document.getElementById("aes-decrypt-key");
const cypherTextElement = document.getElementById("cyphertext-value");
const messageToDecryptBox = document.getElementById("message-to-decrypt");
const decypheredTextElement = document.getElementById("decyphertext-value");
const messageToSign = document.getElementById("message-to-sign");
const signedMessage = document.getElementById("signed-value");
const signedMessageToCheck = document.getElementById("signed-message-to-check");
const signedMessageInClear = document.getElementById("signed-message-in-clear");
const rsaPublicKeyForVerification = document.getElementById("rsa-public-sign");
const verificationValue = document.getElementById("verification-value");
const messageToHash = document.getElementById("message-to-hash");
const hashedMessage = document.getElementById("hashed-message");
const aesCypherTextElement = document.getElementById("aes-cyphertext-value");
const aesCypherIV = document.getElementById("aes-cyphertext-IV");
const aesMessageToDecryptBox = document.getElementById("aes-message-to-decrypt");
const aesIVToDecryptBox = document.getElementById("aes-decrypt-IV");
const aesDecypheredTextElement = document.getElementById("aes-decyphertext-value");
const nonceTextElement = document.getElementById("nonce");
generateAsymEncKeysButton.onclick = function () {
    return __awaiter(this, void 0, void 0, function* () {
        try {
            const keypair = yield generateAssymetricKeysForEncryption();
            const publicKeyText = yield publicKeyToString(keypair[0]);
            const privateKeyText = yield privateKeyToString(keypair[1]);
            publicKeyEncElement.value = publicKeyText;
            privateKeyEncElement.value = privateKeyText;
        }
        catch (e) {
            if (e instanceof DOMException) {
                alert("Generation failed!");
            }
            else {
                alert(e);
            }
        }
    });
};
// generateAsymSignKeysButton.onclick = async function () {
//     try {
//         const keypair: CryptoKey[] = await generateAssymetricKeysForSignature()
//         const publicKeyText = await publicKeyToString(keypair[0])
//         const privateKeyText = await privateKeyToString(keypair[1])
//         publicKeySignElement.value = publicKeyText
//         privateKeySignElement.value = privateKeyText
//     } catch (e) {
//         if (e instanceof DOMException) { alert("Generation failed!") }
//         else { alert(e) }
//     }
// }
generateSymKeyButton.onclick = function () {
    return __awaiter(this, void 0, void 0, function* () {
        try {
            const key = yield generateSymetricKey();
            const keyText = yield symmetricKeyToString(key);
            symmetricKeyElement.value = keyText;
        }
        catch (e) {
            if (e instanceof DOMException) {
                alert("Generation failed!");
            }
            else {
                alert(e);
            }
        }
    });
};
generateNonceButton.onclick = function () {
    const nonce = generateNonce();
    nonceTextElement.textContent = nonce;
};
hashButton.onclick = function () {
    return __awaiter(this, void 0, void 0, function* () {
        const textToHash = messageToHash.value;
        hashedMessage.value = yield hash(textToHash);
    });
};
rsaEncryptButton.onclick = function () {
    return __awaiter(this, void 0, void 0, function* () {
        try {
            const message = rsaMessageBox.value;
            const publicKeyTextBase64 = publicKeyEncBox.value;
            const publicKey = yield stringToPublicKeyForEncryption(publicKeyTextBase64);
            const encryptedMessage = yield encryptWithPublicKey(publicKey, message);
            cypherTextElement.value = encryptedMessage;
        }
        catch (e) {
            alert("Encryption failed!");
        }
    });
};
rsaSignButton.onclick = function () {
    return __awaiter(this, void 0, void 0, function* () {
        try {
            const message = messageToSign.value;
            const privateKeyTextBase64 = privateKeySignBox.value;
            const privateKey = yield stringToPrivateKeyForSignature(privateKeyTextBase64);
            const resultingSignedMessage = yield signWithPrivateKey(privateKey, message);
            signedMessage.value = resultingSignedMessage;
        }
        catch (e) {
            alert("Signature failed!");
        }
    });
};
rsaVerifyButton.onclick = function () {
    return __awaiter(this, void 0, void 0, function* () {
        try {
            const signedMessage = signedMessageToCheck.value;
            const messageInClear = signedMessageInClear.value;
            const publicKeyTextBase64 = publicKeySignBox.value;
            const publicKey = yield stringToPublicKeyForSignature(publicKeyTextBase64);
            const verification = yield verifySignatureWithPublicKey(publicKey, messageInClear, signedMessage);
            verificationValue.value = "" + verification;
        }
        catch (e) {
            alert("Signature failed!");
        }
    });
};
aesEncryptButton.onclick = function () {
    return __awaiter(this, void 0, void 0, function* () {
        try {
            const message = aesEncryptMessageBox.value;
            const keyTextBase64 = aesEncryptKey.value;
            const key = yield stringToSymmetricKey(keyTextBase64);
            const result = yield encryptWithSymmetricKey(key, message);
            aesCypherTextElement.value = result[0];
            aesCypherIV.value = result[1];
        }
        catch (e) {
            alert("Encryption failed!");
        }
    });
};
rsaDecryptButton.onclick = function () {
    return __awaiter(this, void 0, void 0, function* () {
        try {
            const message = messageToDecryptBox.value;
            const privateKeyTextBase64 = privateKeyEncBox.value;
            const privateKey = yield stringToPrivateKeyForEncryption(privateKeyTextBase64);
            const decryptedMessage = yield decryptWithPrivateKey(privateKey, message);
            decypheredTextElement.value = decryptedMessage;
        }
        catch (e) {
            alert("Decryption failed");
        }
    });
};
aesDecryptButton.onclick = function () {
    return __awaiter(this, void 0, void 0, function* () {
        try {
            const message = aesDecryptMessageBox.value;
            const keyTextBase64 = aesDecryptKey.value;
            const key = yield stringToSymmetricKey(keyTextBase64);
            const initVector = aesIVToDecryptBox.value;
            const result = yield decryptWithSymmetricKey(key, message, initVector);
            aesDecypheredTextElement.value = result;
        }
        catch (e) {
            alert("Decryption failed!");
        }
    });
};
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiY2FsY3VsZXR0ZS5qcyIsInNvdXJjZVJvb3QiOiIiLCJzb3VyY2VzIjpbIi4uL3NyYy9saWJDcnlwdG8udHMiLCIuLi9zcmMvY2FsY3VsZXR0ZS50cyJdLCJuYW1lcyI6W10sIm1hcHBpbmdzIjoiOzs7Ozs7Ozs7QUFBQSxpRkFBaUY7QUFFakY7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7O0VBZ0NFO0FBRUYsdUZBQXVGO0FBRXZGOzs7RUFHRTtBQUNGLFNBQWUsOEJBQThCLENBQUMsVUFBa0I7O1FBQzVELElBQUk7WUFDQSxNQUFNLGNBQWMsR0FBZ0IsSUFBSSxDQUFDLHlCQUF5QixDQUFDLFVBQVUsQ0FBQyxDQUFBO1lBQzlFLE1BQU0sR0FBRyxHQUFjLE1BQU0sTUFBTSxDQUFDLE1BQU0sQ0FBQyxNQUFNLENBQUMsU0FBUyxDQUN2RCxNQUFNLEVBQ04sY0FBYyxFQUNkO2dCQUNJLElBQUksRUFBRSxVQUFVO2dCQUNoQixJQUFJLEVBQUUsU0FBUzthQUNsQixFQUNELElBQUksRUFDSixDQUFDLFNBQVMsQ0FBQyxDQUNkLENBQUE7WUFDRCxPQUFPLEdBQUcsQ0FBQTtTQUNiO1FBQUMsT0FBTyxDQUFDLEVBQUU7WUFDUixJQUFJLENBQUMsWUFBWSxZQUFZLEVBQUU7Z0JBQUUsT0FBTyxDQUFDLEdBQUcsQ0FBQywyREFBMkQsQ0FBQyxDQUFBO2FBQUU7aUJBQ3RHLElBQUksQ0FBQyxZQUFZLGtCQUFrQixFQUFFO2dCQUFFLE9BQU8sQ0FBQyxHQUFHLENBQUMsMkRBQTJELENBQUMsQ0FBQTthQUFFO2lCQUNqSDtnQkFBRSxPQUFPLENBQUMsR0FBRyxDQUFDLENBQUMsQ0FBQyxDQUFBO2FBQUU7WUFDdkIsTUFBTSxDQUFDLENBQUE7U0FDVjtJQUNMLENBQUM7Q0FBQTtBQUVEOzs7RUFHRTtBQUNGLFNBQWUsNkJBQTZCLENBQUMsVUFBa0I7O1FBQzNELElBQUk7WUFDQSxNQUFNLGNBQWMsR0FBZ0IsSUFBSSxDQUFDLHlCQUF5QixDQUFDLFVBQVUsQ0FBQyxD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