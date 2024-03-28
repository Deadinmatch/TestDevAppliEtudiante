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
/* tsc --inlineSourceMap true -outFile JS/intruder.js src/libCrypto.ts src/intruder.ts --target es2015 */
// Message for user name
class CasUserName {
    constructor(username) {
        this.username = username;
    }
}
// Filtering of messages
class FilterRequest {
    constructor(from, to, indexmin) {
        this.from = from;
        this.to = to;
        this.indexmin = indexmin;
    }
}
class FilteredMessage {
    constructor(message, index, deleted, deleter) {
        this.message = message;
        this.index = index;
        this.deleted = deleted;
        this.deleter = deleter;
    }
}
// Result of filtering request
class FilteringAnswer {
    constructor(success, failureMessage, allMessages) {
        this.success = success;
        this.failureMessage = failureMessage;
        this.allMessages = allMessages;
    }
}
// Sending a message Result format
class SendResult {
    constructor(success, errorMessage) {
        this.success = success;
        this.errorMessage = errorMessage;
    }
}
// Sending messages
// The message format
class ExtMessage {
    constructor(sender, receiver, content) {
        this.sender = sender;
        this.receiver = receiver;
        this.content = content;
    }
}
class DeletingRequest {
    constructor(indexToDelete) {
        this.indexToDelete = indexToDelete;
    }
}
class DeletingAnswer {
    constructor(success, message) {
        this.success = success;
    }
}
// Requesting keys
class KeyRequest {
    constructor(ownerOfTheKey, publicKey, encryption) {
        this.ownerOfTheKey = ownerOfTheKey;
        this.publicKey = publicKey;
        this.encryption = encryption;
    }
}
class KeyResult {
    constructor(success, key, errorMessage) {
        this.success = success;
        this.key = key;
        this.errorMessage = errorMessage;
    }
}
const filterButton = document.getElementById("filter-button");
const sendButton = document.getElementById("send-button");
const deleteButton = document.getElementById("delete-button");
const getPublicKeyButton = document.getElementById("get-public-key-button");
const getPrivateKeyButton = document.getElementById("get-private-key-button");
const generateNonceButton = document.getElementById("generate-nonce-button");
const public_key_owner = document.getElementById("public-key-owner");
const private_key_owner = document.getElementById("private-key-owner");
const publicKeyElementEnc = document.getElementById("public-key-enc");
const privateKeyElementEnc = document.getElementById("private-key-enc");
const publicKeyElementSign = document.getElementById("public-key-sign");
const privateKeyElementSign = document.getElementById("private-key-sign");
const nonceTextElement = document.getElementById("nonce");
const from = document.getElementById("from");
const to = document.getElementById("to");
const indexminElt = document.getElementById("indexmin");
const filtered_messages = document.getElementById("filtered-messages");
const sendfrom = document.getElementById("sendfrom");
const sendto = document.getElementById("sendto");
const sendcontent = document.getElementById("sendcontent");
const deleteIndex = document.getElementById("deleteindex");
function fetchCasName() {
    return __awaiter(this, void 0, void 0, function* () {
        const urlParams = new URLSearchParams(window.location.search);
        const namerequest = yield fetch("/getuser?" + urlParams, {
            method: "GET",
            headers: {
                "Content-type": "application/json; charset=UTF-8"
            }
        });
        if (!namerequest.ok) {
            throw new Error(`Error! status: ${namerequest.status}`);
        }
        const nameResult = (yield namerequest.json());
        return nameResult.username;
    });
}
// We set the default CAS name for the public key fields
function setCasName() {
    return __awaiter(this, void 0, void 0, function* () {
        public_key_owner.value = yield fetchCasName();
        private_key_owner.value = yield fetchCasName();
    });
}
setCasName();
/* Name of the owner/developper of the application, i.e, the name of the folder
   where the web page of the application is stored. E.g, for teachers' application
   this name is "ens" */
function getOwnerName() {
    const path = window.location.pathname;
    const name = path.split("/", 2)[1];
    return name;
}
let ownerName = getOwnerName();
function clearingMessages() {
    filtered_messages.textContent = "";
}
function stringToHTML(str) {
    var div_elt = document.createElement('div');
    div_elt.innerHTML = str;
    return div_elt;
}
function addingFilteredMessage(message) {
    filtered_messages.append(stringToHTML('<p></p><p></p>' + message));
}
generateNonceButton.onclick = function () {
    const nonce = generateNonce();
    nonceTextElement.textContent = nonce;
};
function fetchKey(user, publicKey, encryption) {
    return __awaiter(this, void 0, void 0, function* () {
        // Getting the public/private key of user. 
        // For public key the boolean 'publicKey' is true.
        // For private key the boolean 'publicKey' is false.
        // If the key is used for encryption/decryption then the boolean 'encryption' is true.
        // If the key is used for signature/signature verification then the boolean is false.
        const keyRequestMessage = new KeyRequest(user, publicKey, encryption);
        // For CAS authentication we need to add the authentication ticket
        // It is contained in urlParams
        const urlParams = new URLSearchParams(window.location.search);
        // For getting a key we do not need the ownerName param
        // Because keys are independant of the applications
        const keyrequest = yield fetch("/getKey?" + urlParams, {
            method: "POST",
            body: JSON.stringify(keyRequestMessage),
            headers: {
                "Content-type": "application/json; charset=UTF-8"
            }
        });
        if (!keyrequest.ok) {
            throw new Error(`Error! status: ${keyrequest.status}`);
        }
        const keyResult = (yield keyrequest.json());
        if (!keyResult.success)
            alert(keyResult.errorMessage);
        else {
            if (publicKey)
                return yield stringToPublicKeyForEncryption(keyResult.key);
            else
                return yield stringToPrivateKeyForEncryption(keyResult.key);
        }
    });
}
getPublicKeyButton.onclick = function () {
    return __awaiter(this, void 0, void 0, function* () {
        const public_key_owner_name = public_key_owner.value;
        const publicKeyEnc = yield fetchKey(public_key_owner_name, true, true);
        const publicKeySign = yield fetchKey(public_key_owner_name, true, false);
        publicKeyElementEnc.textContent = yield publicKeyToString(publicKeyEnc);
        publicKeyElementSign.textContent = yield publicKeyToString(publicKeySign);
    });
};
getPrivateKeyButton.onclick = function () {
    return __awaiter(this, void 0, void 0, function* () {
        const private_key_owner_name = private_key_owner.value;
        const privateKeyEnc = yield fetchKey(private_key_owner_name, false, true);
        const privateKeySign = yield fetchKey(private_key_owner_name, false, false);
        privateKeyElementEnc.textContent = yield privateKeyToString(privateKeyEnc);
        privateKeyElementSign.textContent = yield privateKeyToString(privateKeySign);
    });
};
deleteButton.onclick = function () {
    return __awaiter(this, void 0, void 0, function* () {
        let indexToDelete = deleteIndex.value;
        const urlParams = new URLSearchParams(window.location.search);
        try {
            let deleteRequest = new DeletingRequest(indexToDelete);
            const request = yield fetch("/deleting/" + ownerName + "?" + urlParams, {
                method: "POST",
                body: JSON.stringify(deleteRequest),
                headers: {
                    "Content-type": "application/json; charset=UTF-8"
                }
            });
            if (!request.ok) {
                throw new Error(`Error! status: ${request.status}`);
            }
            // Dealing with the answer of the message server
            return (yield request.json());
        }
        catch (error) {
            if (error instanceof Error) {
                alert(error.message);
                //console.log('error message: ', error.message);
                return new DeletingAnswer(false, error.message);
            }
            else {
                console.log('unexpected error: ', error);
                return new DeletingAnswer(false, 'An unexpected error occurred');
            }
        }
    });
};
function sendMessage(agentName, receiverName, messageContent) {
    return __awaiter(this, void 0, void 0, function* () {
        try {
            let messageToSend = new ExtMessage(agentName, receiverName, messageContent);
            const urlParams = new URLSearchParams(window.location.search);
            const request = yield fetch("/intruderSendingMessage/" + ownerName + "?" + urlParams, {
                method: "POST",
                body: JSON.stringify(messageToSend),
                headers: {
                    "Content-type": "application/json; charset=UTF-8"
                }
            });
            if (!request.ok) {
                throw new Error(`Error! status: ${request.status}`);
            }
            // Dealing with the answer of the message server
            return (yield request.json());
        }
        catch (error) {
            if (error instanceof Error) {
                console.log(error.message);
                return new SendResult(false, error.message);
            }
            else {
                console.log(error);
                return new SendResult(false, 'An unexpected error occurred');
            }
        }
    });
}
// the intruder sends a message in place of any user
sendButton.onclick = function () {
    return __awaiter(this, void 0, void 0, function* () {
        let agentName = sendfrom.value;
        let receiverName = sendto.value;
        let content = sendcontent.value;
        try {
            const sendResult = yield sendMessage(agentName, receiverName, content);
            if (!sendResult.success)
                alert(sendResult.errorMessage);
            else {
                console.log("Successfully sent the message!");
            }
        }
        catch (e) {
            if (e instanceof Error) {
                console.log(e.message);
            }
            else {
                console.log(e);
            }
        }
    });
};
filterButton.onclick = function () {
    return __awaiter(this, void 0, void 0, function* () {
        try {
            const fromText = from.value;
            const toText = to.value;
            const indexmin = indexminElt.value;
            const filterRequest = new FilterRequest(fromText, toText, indexmin);
            // For CAS authentication we need to add the authentication ticket
            // It is contained in urlParams
            const urlParams = new URLSearchParams(window.location.search);
            const request = yield fetch("/filtering/" + ownerName + "?" + urlParams, {
                method: "POST",
                body: JSON.stringify(filterRequest),
                headers: {
                    "Content-type": "application/json; charset=UTF-8"
                }
            });
            if (!request.ok) {
                throw new Error(`Error! status: ${request.status}`);
            }
            const result = (yield request.json());
            if (!result.success) {
                alert(result.failureMessage);
            }
            else {
                clearingMessages();
                for (var filt_message of result.allMessages) {
                    if (filt_message.deleted) {
                        addingFilteredMessage(`Index: ${filt_message.index} Deleted by: ${filt_message.deleter} <strike> From: ${filt_message.message.sender} To: ${filt_message.message.receiver} Content: ${filt_message.message.content} </strike>`);
                    }
                    else {
                        addingFilteredMessage(`Index: ${filt_message.index} From: ${filt_message.message.sender} To: ${filt_message.message.receiver} Content: ${filt_message.message.content}`);
                    }
                }
            }
        }
        catch (error) {
            if (error instanceof Error) {
                console.log('error message: ', error.message);
                return error.message;
            }
            else {
                console.log('unexpected error: ', error);
                return 'An unexpected error occurred';
            }
        }
    });
};
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiaW50cnVkZXIuanMiLCJzb3VyY2VSb290IjoiIiwic291cmNlcyI6WyIuLi9zcmMvbGliQ3J5cHRvLnRzIiwiLi4vc3JjL2ludHJ1ZGVyLnRzIl0sIm5hbWVzIjpbXSwibWFwcGluZ3MiOiI7Ozs7Ozs7OztBQUFBLGlGQUFpRjtBQUVqRjs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7RUFnQ0U7QUFFRix1RkFBdUY7QUFFdkY7OztFQUdFO0FBQ0YsU0FBZSw4QkFBOEIsQ0FBQyxVQUFrQjs7UUFDNUQsSUFBSTtZQUNBLE1BQU0sY0FBYyxHQUFnQixJQUFJLENBQUMseUJBQXlCLENBQUMsVUFBVSxDQUFDLENBQUE7WUFDOUUsTUFBTSxHQUFHLEdBQWMsTUFBTSxNQUFNLENBQUMsTUFBTSxDQUFDLE1BQU0sQ0FBQyxTQUFTLENBQ3ZELE1BQU0sRUFDTixjQUFjLEVBQ2Q7Z0JBQ0ksSUFBSSxFQUFFLFVBQVU7Z0JBQ2hCLElBQUksRUFBRSxTQUFTO2FBQ2xCLEVBQ0QsSUFBSSxFQUNKLENBQUMsU0FBUyxDQUFDLENBQ2QsQ0FBQTtZQUNELE9BQU8sR0FBRyxDQUFBO1NBQ2I7UUFBQyxPQUFPLENBQUMsRUFBRTtZQUNSLElBQUksQ0FBQyxZQUFZLFlBQVksRUFBRTtnQkFBRSxPQUFPLENBQUMsR0FBRyxDQUFDLDJEQUEyRCxDQUFDLENBQUE7YUFBRTtpQkFDdEcsSUFBSSxDQUFDLFlBQVksa0JBQWtCLEVBQUU7Z0JBQUUsT0FBTyxDQUFDLEdBQUcsQ0FBQywyREFBMkQsQ0FBQyxDQUFBO2FBQUU7aUJBQ2pIO2dCQUFFLE9BQU8sQ0FBQyxHQUFHLENBQUMsQ0FBQyxDQUFDLENBQUE7YUFBRTtZQUN2QixNQUFNLENBQUMsQ0FBQTtTQUNWO0lBQ0wsQ0FBQztDQUFBO0FBRUQ7OztFQUdFO0FBQ0YsU0FBZSw2QkFBNkIsQ0FBQyxVQUFrQjs7UUFDM0QsSUFBSTtZQUNBLE1BQU0sY0FBYyxHQUFnQixJQUFJLENBQUMseUJBQXlCLENBQUMsVUFBVSxDQUFDLENBQUE7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