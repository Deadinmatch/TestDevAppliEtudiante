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
/* tsc --inlineSourceMap  true -outFile JS/messenger.js src/libCrypto.ts src/messenger.ts --target es2015 */
// To detect if we can use window.crypto.subtle
if (!window.isSecureContext)
    alert("Not secure context!");
// Message for user name
class CasUserName {
    constructor(username) {
        this.username = username;
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
// The message format
class ExtMessage {
    constructor(sender, receiver, content) {
        this.sender = sender;
        this.receiver = receiver;
        this.content = content;
    }
}
// Sending a message Result format
class SendResult {
    constructor(success, errorMessage) {
        this.success = success;
        this.errorMessage = errorMessage;
    }
}
// Message for requiring history
class HistoryRequest {
    constructor(agentName, index) {
        this.agentName = agentName;
        this.index = index;
    }
}
// Result of history request
class HistoryAnswer {
    constructor(success, failureMessage, index, allMessages) {
        this.success = success;
        this.failureMessage = failureMessage;
        this.index = index;
        this.allMessages = allMessages;
    }
}
const userButtonLabel = document.getElementById("user-name");
const sendButton = document.getElementById("send-button");
const receiver = document.getElementById("receiver");
const message = document.getElementById("message");
const received_messages = document.getElementById("exchanged-messages");
let globalUserName = "";
// Basic utilities for adding/clearing received messages in the page
function clearingMessages() {
    received_messages.textContent = "";
}
function stringToHTML(str) {
    var div_elt = document.createElement('div');
    div_elt.innerHTML = str;
    return div_elt;
}
function addingReceivedMessage(message) {
    received_messages.append(stringToHTML('<p></p><p></p>' + message));
}
// WARNING!
// It is necessary to pass the URL parameters, called `urlParams` below, to 
// every GET/POST query you send to the server. This is mandatory to have the possibility 
// to use alternative identities like alice@univ-rennes.fr, bob@univ-rennes.fr, etc. 
// for debugging purposes.
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
        console.log("Fetched CAS name= " + nameResult.username);
        return nameResult.username;
    });
}
function setCasName() {
    return __awaiter(this, void 0, void 0, function* () {
        globalUserName = yield fetchCasName();
        // We replace the name of the user of the application as the default name
        // In the window
        userButtonLabel.textContent = globalUserName;
    });
}
setCasName();
// WARNING!
// It is necessary to provide the name of the owner of the application. Each pair of student are
// the owner of their application. Other students may use it but they are only users and not owners.
// Messages sent to the server are separated w.r.t. the name of the application (i.e. the name of their owners).
// The name of the owners is the name of the folder of the application where the web pages of the application are stored. 
// E.g, for teachers' application this name is "ens"
function getOwnerName() {
    const path = window.location.pathname;
    const name = path.split("/", 2)[1];
    return name;
}
let ownerName = getOwnerName();
// WARNING!
// It is necessary to pass the URL parameters, called `urlParams` below, to 
// every GET/POST query you send to the server. This is mandatory to have the possibility 
// to use alternative identities like alice@univ-rennes.fr, bob@univ-rennes.fr, etc. 
// for debugging purposes.
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
            if (publicKey && encryption)
                return yield stringToPublicKeyForEncryption(keyResult.key);
            else if (!publicKey && encryption)
                return yield stringToPrivateKeyForEncryption(keyResult.key);
            else if (publicKey && !encryption)
                return yield stringToPublicKeyForSignature(keyResult.key);
            else if (!publicKey && !encryption)
                return yield stringToPrivateKeyForSignature(keyResult.key);
        }
    });
}
// WARNING!
// It is necessary to pass the URL parameters, called `urlParams` below, to 
// every GET/POST query you send to the server. This is mandatory to have the possibility 
// to use alternative identities like alice@univ-rennes.fr, bob@univ-rennes.fr, etc. 
// for debugging purposes.
// 
// We also need to provide the ownerName
function sendMessage(agentName, receiverName, messageContent) {
    return __awaiter(this, void 0, void 0, function* () {
        try {
            let messageToSend = new ExtMessage(agentName, receiverName, messageContent);
            const urlParams = new URLSearchParams(window.location.search);
            const request = yield fetch("/sendingMessage/" + ownerName + "?" + urlParams, {
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
            console.log(`Sent message from ${agentName} to ${receiverName}: ${messageContent}`);
            return (yield request.json());
        }
        catch (error) {
            if (error instanceof Error) {
                console.log('error message: ', error.message);
                return new SendResult(false, error.message);
            }
            else {
                console.log('unexpected error: ', error);
                return new SendResult(false, 'An unexpected error occurred');
            }
        }
    });
}
sendButton.onclick = function () {
    return __awaiter(this, void 0, void 0, function* () {
        let agentName = globalUserName;
        let receiverName = receiver.value;
        try {
            // And send
            const sendResult = yield sendMessage(agentName, receiverName, message.value);
            if (!sendResult.success)
                console.log(sendResult.errorMessage);
            else {
                console.log("Successfully sent the message!");
                // We add the message to the list of sent messages
                const textToAdd = `<font color="blue"> ${agentName} -> ${receiverName} : ${message.value} </font>`;
                addingReceivedMessage(textToAdd);
            }
        }
        catch (e) {
            if (e instanceof Error) {
                console.log('error message: ', e.message);
            }
            else {
                console.log('unexpected error: ', e);
            }
        }
    });
};
//Index of the last read message
let lastIndexInHistory = 0;
// function for refreshing the content of the window (automatic or manual see below)
function refresh() {
    return __awaiter(this, void 0, void 0, function* () {
        try {
            const user = globalUserName;
            const historyRequest = new HistoryRequest(user, lastIndexInHistory);
            const urlParams = new URLSearchParams(window.location.search);
            const request = yield fetch("/history/" + ownerName + "?" + urlParams, {
                method: "POST",
                body: JSON.stringify(historyRequest),
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
                // This is the place where you can perform trigger any operations for refreshing the page
                //addingReceivedMessage("Dummy message!")
                console.log(result);
                if (result.index >= lastIndexInHistory) {
                    console.log("je suis dans le if avant ma boucle for");
                    for (let i = 0; i < result.allMessages.length; i++) {
                        if (result.allMessages[i].receiver === globalUserName) {
                            addingReceivedMessage(result.allMessages[i].content);
                        }
                        lastIndexInHistory++;
                    }
                }
                /*
                if(result.allMessages[result.allMessages.length-1].receiver === globalUserName){
                    addingReceivedMessage(result.allMessages[result.allMessages.length-1].content)
                }*/
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
}
// Automatic refresh: the waiting time is given in milliseconds
const intervalRefresh = setInterval(refresh, 2000);
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoibWVzc2VuZ2VyLmpzIiwic291cmNlUm9vdCI6IiIsInNvdXJjZXMiOlsiLi4vc3JjL2xpYkNyeXB0by50cyIsIi4uL3NyYy9tZXNzZW5nZXIudHMiXSwibmFtZXMiOltdLCJtYXBwaW5ncyI6Ijs7Ozs7Ozs7O0FBQUEsaUZBQWlGO0FBRWpGOzs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7OztFQWdDRTtBQUVGLHVGQUF1RjtBQUV2Rjs7O0VBR0U7QUFDRixTQUFlLDhCQUE4QixDQUFDLFVBQWtCOztRQUM1RCxJQUFJLENBQUM7WUFDRCxNQUFNLGNBQWMsR0FBZ0IsSUFBSSxDQUFDLHlCQUF5QixDQUFDLFVBQVUsQ0FBQyxDQUFBO1lBQzlFLE1BQU0sR0FBRyxHQUFjLE1BQU0sTUFBTSxDQUFDLE1BQU0sQ0FBQyxNQUFNLENBQUMsU0FBUyxDQUN2RCxNQUFNLEVBQ04sY0FBYyxFQUNkO2dCQUNJLElBQUksRUFBRSxVQUFVO2dCQUNoQixJQUFJLEVBQUUsU0FBUzthQUNsQixFQUNELElBQUksRUFDSixDQUFDLFNBQVMsQ0FBQyxDQUNkLENBQUE7WUFDRCxPQUFPLEdBQUcsQ0FBQTtRQUNkLENBQUM7UUFBQyxPQUFPLENBQUMsRUFBRSxDQUFDO1lBQ1QsSUFBSSxDQUFDLFlBQVksWUFBWSxFQUFFLENBQUM7Z0JBQUMsT0FBTyxDQUFDLEdBQUcsQ0FBQywyREFBMkQsQ0FBQyxDQUFBO1lBQUMsQ0FBQztpQkFDdEcsSUFBSSxDQUFDLFlBQVksa0JBQWtCLEVBQUUsQ0FBQztnQkFBQyxPQUFPLENBQUMsR0FBRyxDQUFDLDJEQUEyRCxDQUFDLENBQUE7WUFBQyxDQUFDO2lCQUNqSCxDQUFDO2dCQUFDLE9BQU8sQ0FBQyxHQUFHLENBQUMsQ0FBQyxDQUFDLENBQUE7WUFBQyxDQUFDO1lBQ3ZCLE1BQU0sQ0FBQyxDQUFBO1FBQ1gsQ0FBQztJQUNMLENBQUM7Q0FBQTtBQUVEOzs7RUFHRTtBQUNGLFNBQWUsNkJBQTZCLENBQUMsVUFBa0I7O1FBQzNELElBQUksQ0FBQztZQUNELE1BQU0sY0FBYyxHQUFnQixJQUFJLENBQUMseUJBQXlCLENBQUMsVUFBVSxDQUFDLENBQUE7WUFDOUUsTUFBTSxHQUFHLEdBQWMsTUFBTSxNQUFNLENBQUMsTUFBTSxDQUFDLE1BQU0sQ0FBQyxTQUFTLENBQ3ZELE1BQU0sRUFDTixjQUFjLEVBQ2Q7Z0JBQ0ksSUFBSSxFQUFFLG1CQUFtQjtnQkFDekIsSUFBSSxFQUFFLFNBQVM7YUFDbEIsRUFDRCxJQUFJLEVBQ0osQ0FBQyxRQUFRLENBQUMsQ0FDYixDQUFBO1lBQ0QsT0FBTyxHQUFHLENBQUE7UUFDZCxDQUFDO1FBQUMsT0FBTyxDQUFDLEVBQUUsQ0FBQztZQUNULElBQUksQ0FBQyxZQUFZLFlBQVksRUFBRSxDQUFDO2dCQUFDLE9BQU8sQ0FBQyxHQUFHLENBQUMsdUVBQXVFLENBQUMsQ0FBQTtZQUFDLENBQUM7aUJBQ2xILElBQUksQ0FBQyxZQUFZLGtCQUFrQixFQUFFLENBQUM7Z0JBQUMsT0FBTyxDQUFDLEdBQUcsQ0FBQyx1RUFBdUUsQ0FBQyxDQUFBO1lBQUMsQ0FBQztpQkFDN0gsQ0FBQztnQkFBQyxPQUFPLENBQUMsR0FBRyxDQUFDLENBQUMsQ0FBQyxDQUFBO1lBQUMsQ0FBQztZQUN2QixNQUFNLENBQUMsQ0FBQTtRQUNYLENBQUM7SUFDTCxDQUFDO0NBQUE7QUFFRDs7O0VBR0U7QUFDRixTQUFlLCtCQUErQixDQUFDLFVBQWtCOztRQUM3RCxJQUFJLENBQUM7WUFDRCxNQUFNLGNBQWMsR0FBZ0IsSUFBSSxDQUFDLHlCQUF5QixDQUFDLFVBQVUsQ0FBQyxDQUFBO1lBQzlFLE1BQU0sR0FBRyxHQUFjLE1BQU0sTUFBTSxDQUFDLE1BQU0sQ0FBQyxNQUFNLENBQUMsU0FBUyxDQUN2RCxPQUFPLEVBQ1AsY0FBYyxFQUNkO2dCQUNJLElBQUksRUFBRSxVQUFVO2dCQUNoQixJQUFJLEVBQUUsU0FBUzthQUNsQixFQUNELElBQUksRUFDSixDQUFDLFNBQVMsQ0FBQyxDQUFDLENBQUE7WUFDaEIsT0FBTyxHQUFHLENBQUE7UUFDZCxDQUFDO1FBQUMsT0FBTyxDQUFDLEVBQUUsQ0FBQztZQUNULElBQUksQ0FBQyxZQUFZLFlBQVksRUFBRSxDQUFDO2dCQUFDLE9BQU8sQ0FBQyxHQUFHLENBQUMsNERBQTRELENBQUMsQ0FBQTtZQUFDLENBQUM7aUJBQ3ZHLElBQUksQ0FBQyxZQUFZLGtCQUFrQixFQUFFLENBQUM7Z0JBQUMsT0FBTyxDQUFDLEdBQUcsQ0FBQyw0REFBNEQsQ0FBQyxDQUFBO1lBQUMsQ0FBQztpQkFDbEgsQ0FBQztnQkFBQyxPQUFPLENBQUMsR0FBRyxDQUFDLENBQUMsQ0FBQyxDQUFBO1lBQUMsQ0FBQztZQUN2QixNQUFNLENBQUMsQ0FBQTtRQUNYLENBQUM7SUFDTCxDQUFDO0NBQUE7QUFFRDs7O0VBR0U7QUFDRixTQUFlLDhCQUE4QixDQUFDLFVBQWtCOztRQUM1RCxJQUFJLENBQUM7WUFDRCxNQUFNLGNBQWMsR0FBZ0IsSUFBSSxDQUFDLHlCQUF5QixDQUFDLFVBQVUsQ0FBQyxDQUFBO1lBQzlFLE1BQU0sR0FBRyxHQUFjLE1BQU0sTUFBTSxDQUFDLE1BQU0sQ0FBQyxNQUFNLENBQUMsU0FBUyxDQUN2RCxPQUFPLEVBQ1AsY0FBYyxFQUNkO2dCQUNJLElBQUksRUFBRSxtQkFBbUI7Z0JBQ3pCLElBQUksRUFBRSxTQUFTO2FBQ2xCLEVBQ0QsSUFBSSxFQUNKLENBQUMsTUFBTSxDQUFDLENBQUMsQ0FBQTtZQUNiLE9BQU8sR0FBRyxDQUFBO1FBQ2QsQ0FBQztRQUFDLE9BQU8sQ0FBQyxFQUFFLENBQUM7WUFDVCxJQUFJLENBQUMsWUFBWSxZQUFZLEVBQUUsQ0FBQztnQkFBQyxPQUFPLENBQUMsR0FBRyxDQUFDLDJEQUEyRCxDQUFDLENBQUE7WUFBQyxDQUFDO2lCQUN0RyxJQUFJLENBQUMsWUFBWSxrQkFBa0IsRUFBRSxDQUFDO2dCQUFDLE9BQU8sQ0FBQyxHQUFHLENBQUMsMkRBQTJELENBQUMsQ0FBQTtZQUFDLENBQUM7aUJBQ2pILENBQUM7Z0JBQUMsT0FBTyxDQUFDLEdBQUcsQ0FBQyxDQUFDLENBQUMsQ0FBQTtZQUFDLENBQUM7WUFDdkIsTUFBTSxDQUFDLENBQUE7UUFDWCxDQUFDO0lBQ0wsQ0FBQztDQUFBO0FBQ0Q7OztFQUdFO0FBRUYsU0FBZSxpQkFBaUIsQ0FBQyxHQUFjOztRQUMzQyxNQUFNLFdBQVcsR0FBZ0IsTUFBTSxNQUFNLENBQUMsTUFBTSxDQUFDLE1BQU0sQ0FBQyxTQUFTLENBQUMsTUFBTSxFQUFFLEdBQUcsQ0FBQyxDQUFBO1FBQ2xGLE9BQU8sSUFBSSxDQUFDLHlCQUF5QixDQUFDLFdBQVcsQ0FBQyxDQUFBO0lBQ3RELENBQUM7Q0FBQTtBQUVEOzs7RUFHRTtBQUNGLFNBQWUsa0JBQWtCLENBQUMsR0FBYzs7UUFDNUMsTUFBTSxXQUFXLEdBQWdCLE1BQU0sTUFBTSxDQUFDLE1BQU0sQ0FBQyxNQUFNLENBQUMsU0FBUyxDQUFDLE9BQU8sRUFBRSxHQUFHLENBQUMsQ0FBQTtRQUNuRixPQUFPLElBQUksQ0FBQyx5QkFBeUIsQ0FBQyxXQUFXLENBQUMsQ0FBQTtJQUN0RCxDQUFDO0NBQUE7QUFFRCwrRUFBK0U7QUFDL0UsU0FBZSxtQ0FBbUM7O1FBQzlDLE1BQU0sT0FBTyxHQUFrQixNQUFNLE1BQU0sQ0FBQyxNQUFNLENBQUMsTUFBTSxDQUFDLFdBQVcsQ0FDakU7WUFDSSxJQUFJLEVBQUUsVUFBVTtZQUNoQixhQUFhLEVBQUUsSUFBSTtZQUNuQixjQUFjLEVBQUUsSUFBSSxVQUFVLENBQUMsQ0FBQyxDQUFDLEVBQUUsQ0FBQyxFQUFFLENBQUMsQ0FBQyxDQUFDO1lBQ3pDLElBQUksRUFBRSxTQUFTO1NBQ2xCLEVBQ0QsSUFBSSxFQUNKLENBQUMsU0FBUyxFQUFFLFNBQVMsQ0FBQyxDQUN6QixDQUFBO1FBQ0QsT0FBTyxDQUFDLE9BQU8sQ0FBQyxTQUFTLEVBQUUsT0FBTyxDQUFDLFVBQVUsQ0FBQyxDQUFBO0lBQ2xELENBQUM7Q0FBQTtBQUVELDJFQUEyRTtBQUMzRSxTQUFlLGtDQUFrQzs7UUFDN0MsTUFBTSxPQUFPLEdBQWtCLE1BQU0sTUFBTSxDQUFDLE1BQU0sQ0FBQyxNQUFNLENBQUMsV0FBVyxDQUNqRTtZQUNJLElBQUksRUFBRSxtQkFBbUI7WUFDekIsYUFBYSxFQUFFLElBQUk7WUFDbkIsY0FBYyxFQUFFLElBQUksVUFBVSxDQUFDLENBQUMsQ0FBQyxFQUFFLENBQUMsRUFBRSxDQUFDLENBQUMsQ0FBQztZQUN6QyxJQUFJLEVBQUUsU0FBUztTQUNsQixFQUNELElBQUksRUFDSixDQUFDLE1BQU0sRUFBRSxRQUFRLENBQUMsQ0FDckIsQ0FBQTtRQUNELE9BQU8sQ0FBQyxPQUFPLENBQUMsU0FBUyxFQUFFLE9BQU8sQ0FBQyxVQUFVLENBQUMsQ0FBQTtJQUNsRCxDQUFDO0NBQUE7QUFFRCw4QkFBOEI7QUFDOUIsU0FBUyxhQUFhO0lBQ2xCLE1BQU0sVUFBVSxHQUFHLElBQUksV0FBVyxDQUFDLENBQUMsQ0FBQyxDQUFBO0lBQ3JDLElBQUksQ0FBQyxNQUFNLENBQUMsZUFBZSxDQUFDLFVBQVUsQ0FBQyxDQUFBO0lBQ3ZDLE9BQU8sVUFBVSxDQUFDLENBQUMsQ0FBQyxDQUFDLFFBQVEsRUFBRSxDQUFBO0FBQ25DLENBQUM7QUFFRCwwQ0FBMEM7QUFDMUMsU0FBZSxvQkFBb0IsQ0FBQyxTQUFvQixFQUFFLE9BQWU7O1FBQ3JFLE9BQU8sQ0FBQyxHQUFHLENBQUMsZUFBZSxHQUFHLFNBQVMsR0FBRyxZQUFZLEdBQUcsT0FBTyxDQUFDLENBQUE7UUFDakUsSUFBSSxDQUFDO1lBQ0QsTUFBTSxvQkFBb0IsR0FBRyxpQkFBaUIsQ0FBQyxPQUFPLENBQUMsQ0FBQTtZQUN2RCxNQUFNLGlCQUFpQixHQUFnQixNQUFNLE1BQU0sQ0FBQyxNQUFNLENBQUMsTUFBTSxDQUFDLE9BQU8sQ0FDckUsRUFBRSxJQUFJLEVBQUUsVUFBVSxFQUFFLEVBQ3BCLFNBQVMsRUFDVCxvQkFBb0IsQ0FDdkIsQ0FBQTtZQUNELE9BQU8sSUFBSSxDQUFDLHlCQUF5QixDQUFDLGlCQUFpQixDQUFDLENBQUE7UUFDNUQsQ0FBQztRQUFDLE9BQU8sQ0FBQyxFQUFFLENBQUM7WUFDVCxJQUFJLENBQUMsWUFBWSxZQUFZLEVBQUUsQ0FBQztnQkFBQyxPQUFPLENBQUMsR0FBRyxDQUFDLENBQUMsQ0FBQyxDQUFDO2dCQUFDLE9BQU8sQ0FBQyxHQUFHLENBQUMsb0JBQW9CLENBQUMsQ0FBQTtZQUFDLENBQUM7aUJBQy9FLElBQUksQ0FBQyxZQUFZLGtCQUFrQixFQUFFLENBQUM7Z0JBQUMsT0FBTyxDQUFDLEdBQUcsQ0FBQyxnREFBZ0QsQ0FBQyxDQUFBO1lBQUMsQ0FBQztpQkFDdEcsQ0FBQztnQkFBQyxPQUFPLENBQUMsR0FBRyxDQUFDLENBQUMsQ0FBQyxDQUFBO1lBQUMsQ0FBQztZQUN2QixNQUFNLENBQUMsQ0FBQTtRQUNYLENBQUM7SUFDTCxDQUFDO0NBQUE7QUFFRCx1Q0FBdUM7QUFDdkMsU0FBZSxrQkFBa0IsQ0FBQyxVQUFxQixFQUFFLE9BQWU7O1FBQ3BFLE9BQU8sQ0FBQyxHQUFHLENBQUMsWUFBWSxHQUFHLFVBQVUsR0FBRyxZQUFZLEdBQUcsT0FBTyxDQUFDLENBQUE7UUFDL0QsSUFBSSxDQUFDO1lBQ0QsTUFBTSxvQkFBb0IsR0FBRyxpQkFBaUIsQ0FBQyxPQUFPLENBQUMsQ0FBQTtZQUN2RCxNQUFNLGVBQWUsR0FBZ0IsTUFBTSxNQUFNLENBQUMsTUFBTSxDQUFDLE1BQU0sQ0FBQyxJQUFJLENBQ2hFLG1CQUFtQixFQUNuQixVQUFVLEVBQ1Ysb0JBQW9CLENBQ3ZCLENBQUE7WUFDRCxPQUFPLElBQUksQ0FBQyx5QkFBeUIsQ0FBQyxlQUFlLENBQUMsQ0FBQTtRQUMxRCxDQUFDO1FBQUMsT0FBTyxDQUFDLEVBQUUsQ0FBQztZQUNULElBQUksQ0FBQyxZQUFZLFlBQVksRUFBRSxDQUFDO2dCQUFDLE9BQU8sQ0FBQyxHQUFHLENBQUMsQ0FBQyxDQUFDLENBQUM7Z0JBQUMsT0FBTyxDQUFDLEdBQUcsQ0FBQyxtQkFBbUIsQ0FBQyxDQUFBO1lBQUMsQ0FBQztpQkFDOUUsSUFBSSxDQUFDLFlBQVksa0JBQWtCLEVBQUUsQ0FBQztnQkFBQyxPQUFPLENBQUMsR0FBRyxDQUFDLDhDQUE4QyxDQUFDLENBQUE7WUFBQyxDQUFDO2lCQUNwRyxDQUFDO2dCQUFDLE9BQU8sQ0FBQyxHQUFHLENBQUMsQ0FBQyxDQUFDLENBQUE7WUFBQyxDQUFDO1lBQ3ZCLE1BQU0sQ0FBQyxDQUFBO1FBQ1gsQ0FBQztJQUNMLENBQUM7Q0FBQTtBQUdELDJDQUEyQztBQUMzQyxTQUFlLHFCQUFxQixDQUFDLFVBQXFCLEVBQUUsT0FBZTs7UUFDdkUsSUFBSSxDQUFDO1lBQ0QsTUFBTSxrQkFBa0IsR0FBZ0IsTUFDcEMsTUFBTSxDQUFDLE1BQU0sQ0FBQyxNQUFNLENBQUMsT0FBTyxDQUN4QixFQUFFLElBQUksRUFBRSxVQUFVLEVBQUUsRUFDcEIsVUFBVSxFQUNWLElBQUksQ0FBQyx5QkFBeUIsQ0FBQyxPQUFPLENBQUMsQ0FDMUMsQ0FBQTtZQUNMLE9BQU8sSUFBSSxDQUFDLGlCQUFpQixDQUFDLGtCQUFrQixDQUFDLENBQUE7UUFDckQsQ0FBQztRQUFDLE9BQU8sQ0FBQyxFQUFFLENBQUM7WUFDVCxJQUFJLENBQUMsWUFBWSxZQUFZLEVBQUUsQ0FBQztnQkFDNUIsT0FBTyxDQUFDLEdBQUcsQ0FBQyxrREFBa0QsQ0FBQyxDQUFBO1lBQ25FLENBQUM7aUJBQU0sSUFBSSxDQUFDLFlBQVksa0JBQWtCLEVBQUUsQ0FBQztnQkFDekMsT0FBTyxDQUFDLEdBQUcsQ0FBQyxpREFBaUQsQ0FBQyxDQUFBO1lBQ2xFLENBQUM7O2dCQUNJLE9BQU8sQ0FBQyxHQUFHLENBQUMsbUJBQW1CLENBQUMsQ0FBQTtZQUNyQyxNQUFNLENBQUMsQ0FBQTtRQUNYLENBQUM7SUFDTCxDQUFDO0NBQUE7QUFHRCxnRUFBZ0U7QUFDaEUsU0FBZSw0QkFBNEIsQ0FBQyxTQUFvQixFQUFFLGNBQXNCLEVBQUUsYUFBcUI7O1FBQzNHLElBQUksQ0FBQztZQUNELE1BQU0sbUJBQW1CLEdBQUcseUJBQXlCLENBQUMsYUFBYSxDQUFDLENBQUE7WUFDcEUsTUFBTSwyQkFBMkIsR0FBRyxpQkFBaUIsQ0FBQyxjQUFjLENBQUMsQ0FBQTtZQUNyRSxNQUFNLFFBQVEsR0FBWSxNQUN0QixNQUFNLENBQUMsTUFBTSxDQUFDLE1BQU0sQ0FBQyxNQUFNLENBQ3ZCLG1CQUFtQixFQUNuQixTQUFTLEVBQ1QsbUJBQW1CLEVBQ25CLDJCQUEyQixDQUFDLENBQUE7WUFDcEMsT0FBTyxRQUFRLENBQUE7UUFDbkIsQ0FBQztRQUFDLE9BQU8sQ0FBQyxFQUFFLENBQUM7WUFDVCxJQUFJLENBQUMsWUFBWSxZQUFZLEVBQUUsQ0FBQztnQkFDNUIsT0FBTyxDQUFDLEdBQUcsQ0FBQyw4REFBOEQsQ0FBQyxDQUFBO1lBQy9FLENBQUM7aUJBQU0sSUFBSSxDQUFDLFlBQVksa0JBQWtCLEVBQUUsQ0FBQztnQkFDekMsT0FBTyxDQUFDLEdBQUcsQ0FBQyxzREFBc0QsQ0FBQyxDQUFBO1lBQ3ZFLENBQUM7O2dCQUNJLE9BQU8sQ0FBQyxHQUFHLENBQUMsbUJBQW1CLENBQUMsQ0FBQTtZQUNyQyxNQUFNLENBQUMsQ0FBQTtRQUNYLENBQUM7SUFDTCxDQUFDO0NBQUE7QUFHRCx1Q0FBdUM7QUFDdkMsU0FBZSxtQkFBbUI7O1FBQzlCLE1BQU0sR0FBRyxHQUFjLE1BQU0sTUFBTSxDQUFDLE1BQU0sQ0FBQyxNQUFNLENBQUMsV0FBVyxDQUN6RDtZQUNJLElBQUksRUFBRSxTQUFTO1lBQ2YsTUFBTSxFQUFFLEdBQUc7U0FDZCxFQUNELElBQUksRUFDSixDQUFDLFNBQVMsRUFBRSxTQUFTLENBQUMsQ0FDekIsQ0FBQTtRQUNELE9BQU8sR0FBRyxDQUFBO0lBQ2QsQ0FBQztDQUFBO0FBRUQsdUNBQXVDO0FBQ3ZDLFNBQWUsb0JBQW9CLENBQUMsR0FBYzs7UUFDOUMsTUFBTSxXQUFXLEdBQWdCLE1BQU0sTUFBTSxDQUFDLE1BQU0sQ0FBQyxNQUFNLENBQUMsU0FBUyxDQUFDLEtBQUssRUFBRSxHQUFHLENBQUMsQ0FBQTtRQUNqRixPQUFPLHlCQUF5QixDQUFDLFdBQVcsQ0FBQyxDQUFBO0lBQ2pELENBQUM7Q0FBQTtBQUVELDBEQUEwRDtBQUMxRCxTQUFlLG9CQUFvQixDQUFDLFVBQWtCOztRQUNsRCxJQUFJLENBQUM7WUFDRCxNQUFNLGNBQWMsR0FBZ0IseUJBQXlCLENBQUMsVUFBVSxDQUFDLENBQUE7WUFDekUsTUFBTSxHQUFHLEdBQWMsTUFBTSxNQUFNLENBQUMsTUFBTSxDQUFDLE1BQU0sQ0FBQyxTQUFTLENBQ3ZELEtBQUssRUFDTCxjQUFjLEVBQ2QsU0FBUyxFQUNULElBQUksRUFDSixDQUFDLFNBQVMsRUFBRSxTQUFTLENBQUMsQ0FBQyxDQUFBO1lBQzNCLE9BQU8sR0FBRyxDQUFBO1FBQ2QsQ0FBQztRQUFDLE9BQU8sQ0FBQyxFQUFFLENBQUM7WUFDVCxJQUFJLENBQUMsWUFBWSxZQUFZLEVBQUUsQ0FBQztnQkFBQyxPQUFPLENBQUMsR0FBRyxDQUFDLDZDQUE2QyxDQUFDLENBQUE7WUFBQyxDQUFDO2lCQUN4RixJQUFJLENBQUMsWUFBWSxrQkFBa0IsRUFBRSxDQUFDO2dCQUFDLE9BQU8sQ0FBQyxHQUFHLENBQUMsNkNBQTZDLENBQUMsQ0FBQTtZQUFDLENBQUM7aUJBQ25HLENBQUM7Z0JBQUMsT0FBTyxDQUFDLEdBQUcsQ0FBQyxDQUFDLENBQUMsQ0FBQTtZQUFDLENBQUM7WUFDdkIsTUFBTSxDQUFDLENBQUE7UUFDWCxDQUFDO0lBQ0wsQ0FBQztDQUFBO0FBR0QsMkdBQTJHO0FBQzNHLHNHQUFzRztBQUN0Ryw0R0FBNEc7QUFDNUcsNEdBQTRHO0FBQzVHLHVFQUF1RTtBQUN2RSxHQUFHO0FBQ0gsZ0ZBQWdGO0FBQ2hGLDZFQUE2RTtBQUU3RSxTQUFlLHVCQUF1QixDQUFDLEdBQWMsRUFBRSxPQUFlOztRQUNsRSxPQUFPLENBQUMsR0FBRyxDQUFDLGVBQWUsR0FBRyxHQUFHLEdBQUcsWUFBWSxHQUFHLE9BQU8sQ0FBQyxDQUFBO1FBQzNELElBQUksQ0FBQztZQUNELE1BQU0sb0JBQW9CLEdBQUcsaUJBQWlCLENBQUMsT0FBTyxDQUFDLENBQUE7WUFDdkQsTUFBTSxFQUFFLEdBQUcsTUFBTSxDQUFDLE1BQU0sQ0FBQyxlQUFlLENBQUMsSUFBSSxVQUFVLENBQUMsRUFBRSxDQUFDLENBQUMsQ0FBQztZQUM3RCxNQUFNLE1BQU0sR0FBRyx5QkFBeUIsQ0FBQyxFQUFFLENBQUMsQ0FBQTtZQUM1QyxNQUFNLGlCQUFpQixHQUFnQixNQUFNLE1BQU0sQ0FBQyxNQUFNLENBQUMsTUFBTSxDQUFDLE9BQU8sQ0FDckUsRUFBRSxJQUFJLEVBQUUsU0FBUyxFQUFFLEVBQUUsRUFBRSxFQUN2QixHQUFHLEVBQ0gsb0JBQW9CLENBQ3ZCLENBQUE7WUFDRCxPQUFPLENBQUMseUJBQXlCLENBQUMsaUJBQWlCLENBQUMsRUFBRSxNQUFNLENBQUMsQ0FBQTtRQUNqRSxDQUFDO1FBQUMsT0FBTyxDQUFDLEVBQUUsQ0FBQztZQUNULElBQUksQ0FBQyxZQUFZLFlBQVksRUFBRSxDQUFDO2dCQUFDLE9BQU8sQ0FBQyxHQUFHLENBQUMsQ0FBQyxDQUFDLENBQUM7Z0JBQUMsT0FBTyxDQUFDLEdBQUcsQ0FBQyxvQkFBb0IsQ0FBQyxDQUFBO1lBQUMsQ0FBQztpQkFDL0UsSUFBSSxDQUFDLFlBQVksa0JBQWtCLEVBQUUsQ0FBQztnQkFBQyxPQUFPLENBQUMsR0FBRyxDQUFDLG1EQUFtRCxDQUFDLENBQUE7WUFBQyxDQUFDO2lCQUN6RyxDQUFDO2dCQUFDLE9BQU8sQ0FBQyxHQUFHLENBQUMsQ0FBQyxDQUFDLENBQUE7WUFBQyxDQUFDO1lBQ3ZCLE1BQU0sQ0FBQyxDQUFBO1FBQ1gsQ0FBQztJQUNMLENBQUM7Q0FBQTtBQUVELHVHQUF1RztBQUN2RyxvREFBb0Q7QUFDcEQsU0FBZSx1QkFBdUIsQ0FBQyxHQUFjLEVBQUUsT0FBZSxFQUFFLFVBQWtCOztRQUN0RixNQUFNLGlCQUFpQixHQUFnQix5QkFBeUIsQ0FBQyxVQUFVLENBQUMsQ0FBQTtRQUM1RSxJQUFJLENBQUM7WUFDRCxNQUFNLGtCQUFrQixHQUFnQixNQUNwQyxNQUFNLENBQUMsTUFBTSxDQUFDLE1BQU0sQ0FBQyxPQUFPLENBQ3hCLEVBQUUsSUFBSSxFQUFFLFNBQVMsRUFBRSxFQUFFLEVBQUUsaUJBQWlCLEVBQUUsRUFDMUMsR0FBRyxFQUNILHlCQUF5QixDQUFDLE9BQU8sQ0FBQyxDQUNyQyxDQUFBO1lBQ0wsT0FBTyxJQUFJLENBQUMsaUJBQWlCLENBQUMsa0JBQWtCLENBQUMsQ0FBQTtRQUNyRCxDQUFDO1FBQUMsT0FBTyxDQUFDLEVBQUUsQ0FBQztZQUNULElBQUksQ0FBQyxZQUFZLFlBQVksRUFBRSxDQUFDO2dCQUM1QixPQUFPLENBQUMsR0FBRyxDQUFDLGtEQUFrRCxDQUFDLENBQUE7WUFDbkUsQ0FBQztpQkFBTSxJQUFJLENBQUMsWUFBWSxrQkFBa0IsRUFBRSxDQUFDO2dCQUN6QyxPQUFPLENBQUMsR0FBRyxDQUFDLG1EQUFtRCxDQUFDLENBQUE7WUFDcEUsQ0FBQzs7Z0JBQ0ksT0FBTyxDQUFDLEdBQUcsQ0FBQyxtQkFBbUIsQ0FBQyxDQUFBO1lBQ3JDLE1BQU0sQ0FBQyxDQUFBO1FBQ1gsQ0FBQztJQUNMLENBQUM7Q0FBQTtBQUVELDJCQUEyQjtBQUMzQixTQUFlLElBQUksQ0FBQyxJQUFZOztRQUM1QixNQUFNLGFBQWEsR0FBRyxpQkFBaUIsQ0FBQyxJQUFJLENBQUMsQ0FBQTtRQUM3QyxNQUFNLFdBQVcsR0FBRyxNQUFNLE1BQU0sQ0FBQyxNQUFNLENBQUMsTUFBTSxDQUFDLE1BQU0sQ0FBQyxTQUFTLEVBQUUsYUFBYSxDQUFDLENBQUE7UUFDL0UsT0FBTyx5QkFBeUIsQ0FBQyxXQUFXLENBQUMsQ0FBQTtJQUNqRCxDQUFDO0NBQUE7QUFFRCxNQUFNLGtCQUFtQixTQUFRLEtBQUs7Q0FBSTtBQUUxQyxpQ0FBaUM7QUFDakMsU0FBUyx5QkFBeUIsQ0FBQyxXQUF3QjtJQUN2RCxJQUFJLFNBQVMsR0FBRyxJQUFJLFVBQVUsQ0FBQyxXQUFXLENBQUMsQ0FBQTtJQUMzQyxJQUFJLFVBQVUsR0FBRyxFQUFFLENBQUE7SUFDbkIsS0FBSyxJQUFJLENBQUMsR0FBRyxDQUFDLEVBQUUsQ0FBQyxHQUFHLFNBQVMsQ0FBQyxVQUFVLEVBQUUsQ0FBQyxFQUFFLEVBQUUsQ0FBQztRQUM1QyxVQUFVLElBQUksTUFBTSxDQUFDLFlBQVksQ0FBQyxTQUFTLENBQUMsQ0FBQyxDQUFDLENBQUMsQ0FBQTtJQUNuRCxDQUFDO0lBQ0QsT0FBTyxJQUFJLENBQUMsVUFBVSxDQUFDLENBQUE7QUFDM0IsQ0FBQztBQUVELGtDQUFrQztBQUNsQyxTQUFTLHlCQUF5QixDQUFDLE1BQWM7SUFDN0MsSUFBSSxDQUFDO1FBQ0QsSUFBSSxPQUFPLEdBQUcsSUFBSSxDQUFDLE1BQU0sQ0FBQyxDQUFBO1FBQzFCLElBQUksS0FBSyxHQUFHLElBQUksVUFBVSxDQUFDLE9BQU8sQ0FBQyxNQUFNLENBQUMsQ0FBQTtRQUMxQyxLQUFLLElBQUksQ0FBQyxHQUFHLENBQUMsRUFBRSxDQUFDLEdBQUcsT0FBTyxDQUFDLE1BQU0sRUFBRSxDQUFDLEVBQUUsRUFBRSxDQUFDO1lBQ3RDLEtBQUssQ0FBQyxDQUFDLENBQUMsR0FBRyxPQUFPLENBQUMsVUFBVSxDQUFDLENBQUMsQ0FBQyxDQUFBO1FBQ3BDLENBQUM7UUFDRCxPQUFPLEtBQUssQ0FBQyxNQUFNLENBQUE7SUFDdkIsQ0FBQztJQUFDLE9BQU8sQ0FBQyxFQUFFLENBQUM7UUFDVCxPQUFPLENBQUMsR0FBRyxDQUFDLHVCQUF1QixNQUFNLENBQUMsU0FBUyxDQUFDLENBQUMsRUFBRSxFQUFFLENBQUMsaURBQWlELENBQUMsQ0FBQTtRQUM1RyxNQUFNLElBQUksa0JBQWtCLENBQUE7SUFDaEMsQ0FBQztBQUNMLENBQUM7QUFFRCx5QkFBeUI7QUFDekIsU0FBUyxpQkFBaUIsQ0FBQyxHQUFXO0lBQ2xDLElBQUksR0FBRyxHQUFHLGtCQUFrQixDQUFDLEdBQUcsQ0FBQyxDQUFBLENBQUMsd0JBQXdCO0lBQzFELElBQUksT0FBTyxHQUFHLElBQUksVUFBVSxDQUFDLEdBQUcsQ0FBQyxNQUFNLENBQUMsQ0FBQTtJQUN4QyxLQUFLLElBQUksQ0FBQyxHQUFHLENBQUMsRUFBRSxDQUFDLEdBQUcsR0FBRyxDQUFDLE1BQU0sRUFBRSxDQUFDLEVBQUUsRUFBRSxDQUFDO1FBQ2xDLE9BQU8sQ0FBQyxDQUFDLENBQUMsR0FBRyxHQUFHLENBQUMsVUFBVSxDQUFDLENBQUMsQ0FBQyxDQUFBO0lBQ2xDLENBQUM7SUFDRCxPQUFPLE9BQU8sQ0FBQTtBQUNsQixDQUFDO0FBRUQsMEJBQTBCO0FBQzFCLFNBQVMsaUJBQWlCLENBQUMsV0FBd0I7SUFDL0MsSUFBSSxTQUFTLEdBQUcsSUFBSSxVQUFVLENBQUMsV0FBVyxDQUFDLENBQUE7SUFDM0MsSUFBSSxHQUFHLEdBQUcsRUFBRSxDQUFBO0lBQ1osS0FBSyxJQUFJLENBQUMsR0FBRyxDQUFDLEVBQUUsQ0FBQyxHQUFHLFNBQVMsQ0FBQyxVQUFVLEVBQUUsQ0FBQyxFQUFFLEVBQUUsQ0FBQztRQUM1QyxHQUFHLElBQUksTUFBTSxDQUFDLFlBQVksQ0FBQyxTQUFTLENBQUMsQ0FBQyxDQUFDLENBQUMsQ0FBQTtJQUM1QyxDQUFDO0lBQ0QsT0FBTyxrQkFBa0IsQ0FBQyxHQUFHLENBQUMsQ0FBQTtBQUNsQyxDQUFDO0FDdGFELDRHQUE0RztBQUU1RywrQ0FBK0M7QUFDL0MsSUFBSSxDQUFDLE1BQU0sQ0FBQyxlQUFlO0lBQUUsS0FBSyxDQUFDLHFCQUFxQixDQUFDLENBQUE7QUFFekQsd0JBQXdCO0FBQ3hCLE1BQU0sV0FBVztJQUNiLFlBQW1CLFFBQWdCO1FBQWhCLGFBQVEsR0FBUixRQUFRLENBQVE7SUFBSSxDQUFDO0NBQzNDO0FBRUQsa0JBQWtCO0FBQ2xCLE1BQU0sVUFBVTtJQUNaLFlBQW1CLGFBQXFCLEVBQVMsU0FBa0IsRUFBUyxVQUFtQjtRQUE1RSxrQkFBYSxHQUFiLGFBQWEsQ0FBUTtRQUFTLGNBQVMsR0FBVCxTQUFTLENBQVM7UUFBUyxlQUFVLEdBQVYsVUFBVSxDQUFTO0lBQUksQ0FBQztDQUN2RztBQUVELE1BQU0sU0FBUztJQUNYLFlBQW1CLE9BQWdCLEVBQVMsR0FBVyxFQUFTLFlBQW9CO1FBQWpFLFlBQU8sR0FBUCxPQUFPLENBQVM7UUFBUyxRQUFHLEdBQUgsR0FBRyxDQUFRO1FBQVMsaUJBQVksR0FBWixZQUFZLENBQVE7SUFBSSxDQUFDO0NBQzVGO0FBRUQscUJBQXFCO0FBQ3JCLE1BQU0sVUFBVTtJQUNaLFlBQW1CLE1BQWMsRUFBUyxRQUFnQixFQUFTLE9BQWU7UUFBL0QsV0FBTSxHQUFOLE1BQU0sQ0FBUTtRQUFTLGFBQVEsR0FBUixRQUFRLENBQVE7UUFBUyxZQUFPLEdBQVAsT0FBTyxDQUFRO0lBQUksQ0FBQztDQUMxRjtBQUVELGtDQUFrQztBQUNsQyxNQUFNLFVBQVU7SUFDWixZQUFtQixPQUFnQixFQUFTLFlBQW9CO1FBQTdDLFlBQU8sR0FBUCxPQUFPLENBQVM7UUFBUyxpQkFBWSxHQUFaLFlBQVksQ0FBUTtJQUFJLENBQUM7Q0FDeEU7QUFFRCxnQ0FBZ0M7QUFDaEMsTUFBTSxjQUFjO0lBQ2hCLFlBQW1CLFNBQWlCLEVBQVMsS0FBYTtRQUF2QyxjQUFTLEdBQVQsU0FBUyxDQUFRO1FBQVMsVUFBSyxHQUFMLEtBQUssQ0FBUTtJQUFJLENBQUM7Q0FDbEU7QUFFRCw0QkFBNEI7QUFDNUIsTUFBTSxhQUFhO0lBQ2YsWUFBbUIsT0FBZ0IsRUFDeEIsY0FBc0IsRUFDdEIsS0FBYSxFQUNiLFdBQXlCO1FBSGpCLFlBQU8sR0FBUCxPQUFPLENBQVM7UUFDeEIsbUJBQWMsR0FBZCxjQUFjLENBQVE7UUFDdEIsVUFBSyxHQUFMLEtBQUssQ0FBUTtRQUNiLGdCQUFXLEdBQVgsV0FBVyxDQUFjO0lBQUksQ0FBQztDQUM1QztBQUVELE1BQU0sZUFBZSxHQUFHLFFBQVEsQ0FBQyxjQUFjLENBQUMsV0FBVyxDQUFxQixDQUFBO0FBRWhGLE1BQU0sVUFBVSxHQUFHLFFBQVEsQ0FBQyxjQUFjLENBQUMsYUFBYSxDQUFzQixDQUFBO0FBQzlFLE1BQU0sUUFBUSxHQUFHLFFBQVEsQ0FBQyxjQUFjLENBQUMsVUFBVSxDQUFxQixDQUFBO0FBQ3hFLE1BQU0sT0FBTyxHQUFHLFFBQVEsQ0FBQyxjQUFjLENBQUMsU0FBUyxDQUFxQixDQUFBO0FBQ3RFLE1BQU0saUJBQWlCLEdBQUcsUUFBUSxDQUFDLGNBQWMsQ0FBQyxvQkFBb0IsQ0FBcUIsQ0FBQTtBQUUzRixJQUFJLGNBQWMsR0FBRyxFQUFFLENBQUE7QUFHdkIsb0VBQW9FO0FBQ3BFLFNBQVMsZ0JBQWdCO0lBQ3JCLGlCQUFpQixDQUFDLFdBQVcsR0FBRyxFQUFFLENBQUE7QUFDdEMsQ0FBQztBQUVELFNBQVMsWUFBWSxDQUFDLEdBQVc7SUFDN0IsSUFBSSxPQUFPLEdBQUcsUUFBUSxDQUFDLGFBQWEsQ0FBQyxLQUFLLENBQUMsQ0FBQTtJQUMzQyxPQUFPLENBQUMsU0FBUyxHQUFHLEdBQUcsQ0FBQTtJQUN2QixPQUFPLE9BQU8sQ0FBQTtBQUNsQixDQUFDO0FBRUQsU0FBUyxxQkFBcUIsQ0FBQyxPQUFlO0lBQzFDLGlCQUFpQixDQUFDLE1BQU0sQ0FBQyxZQUFZLENBQUMsZ0JBQWdCLEdBQUcsT0FBTyxDQUFDLENBQUMsQ0FBQTtBQUN0RSxDQUFDO0FBRUQsV0FBVztBQUNYLDRFQUE0RTtBQUM1RSwwRkFBMEY7QUFDMUYscUZBQXFGO0FBQ3JGLDBCQUEwQjtBQUUxQixTQUFlLFlBQVk7O1FBQ3ZCLE1BQU0sU0FBUyxHQUFHLElBQUksZUFBZSxDQUFDLE1BQU0sQ0FBQyxRQUFRLENBQUMsTUFBTSxDQUFDLENBQUM7UUFDOUQsTUFBTSxXQUFXLEdBQUcsTUFBTSxLQUFLLENBQUMsV0FBVyxHQUFHLFNBQVMsRUFBRTtZQUNyRCxNQUFNLEVBQUUsS0FBSztZQUNiLE9BQU8sRUFBRTtnQkFDTCxjQUFjLEVBQUUsaUNBQWlDO2FBQ3BEO1NBQ0osQ0FBQyxDQUFDO1FBQ0gsSUFBSSxDQUFDLFdBQVcsQ0FBQyxFQUFFLEVBQUUsQ0FBQztZQUNsQixNQUFNLElBQUksS0FBSyxDQUFDLGtCQUFrQixXQUFXLENBQUMsTUFBTSxFQUFFLENBQUMsQ0FBQTtRQUMzRCxDQUFDO1FBQ0QsTUFBTSxVQUFVLEdBQUcsQ0FBQyxNQUFNLFdBQVcsQ0FBQyxJQUFJLEVBQUUsQ0FBZ0IsQ0FBQTtRQUM1RCxPQUFPLENBQUMsR0FBRyxDQUFDLG9CQUFvQixHQUFHLFVBQVUsQ0FBQyxRQUFRLENBQUMsQ0FBQTtRQUN2RCxPQUFPLFVBQVUsQ0FBQyxRQUFRLENBQUE7SUFDOUIsQ0FBQztDQUFBO0FBRUQsU0FBZSxVQUFVOztRQUNyQixjQUFjLEdBQUcsTUFBTSxZQUFZLEVBQUUsQ0FBQTtRQUNyQyx5RUFBeUU7UUFDekUsZ0JBQWdCO1FBQ2hCLGVBQWUsQ0FBQyxXQUFXLEdBQUcsY0FBYyxDQUFBO0lBQ2hELENBQUM7Q0FBQTtBQUVELFVBQVUsRUFBRSxDQUFBO0FBRVosV0FBVztBQUNYLGdHQUFnRztBQUNoRyxvR0FBb0c7QUFDcEcsZ0hBQWdIO0FBQ2hILDBIQUEwSDtBQUMxSCxvREFBb0Q7QUFFcEQsU0FBUyxZQUFZO0lBQ2pCLE1BQU0sSUFBSSxHQUFHLE1BQU0sQ0FBQyxRQUFRLENBQUMsUUFBUSxDQUFBO0lBQ3JDLE1BQU0sSUFBSSxHQUFHLElBQUksQ0FBQyxLQUFLLENBQUMsR0FBRyxFQUFFLENBQUMsQ0FBQyxDQUFDLENBQUMsQ0FBQyxDQUFBO0lBQ2xDLE9BQU8sSUFBSSxDQUFBO0FBQ2YsQ0FBQztBQUVELElBQUksU0FBUyxHQUFHLFlBQVksRUFBRSxDQUFBO0FBRTlCLFdBQVc7QUFDWCw0RUFBNEU7QUFDNUUsMEZBQTBGO0FBQzFGLHFGQUFxRjtBQUNyRiwwQkFBMEI7QUFFMUIsU0FBZSxRQUFRLENBQUMsSUFBWSxFQUFFLFNBQWtCLEVBQUUsVUFBbUI7O1FBQ3pFLDBDQUEwQztRQUMxQyxrREFBa0Q7UUFDbEQsb0RBQW9EO1FBQ3BELHNGQUFzRjtRQUN0RixxRkFBcUY7UUFDckYsTUFBTSxpQkFBaUIsR0FDbkIsSUFBSSxVQUFVLENBQUMsSUFBSSxFQUFFLFNBQVMsRUFBRSxVQUFVLENBQUMsQ0FBQTtRQUMvQyxrRUFBa0U7UUFDbEUsK0JBQStCO1FBQy9CLE1BQU0sU0FBUyxHQUFHLElBQUksZUFBZSxDQUFDLE1BQU0sQ0FBQyxRQUFRLENBQUMsTUFBTSxDQUFDLENBQUM7UUFDOUQsdURBQXVEO1FBQ3ZELG1EQUFtRDtRQUNuRCxNQUFNLFVBQVUsR0FBRyxNQUFNLEtBQUssQ0FBQyxVQUFVLEdBQUcsU0FBUyxFQUFFO1lBQ25ELE1BQU0sRUFBRSxNQUFNO1lBQ2QsSUFBSSxFQUFFLElBQUksQ0FBQyxTQUFTLENBQUMsaUJBQWlCLENBQUM7WUFDdkMsT0FBTyxFQUFFO2dCQUNMLGNBQWMsRUFBRSxpQ0FBaUM7YUFDcEQ7U0FDSixDQUFDLENBQUM7UUFDSCxJQUFJLENBQUMsVUFBVSxDQUFDLEVBQUUsRUFBRSxDQUFDO1lBQ2pCLE1BQU0sSUFBSSxLQUFLLENBQUMsa0JBQWtCLFVBQVUsQ0FBQyxNQUFNLEVBQUUsQ0FBQyxDQUFDO1FBQzNELENBQUM7UUFDRCxNQUFNLFNBQVMsR0FBRyxDQUFDLE1BQU0sVUFBVSxDQUFDLElBQUksRUFBRSxDQUFjLENBQUM7UUFDekQsSUFBSSxDQUFDLFNBQVMsQ0FBQyxPQUFPO1lBQUUsS0FBSyxDQUFDLFNBQVMsQ0FBQyxZQUFZLENBQUMsQ0FBQTthQUNoRCxDQUFDO1lBQ0YsSUFBSSxTQUFTLElBQUksVUFBVTtnQkFBRSxPQUFPLE1BQU0sOEJBQThCLENBQUMsU0FBUyxDQUFDLEdBQUcsQ0FBQyxDQUFBO2lCQUNsRixJQUFJLENBQUMsU0FBUyxJQUFJLFVBQVU7Z0JBQUUsT0FBTyxNQUFNLCtCQUErQixDQUFDLFNBQVMsQ0FBQyxHQUFHLENBQUMsQ0FBQTtpQkFDekYsSUFBSSxTQUFTLElBQUksQ0FBQyxVQUFVO2dCQUFFLE9BQU8sTUFBTSw2QkFBNkIsQ0FBQyxTQUFTLENBQUMsR0FBRyxDQUFDLENBQUE7aUJBQ3ZGLElBQUksQ0FBQyxTQUFTLElBQUksQ0FBQyxVQUFVO2dCQUFFLE9BQU8sTUFBTSw4QkFBOEIsQ0FBQyxTQUFTLENBQUMsR0FBRyxDQUFDLENBQUE7UUFDbEcsQ0FBQztJQUNMLENBQUM7Q0FBQTtBQUVELFdBQVc7QUFDWCw0RUFBNEU7QUFDNUUsMEZBQTBGO0FBQzFGLHFGQUFxRjtBQUNyRiwwQkFBMEI7QUFDMUIsR0FBRztBQUNILHdDQUF3QztBQUV4QyxTQUFlLFdBQVcsQ0FBQyxTQUFpQixFQUFFLFlBQW9CLEVBQUUsY0FBc0I7O1FBQ3RGLElBQUksQ0FBQztZQUNELElBQUksYUFBYSxHQUNiLElBQUksVUFBVSxDQUFDLFNBQVMsRUFBRSxZQUFZLEVBQUUsY0FBYyxDQUFDLENBQUE7WUFDM0QsTUFBTSxTQUFTLEdBQUcsSUFBSSxlQUFlLENBQUMsTUFBTSxDQUFDLFFBQVEsQ0FBQyxNQUFNLENBQUMsQ0FBQztZQUU5RCxNQUFNLE9BQU8sR0FBRyxNQUFNLEtBQUssQ0FBQyxrQkFBa0IsR0FBRyxTQUFTLEdBQUcsR0FBRyxHQUFHLFNBQVMsRUFBRTtnQkFDMUUsTUFBTSxFQUFFLE1BQU07Z0JBQ2QsSUFBSSxFQUFFLElBQUksQ0FBQyxTQUFTLENBQUMsYUFBYSxDQUFDO2dCQUNuQyxPQUFPLEVBQUU7b0JBQ0wsY0FBYyxFQUFFLGlDQUFpQztpQkFDcEQ7YUFDSixDQUFDLENBQUM7WUFDSCxJQUFJLENBQUMsT0FBTyxDQUFDLEVBQUUsRUFBRSxDQUFDO2dCQUNkLE1BQU0sSUFBSSxLQUFLLENBQUMsa0JBQWtCLE9BQU8sQ0FBQyxNQUFNLEVBQUUsQ0FBQyxDQUFDO1lBQ3hELENBQUM7WUFDRCxnREFBZ0Q7WUFDaEQsT0FBTyxDQUFDLEdBQUcsQ0FBQyxxQkFBcUIsU0FBUyxPQUFPLFlBQVksS0FBSyxjQUFjLEVBQUUsQ0FBQyxDQUFBO1lBQ25GLE9BQU8sQ0FBQyxNQUFNLE9BQU8sQ0FBQyxJQUFJLEVBQUUsQ0FBZSxDQUFBO1FBQy9DLENBQUM7UUFDRCxPQUFPLEtBQUssRUFBRSxDQUFDO1lBQ1gsSUFBSSxLQUFLLFlBQVksS0FBSyxFQUFFLENBQUM7Z0JBQ3pCLE9BQU8sQ0FBQyxHQUFHLENBQUMsaUJBQWlCLEVBQUUsS0FBSyxDQUFDLE9BQU8sQ0FBQyxDQUFDO2dCQUM5QyxPQUFPLElBQUksVUFBVSxDQUFDLEtBQUssRUFBRSxLQUFLLENBQUMsT0FBTyxDQUFDLENBQUE7WUFDL0MsQ0FBQztpQkFBTSxDQUFDO2dCQUNKLE9BQU8sQ0FBQyxHQUFHLENBQUMsb0JBQW9CLEVBQUUsS0FBSyxDQUFDLENBQUM7Z0JBQ3pDLE9BQU8sSUFBSSxVQUFVLENBQUMsS0FBSyxFQUFFLDhCQUE4QixDQUFDLENBQUE7WUFDaEUsQ0FBQztRQUNMLENBQUM7SUFDTCxDQUFDO0NBQUE7QUFFRCxVQUFVLENBQUMsT0FBTyxHQUFHOztRQUNqQixJQUFJLFNBQVMsR0FBRyxjQUFjLENBQUE7UUFDOUIsSUFBSSxZQUFZLEdBQUcsUUFBUSxDQUFDLEtBQUssQ0FBQTtRQUNqQyxJQUFJLENBQUM7WUFDRCxXQUFXO1lBQ1gsTUFBTSxVQUFVLEdBQUcsTUFBTSxXQUFXLENBQUMsU0FBUyxFQUFFLFlBQVksRUFBRSxPQUFPLENBQUMsS0FBSyxDQUFDLENBQUE7WUFDNUUsSUFBSSxDQUFDLFVBQVUsQ0FBQyxPQUFPO2dCQUFFLE9BQU8sQ0FBQyxHQUFHLENBQUMsVUFBVSxDQUFDLFlBQVksQ0FBQyxDQUFBO2lCQUN4RCxDQUFDO2dCQUNGLE9BQU8sQ0FBQyxHQUFHLENBQUMsZ0NBQWdDLENBQUMsQ0FBQTtnQkFDN0Msa0RBQWtEO2dCQUNsRCxNQUFNLFNBQVMsR0FBRyx1QkFBdUIsU0FBUyxPQUFPLFlBQVksTUFBTSxPQUFPLENBQUMsS0FBSyxVQUFVLENBQUE7Z0JBQ2xHLHFCQUFxQixDQUFDLFNBQVMsQ0FBQyxDQUFBO1lBQ3BDLENBQUM7UUFDTCxDQUFDO1FBQUMsT0FBTyxDQUFDLEVBQUUsQ0FBQztZQUNULElBQUksQ0FBQyxZQUFZLEtBQUssRUFBRSxDQUFDO2dCQUNyQixPQUFPLENBQUMsR0FBRyxDQUFDLGlCQUFpQixFQUFFLENBQUMsQ0FBQyxPQUFPLENBQUMsQ0FBQTtZQUM3QyxDQUFDO2lCQUFNLENBQUM7Z0JBQ0osT0FBTyxDQUFDLEdBQUcsQ0FBQyxvQkFBb0IsRUFBRSxDQUFDLENBQUMsQ0FBQztZQUN6QyxDQUFDO1FBQ0wsQ0FBQztJQUNMLENBQUM7Q0FBQSxDQUFBO0FBR0QsZ0NBQWdDO0FBQ2hDLElBQUksa0JBQWtCLEdBQUcsQ0FBQyxDQUFBO0FBRTFCLG9GQUFvRjtBQUNwRixTQUFlLE9BQU87O1FBQ2xCLElBQUksQ0FBQztZQUNELE1BQU0sSUFBSSxHQUFHLGNBQWMsQ0FBQTtZQUMzQixNQUFNLGNBQWMsR0FDaEIsSUFBSSxjQUFjLENBQUMsSUFBSSxFQUFFLGtCQUFrQixDQUFDLENBQUE7WUFDaEQsTUFBTSxTQUFTLEdBQUcsSUFBSSxlQUFlLENBQUMsTUFBTSxDQUFDLFFBQVEsQ0FBQyxNQUFNLENBQUMsQ0FBQztZQUM5RCxNQUFNLE9BQU8sR0FBRyxNQUFNLEtBQUssQ0FBQyxXQUFXLEdBQUcsU0FBUyxHQUFHLEdBQUcsR0FBRyxTQUFTLEVBQy9EO2dCQUNFLE1BQU0sRUFBRSxNQUFNO2dCQUNkLElBQUksRUFBRSxJQUFJLENBQUMsU0FBUyxDQUFDLGNBQWMsQ0FBQztnQkFDcEMsT0FBTyxFQUFFO29CQUNMLGNBQWMsRUFBRSxpQ0FBaUM7aUJBQ3BEO2FBQ0osQ0FBQyxDQUFDO1lBQ1AsSUFBSSxDQUFDLE9BQU8sQ0FBQyxFQUFFLEVBQUUsQ0FBQztnQkFDZCxNQUFNLElBQUksS0FBSyxDQUFDLGtCQUFrQixPQUFPLENBQUMsTUFBTSxFQUFFLENBQUMsQ0FBQztZQUN4RCxDQUFDO1lBQ0QsTUFBTSxNQUFNLEdBQUcsQ0FBQyxNQUFNLE9BQU8sQ0FBQyxJQUFJLEVBQUUsQ0FBa0IsQ0FBQTtZQUN0RCxJQUFJLENBQUMsTUFBTSxDQUFDLE9BQU8sRUFBRSxDQUFDO2dCQUFDLEtBQUssQ0FBQyxNQUFNLENBQUMsY0FBYyxDQUFDLENBQUE7WUFBQyxDQUFDO2lCQUNoRCxDQUFDO2dCQUNGLHlGQUF5RjtnQkFDekYseUNBQXlDO2dCQUN6QyxPQUFPLENBQUMsR0FBRyxDQUFDLE1BQU0sQ0FBQyxDQUFBO2dCQUNuQixJQUFHLE1BQU0sQ0FBQyxLQUFLLElBQUksa0JBQWtCLEVBQUUsQ0FBQztvQkFDcEMsT0FBTyxDQUFDLEdBQUcsQ0FBQyx3Q0FBd0MsQ0FBQyxDQUFBO29CQUNyRCxLQUFJLElBQUksQ0FBQyxHQUFDLENBQUMsRUFBRSxDQUFDLEdBQUMsTUFBTSxDQUFDLFdBQVcsQ0FBQyxNQUFNLEVBQUUsQ0FBQyxFQUFFLEVBQUUsQ0FBQzt3QkFDNUMsSUFBSSxNQUFNLENBQUMsV0FBVyxDQUFDLENBQUMsQ0FBQyxDQUFDLFFBQVEsS0FBSyxjQUFjLEVBQUUsQ0FBQzs0QkFDcEQscUJBQXFCLENBQUMsTUFBTSxDQUFDLFdBQVcsQ0FBQyxDQUFDLENBQUMsQ0FBQyxPQUFPLENBQUMsQ0FBQTt3QkFDeEQsQ0FBQzt3QkFDRCxrQkFBa0IsRUFBRSxDQUFBO29CQUN4QixDQUFDO2dCQUNMLENBQUM7Z0JBQ0Q7OzttQkFHRztZQUdQLENBQUM7UUFDTCxDQUFDO1FBQ0QsT0FBTyxLQUFLLEVBQUUsQ0FBQztZQUNYLElBQUksS0FBSyxZQUFZLEtBQUssRUFBRSxDQUFDO2dCQUN6QixPQUFPLENBQUMsR0FBRyxDQUFDLGlCQUFpQixFQUFFLEtBQUssQ0FBQyxPQUFPLENBQUMsQ0FBQztnQkFDOUMsT0FBTyxLQUFLLENBQUMsT0FBTyxDQUFDO1lBQ3pCLENBQUM7aUJBQU0sQ0FBQztnQkFDSixPQUFPLENBQUMsR0FBRyxDQUFDLG9CQUFvQixFQUFFLEtBQUssQ0FBQyxDQUFDO2dCQUN6QyxPQUFPLDhCQUE4QixDQUFDO1lBQzFDLENBQUM7UUFDTCxDQUFDO0lBQ0wsQ0FBQztDQUFBO0FBRUQsK0RBQStEO0FBQy9ELE1BQU0sZUFBZSxHQUFHLFdBQVcsQ0FBQyxPQUFPLEVBQUUsSUFBSSxDQUFDLENBQUEifQ==