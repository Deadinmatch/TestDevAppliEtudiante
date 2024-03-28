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
/* tsc --inlineSourceMap  true -outFile JS/messengerNaive.js src/libCrypto.ts src/messengerNaive.ts --target es2015 */
// To detect if we can use window.crypto.subtle
if (!window.isSecureContext)
    alert("Not secure context!");
//Index of the last read message
let lastIndexInHistory = 0;
// Message for user name
class CasUserName {
    constructor(username) {
        this.username = username;
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
// Sending messages
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
const userButtonLabel = document.getElementById("user-name");
const sendButton = document.getElementById("send-button");
const receiver = document.getElementById("receiver");
const message = document.getElementById("message");
const received_messages = document.getElementById("exchanged-messages");
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
/* Name of the user of the application... can be Alice/Bob for attacking purposes */
let globalUserName = "";
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
function setCasName() {
    return __awaiter(this, void 0, void 0, function* () {
        globalUserName = yield fetchCasName();
        // We replace the name of the user of the application as the default name
        // In the window
        userButtonLabel.textContent = globalUserName;
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
        let contentToEncrypt = JSON.stringify([agentName, message.value]);
        // we fetch the public key of B
        try {
            const kb = yield fetchKey(receiverName, true, true);
            // We encrypt
            const encryptedMessage = yield encryptWithPublicKey(kb, contentToEncrypt);
            // And send
            const sendResult = yield sendMessage(agentName, receiverName, encryptedMessage);
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
// Parsing/Recognizing a message sent to app_user
// The first element of the tuple is a boolean saying if the message was for the user
// If this boolean is true, then the second element is the name of the sender
// and the third is the content of the message
function analyseMessage(message) {
    return __awaiter(this, void 0, void 0, function* () {
        const user = globalUserName;
        try {
            const messageSender = message.sender;
            const messageContent = message.content;
            if (message.receiver !== user) {
                // If the message is not sent to the user, we do not consider it
                return [false, "", ""];
            }
            else {
                //we fetch user private key to decrypt the message
                try {
                    const privkey = yield fetchKey(user, false, true);
                    const messageInClearString = yield decryptWithPrivateKey(privkey, messageContent);
                    // The next lines contain several intentional programming errors
                    // 1) This is not the safest way to obtain an object from a JSON string!
                    const messageArrayInClear = eval(`${messageInClearString}`);
                    const messageSenderInMessage = messageArrayInClear[0];
                    const messageInClear = messageArrayInClear[1];
                    if (messageSenderInMessage == messageSender) {
                        if (messageInClear.indexOf("\\") == -1) {
                            return [true, messageSender, messageInClear];
                        }
                        else {
                            // If the string contains escaped characters like \" \n etc
                            // we remove them using eval.
                            // Using eval to build a value is *always* a bad programming practice
                            const result = `[true, messageSender, ${messageInClear}]`;
                            return eval(`${result}`);
                        }
                    }
                    else {
                        console.log("Real message sender and message sender name in the message do not coincide");
                    }
                }
                catch (e) {
                    console.log("analyseMessage: decryption failed because of " + e);
                    return [false, "", ""];
                }
            }
        }
        catch (e) {
            console.log("analyseMessage: decryption failed because of " + e);
            return [false, "", ""];
        }
    });
}
// action for receiving message 
// 1. A -> B: A,{message}Kb     
function actionOnMessageOne(fromA, messageContent) {
    const user = globalUserName;
    const textToAdd = `${fromA} -> ${user} : ${messageContent}`;
    addingReceivedMessage(textToAdd);
}
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
                // We update the index with the index of last read message from message server
                lastIndexInHistory = result.index;
                if (result.allMessages.length != 0) {
                    for (var m of result.allMessages) {
                        let [b, sender, msgContent] = yield analyseMessage(m);
                        if (b)
                            actionOnMessageOne(sender, msgContent);
                        else
                            console.log("Msg " + m + " cannot be exploited by " + user);
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
}
// Automatic refresh
const intervalRefresh = setInterval(refresh, 2000);
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoibWVzc2VuZ2VyTmFpdmUuanMiLCJzb3VyY2VSb290IjoiIiwic291cmNlcyI6WyIuLi9zcmMvbGliQ3J5cHRvLnRzIiwiLi4vc3JjL21lc3Nlbmdlck5haXZlLnRzIl0sIm5hbWVzIjpbXSwibWFwcGluZ3MiOiI7Ozs7Ozs7OztBQUFBLGlGQUFpRjtBQUVqRjs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7RUFnQ0U7QUFFRix1RkFBdUY7QUFFdkY7OztFQUdFO0FBQ0YsU0FBZSw4QkFBOEIsQ0FBQyxVQUFrQjs7UUFDNUQsSUFBSTtZQUNBLE1BQU0sY0FBYyxHQUFnQixJQUFJLENBQUMseUJBQXlCLENBQUMsVUFBVSxDQUFDLENBQUE7WUFDOUUsTUFBTSxHQUFHLEdBQWMsTUFBTSxNQUFNLENBQUMsTUFBTSxDQUFDLE1BQU0sQ0FBQyxTQUFTLENBQ3ZELE1BQU0sRUFDTixjQUFjLEVBQ2Q7Z0JBQ0ksSUFBSSxFQUFFLFVBQVU7Z0JBQ2hCLElBQUksRUFBRSxTQUFTO2FBQ2xCLEVBQ0QsSUFBSSxFQUNKLENBQUMsU0FBUyxDQUFDLENBQ2QsQ0FBQTtZQUNELE9BQU8sR0FBRyxDQUFBO1NBQ2I7UUFBQyxPQUFPLENBQUMsRUFBRTtZQUNSLElBQUksQ0FBQyxZQUFZLFlBQVksRUFBRTtnQkFBRSxPQUFPLENBQUMsR0FBRyxDQUFDLDJEQUEyRCxDQUFDLENBQUE7YUFBRTtpQkFDdEcsSUFBSSxDQUFDLFlBQVksa0JBQWtCLEVBQUU7Z0JBQUUsT0FBTyxDQUFDLEdBQUcsQ0FBQywyREFBMkQsQ0FBQyxDQUFBO2FBQUU7aUJBQ2pIO2dCQUFFLE9BQU8sQ0FBQyxHQUFHLENBQUMsQ0FBQyxDQUFDLENBQUE7YUFBRTtZQUN2QixNQUFNLENBQUMsQ0FBQTtTQUNWO0lBQ0wsQ0FBQztDQUFBO0FBRUQ7OztFQUdFO0FBQ0YsU0FBZSw2QkFBNkIsQ0FBQyxVQUFrQjs7UUFDM0QsSUFBSTtZQUNBLE1BQU0sY0FBYyxHQUFnQixJQUFJLENBQUMseUJBQXlCLENBQUMsVUFB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