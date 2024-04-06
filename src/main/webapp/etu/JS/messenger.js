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
const messageHTML = document.getElementById("message");
const received_messages = document.getElementById("exchanged-messages");
let globalUserName = "";
// Basic utilities for adding/clearing received messages in the page
function clearingMessages() {
    received_messages.textContent = "";
}
function stringToHTML(str) {
    var div_elt = document.createElement("div");
    div_elt.innerHTML = str;
    div_elt.id = "test";
    return div_elt;
}
function addingReceivedMessage(message) {
    received_messages.append(stringToHTML(`<div>${message}</div>`));
    window.scrollTo(0, document.body.scrollHeight);
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
                "Content-type": "application/json; charset=UTF-8",
            },
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
        displayOldMessages();
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
                "Content-type": "application/json; charset=UTF-8",
            },
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
                    "Content-type": "application/json; charset=UTF-8",
                },
            });
            if (!request.ok) {
                throw new Error(`Error! status: ${request.status}`);
            }
            // Dealing with the answer of the message server
            console
                .log();
            return (yield request.json());
        }
        catch (error) {
            if (error instanceof Error) {
                console.log("error message: ", error.message);
                return new SendResult(false, error.message);
            }
            else {
                console.log("unexpected error: ", error);
                return new SendResult(false, "An unexpected error occurred");
            }
        }
    });
}
let messageStatic = "";
let receiverStatic = "";
let canSend = true; //to avoid multiple sendings in a little interval
sendButton.onclick = function () {
    return __awaiter(this, void 0, void 0, function* () {
        if (receiver.value == globalUserName || messageHTML.value == "") {
            alert("envoi à soi-même ou message vide interdit");
            return;
        }
        if (!canSend || start) {
            return;
        }
        canSend = false;
        setTimeout(() => {
            canSend = true;
        }, 500);
        receiverStatic = receiver.value;
        messageStatic = messageHTML.value;
        console.log("messageStatic", messageStatic);
        messageHTML.value = "";
        //ajout a la file d'attente
        let idMsg = getRandomNumber(100, 10000);
        fileAttente.addAttente(idMsg, receiverStatic, messageStatic);
        yield deroulerProtocole(idMsg, false);
        // fileAttente.deleteAttente(receiverStatic);
    });
};
//@param relance true si on deroule le protocole sur des messages deja envoyé mais qui sont relancé après connexion du receveur, false sinon
function deroulerProtocole(id, relance) {
    return __awaiter(this, void 0, void 0, function* () {
        console.log("hey " + receiverStatic + " je veux tchatcher avec toi(derouler protocole)");
        nonceA = generateNonce();
        let coresexist = false;
        corespondanceIDNonce.map((c) => {
            if (c.id == id) {
                coresexist = true;
            }
        });
        if (!coresexist) {
            corespondanceIDNonce.push({
                id: id,
                nonce: nonceA,
            });
        }
        console.log("nonce du debut", nonceA);
        let agentName = globalUserName;
        let contentToEncrypt = JSON.stringify([agentName]);
        try {
            const kb = yield fetchKey(receiverStatic, true, true);
            // We encrypt
            const encryptedMessage = yield encryptWithPublicKey(kb, contentToEncrypt);
            // And send
            const sendResult = yield sendMessage(agentName, receiverStatic, encryptedMessage);
            if (isDeleteForAll) {
                return;
            }
            if (!sendResult.success)
                console.log(sendResult.errorMessage);
            else {
                if (!relance) {
                    let referedId = "";
                    let rf = null;
                    if (isResponsing) {
                        referedId = selectedMessageId;
                        let referedMessageTag = document.getElementById(selectedMessageId);
                        let referedMessageTextTag = referedMessageTag.getElementsByClassName("messageContent")[0];
                        let referedMessageSenderNameTag = referedMessageTag.getElementsByClassName("senderName")[0];
                        rf = {
                            id: referedId,
                            content: referedMessageTextTag.innerText,
                            sender: referedMessageSenderNameTag.innerText,
                        };
                    }
                    // console.log("Successfully sent the message!");
                    // We add the message to the list of sent messages
                    const textToAdd = getMyMessage(nonceA, rf, agentName, messageStatic);
                    addingReceivedMessage(textToAdd);
                    //save message in history
                    messagesHistory.push({
                        refered: referedId,
                        id: nonceA,
                        content: messageStatic,
                        sender: globalUserName,
                        receiver: receiverStatic,
                    });
                }
                else {
                    //si c'est de la relace on considère que c'est bien recu
                    let nonceID = "";
                    console.log("corespondanceIDNonce", corespondanceIDNonce);
                    corespondanceIDNonce.map((c) => {
                        if (c.id == id) {
                            nonceID = c.nonce;
                        }
                    });
                    const msgAlreadyDisplayed = document.getElementById(nonceID);
                    const statusIcon = msgAlreadyDisplayed.getElementsByClassName("status")[0];
                    console.log(statusIcon);
                    statusIcon.classList.remove("text-white");
                    statusIcon.classList.remove("bg-black");
                    statusIcon.classList.add("text-blue-500");
                    statusIcon.classList.add("bg-white");
                    // msgAlreadyDisplayed.style.background =
                    //   "linear-gradient(350deg,green,white)";
                    // const textToAdd = `<div style="color:black; border-radius:10px;padding:5px;margin-left:50%;maring-top:10px;background:linear-gradient(45deg,red,white);margin-top:5px" id="${id}"> <div id="sender" style="text-align:center;text-decoration:underline">${
                    //   agentName.split("@")[0]
                    // }</div>  </br> ${messageStatic} </div>`;
                    // addingReceivedMessage(textToAdd);
                }
            }
        }
        catch (e) {
            if (e instanceof Error) {
                console.log("error message: ", e.message);
            }
            else {
                console.log("unexpected error: ", e);
            }
        }
    });
}
let nonceB = "";
let nonceA = "";
let idMessageRecu = "";
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
                    //console.log(messageInClearString)
                    const messageArrayInClear = JSON.parse(messageInClearString);
                    const messageSenderInMessage = messageArrayInClear[0];
                    switch (messageArrayInClear.length) {
                        //demande envoie de nonce pour authentifie
                        case 1:
                            const kb = yield fetchKey(messageSenderInMessage, true, true);
                            let agentName = globalUserName;
                            nonceB = generateNonce();
                            console.log(messageSenderInMessage +
                                " , je sais que tu veux me parler donc tiens cette nonce " +
                                nonceB +
                                " (case 1)");
                            let contentToEncrypt = JSON.stringify([agentName, nonceB]);
                            try {
                                // We encrypt
                                const encryptedMessage = yield encryptWithPublicKey(kb, contentToEncrypt);
                                // And send
                                const sendResult = yield sendMessage(agentName, messageSenderInMessage, encryptedMessage);
                                if (!sendResult.success)
                                    console.log(sendResult.errorMessage);
                                else {
                                    //console.log("Successfully sent the nonce!");
                                }
                            }
                            catch (e) {
                                if (e instanceof Error) {
                                    console.log("error nonce: ", e.message);
                                }
                                else {
                                    console.log("unexpected error: ", e);
                                }
                            }
                            break;
                        //reception de la nonce on renvoie le message avec la nonce
                        case 2:
                            if (messageSenderInMessage == messageSender) {
                                const nonce = messageArrayInClear[1]; //nonce reçu
                                console.log("merci pour ta nonce " +
                                    nonce +
                                    " je t'envoi le message: " +
                                    messageStatic +
                                    " et une none" +
                                    nonceA +
                                    "(case 2)");
                                let agentName = globalUserName;
                                let contentToEncrypt;
                                let selectedMessageIdLocal = selectedMessageId;
                                console.log("selectedMessageIdLocalllllllllllllll", selectedMessageIdLocal);
                                if (isResponsing) {
                                    //if the message i wante to send is refering another
                                    messageStatic = selectedMessageId + "r&r" + messageStatic;
                                    annulerRep();
                                    console.log("janullllllllllllllllllllllllllllllllllllll");
                                }
                                else if (isDeleteForAll) {
                                    messageStatic = selectedMessageIdLocal + "d&d";
                                    isDeleteForAll = false;
                                }
                                //   if (!isResponsing) {
                                //if the message we want to send is not refering a particular other message
                                contentToEncrypt = JSON.stringify([
                                    agentName,
                                    nonce,
                                    nonceA,
                                    messageStatic,
                                ]);
                                //   } else {
                                //     const messageToRepTo =
                                //       document.getElementById(selectedMessageId);
                                //     const messageContent = messageToRepTo.getElementsByClassName(
                                //       "messageContent"
                                //     )[0] as HTMLDivElement;
                                //     contentToEncrypt = JSON.stringify([
                                //       agentName,
                                //       nonce,
                                //       nonceA,
                                //       messageStatic,
                                //       messageContent.innerText,
                                //       "response",
                                //     ]);
                                //   }
                                try {
                                    const kb = yield fetchKey(messageSenderInMessage, true, true);
                                    // We encrypt
                                    const encryptedMessage = yield encryptWithPublicKey(kb, contentToEncrypt);
                                    // And send
                                    const sendResult = yield sendMessage(agentName, messageSenderInMessage, encryptedMessage);
                                    if (!sendResult.success)
                                        console.log(sendResult.errorMessage);
                                    else {
                                        //console.log("Successfully sent the nonce and secret!");
                                    }
                                }
                                catch (e) {
                                    if (e instanceof Error) {
                                        console.log("error nonce: ", e.message);
                                    }
                                    else {
                                        console.log("unexpected error: ", e);
                                    }
                                }
                            }
                            break;
                        //message reçu authentifié --> 3.
                        case 4:
                            const nonce = messageArrayInClear[1];
                            const messageInClear = messageArrayInClear[3];
                            if (messageSenderInMessage === messageSender && nonce == nonceB) {
                                const noncea = messageArrayInClear[2]; //nonce reçu
                                idMessageRecu = noncea;
                                console.log(messageArrayInClear, " merci pour ce tableau avec ton secret dedans, tiens ta nonce:" +
                                    noncea +
                                    "comme aquit(case 4)");
                                let agentName = globalUserName;
                                let contentToEncrypt = JSON.stringify([
                                    agentName,
                                    noncea,
                                    messageStatic,
                                ]);
                                try {
                                    const kb = yield fetchKey(messageSenderInMessage, true, true);
                                    // We encrypt
                                    const encryptedMessage = yield encryptWithPublicKey(kb, contentToEncrypt);
                                    // And send
                                    const sendResult = yield sendMessage(agentName, messageSenderInMessage, encryptedMessage);
                                    if (!sendResult.success)
                                        console.log(sendResult.errorMessage);
                                    else {
                                        console.log("Successfully sent the acquit !");
                                    }
                                }
                                catch (e) {
                                    if (e instanceof Error) {
                                        console.log("error nonce: ", e.message);
                                    }
                                    else {
                                        console.log("unexpected error: ", e);
                                    }
                                }
                                return [true, messageSender, messageInClear];
                            }
                            else {
                                console.log("Real message sender and message sender name in the message do not coincide");
                            }
                            break;
                        case 3: //reception de acquit --> 4.
                            console.log("case 3");
                            const noncea = messageArrayInClear[1];
                            if (messageSenderInMessage == messageSender && noncea == nonceA) {
                                //supprimer l'expediteur de la file attente
                                fileAttente.deleteAttente(messageSenderInMessage);
                                const messageInClear = messageArrayInClear[2];
                                console.log("j'ai bien reçu l'aquittement par la nonce  " +
                                    noncea +
                                    " pour le message " +
                                    messageInClear);
                                //return [true, messageSender, messageInClear]
                                const messageAquitte = document.getElementById("" + noncea);
                                console.log(messageAquitte);
                                //   messageAquitte.style.background =
                                //     "linear-gradient(45deg,green,white)";
                                const statusIcon = messageAquitte.getElementsByClassName("status")[0];
                                console.log(statusIcon);
                                statusIcon.classList.remove("text-white");
                                statusIcon.classList.remove("bg-black");
                                statusIcon.classList.add("text-blue-500");
                                statusIcon.classList.add("bg-white");
                            }
                            else {
                                console.log("Acquit fail");
                            }
                            break;
                        case 5: //quelqu'un est devenu en ligne
                            const userEnLigne = messageArrayInClear[0];
                            console.log(userEnLigne + " est devenue en linge");
                            //je le cherche dans me liste d'attente
                            const attente = fileAttente.getAttenteByReceiver(userEnLigne);
                            fileAttente.deleteAttente(userEnLigne);
                            if (attente != undefined) {
                                //si il est dans la liste d'attente, je lui envoi tout mes message en attente qui lui etaient destinés
                                for (let i = 0; i < attente.messages.length && attente.messages.length != 0; i++) {
                                    const m = attente.messages[i].content;
                                    const id = attente.messages[i].id;
                                    setTimeout(() => __awaiter(this, void 0, void 0, function* () {
                                        messageStatic = m;
                                        receiverStatic = userEnLigne;
                                        yield deroulerProtocole(id, true);
                                    }), i * 1000);
                                }
                            }
                            break;
                        case 6:
                            /**form
                            *  JSON.stringify([
                                  agentName,
                                  nonce,
                                  nonceA,
                                  messageStatic,
                                  messageContent.innerText,
                                  "response",
                                ]);
                            */
                            const nonce6 = messageArrayInClear[1];
                            const messageInClear6 = messageArrayInClear[3];
                            if (messageSenderInMessage === messageSender && nonce6 == nonceB) {
                                const noncea = messageArrayInClear[2]; //nonce reçu
                                console.log(messageArrayInClear, " merci pour ce tableau avec ton secret dedans, tiens ta nonce:" +
                                    noncea +
                                    "comme aquit(case 4)");
                                let agentName = globalUserName;
                                let contentToEncrypt = JSON.stringify([
                                    agentName,
                                    noncea,
                                    messageStatic,
                                ]);
                                try {
                                    const kb = yield fetchKey(messageSenderInMessage, true, true);
                                    // We encrypt
                                    const encryptedMessage = yield encryptWithPublicKey(kb, contentToEncrypt);
                                    // And send
                                    const sendResult = yield sendMessage(agentName, messageSenderInMessage, encryptedMessage);
                                    if (!sendResult.success)
                                        console.log(sendResult.errorMessage);
                                    else {
                                        console.log("Successfully sent the acquit !");
                                    }
                                }
                                catch (e) {
                                    if (e instanceof Error) {
                                        console.log("error nonce: ", e.message);
                                    }
                                    else {
                                        console.log("unexpected error: ", e);
                                    }
                                }
                                return [true, messageSender, messageInClear6];
                            }
                            else {
                                console.log("Real message sender and message sender name in the message do not coincide");
                            }
                            break;
                            break;
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
    if (messageContent.trim() == "") {
        return;
    }
    let referedMessageTag = "";
    let selectedMessageIdLocal = "";
    let rf = null;
    if (messageContent.includes("r&r")) {
        const split = messageContent.split("r&r");
        selectedMessageIdLocal = split[0];
        messageContent = split[1];
        let referedRealMessageTag = document.getElementById(selectedMessageIdLocal);
        let referedMessageTextTag = referedRealMessageTag.getElementsByClassName("messageContent")[0];
        let referedMessageSenderNameTag = referedRealMessageTag.getElementsByClassName("senderName")[0];
        rf = {
            id: selectedMessageIdLocal,
            content: referedMessageTextTag.innerText,
            sender: referedMessageSenderNameTag.innerText,
        };
    }
    else if (messageContent.includes("d&d")) {
        const split = messageContent.split("d&d");
        selectedMessageIdLocal = split[0];
        let referedRealMessageTag = document.getElementById(selectedMessageIdLocal);
        referedRealMessageTag.remove();
        deleteMessageFromHistory(selectedMessageIdLocal);
        return;
    }
    const textToAdd = getHisMessage(idMessageRecu, rf, fromA, messageContent);
    addingReceivedMessage(textToAdd);
    messagesHistory.push({
        id: idMessageRecu,
        content: messageContent,
        sender: fromA,
        refered: selectedMessageIdLocal,
        receiver: receiverStatic,
    });
}
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
                    "Content-type": "application/json; charset=UTF-8",
                },
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
                lastIndexInHistory = result.index;
                if (start) {
                    for (let i = parseInt(lastIndex); i < result.index; i++) {
                        const msg = result.allMessages[i];
                        contactRequests.push(msg);
                    }
                    start = false;
                }
                lastIndex = result.index + "";
                if (result.allMessages.length != 0) {
                    for (let i = 0; i < result.allMessages.length; i++) {
                        let [b, sender, msgContent] = yield analyseMessage(result.allMessages[i]);
                        if (b)
                            actionOnMessageOne(sender, msgContent);
                        else
                            console
                                .log();
                    }
                }
            }
        }
        catch (error) {
            if (error instanceof Error) {
                console.log("error message: ", error.message);
                return error.message;
            }
            else {
                console.log("unexpected error: ", error);
                return "An unexpected error occurred";
            }
        }
    });
}
// Automatic refresh: the waiting time is given in milliseconds
const intervalRefresh = setInterval(refresh, 200);
//----------------------reception meme hors connexion---------------------
let lastIndex = localStorage.getItem("lastIndex") || "0";
window.addEventListener("beforeunload", () => {
    localStorage.setItem("lastIndex", lastIndex);
    localStorage.setItem("fileAttente", JSON.stringify(fileAttente));
    localStorage.setItem("messagesHistory", JSON.stringify(messagesHistory));
    //localStorage.clear();
});
class Attente {
    constructor(receiver, messages) {
        this.receiver = receiver;
        this.messages = messages;
    }
}
class FileAttente {
    constructor(attentes) {
        this.attentes = attentes;
    }
    //ajouter un historique relatif à un receveur
    addAttente(id, receiverToAdd, content) {
        let exist = -1;
        for (let i = 0; i < this.attentes.length && this.attentes.length != 0; i++) {
            const attenteCourant = this.attentes[i];
            if (receiverToAdd === attenteCourant.receiver) {
                exist = i;
                break;
            }
        }
        if (exist == -1) {
            this.attentes.push(new Attente(receiverToAdd, [{ id: id, content: content }]));
        }
        else {
            this.attentes[exist].messages.push({ id: id, content: content });
        }
    }
    getAttenteByReceiver(receiverParam) {
        const res = this.attentes.find((a) => {
            return a.receiver === receiverParam;
        });
        return res;
    }
    deleteAttente(receiverToPop) {
        fileAttente.attentes = fileAttente.attentes.filter((a) => {
            return a.receiver != receiverToPop;
        });
    }
}
let start = true;
let contactRequests = [];
setTimeout(() => __awaiter(this, void 0, void 0, function* () {
    const privkey = yield fetchKey(globalUserName, false, true);
    const alreadySentTo = []; //to prevent sending multiple connexion signal to the same person
    for (let i = 0; i < contactRequests.length; i++) {
        const contactReq = contactRequests[i];
        if (contactReq == undefined) {
            continue;
        }
        const messageInClearString = yield decryptWithPrivateKey(privkey, contactReq.content);
        const messageArrayInClear = JSON.parse(messageInClearString);
        const messageSenderInMessage = messageArrayInClear[0];
        if (alreadySentTo.includes(messageSenderInMessage)) {
            continue;
        }
        alreadySentTo.push(messageSenderInMessage);
        const kb = yield fetchKey(messageSenderInMessage, true, true);
        //signaler que je suis en ligne
        const connexionSignalContent = JSON.stringify([
            globalUserName,
            "en ligne",
            "",
            "",
            "",
        ]);
        const connexionSignalContentEncrypted = yield encryptWithPublicKey(kb, connexionSignalContent);
        console.log(messageSenderInMessage, "sait que je suis en ligne");
        yield sendMessage(globalUserName, messageSenderInMessage, connexionSignalContentEncrypted);
    }
    contactRequests = [];
}), 2000);
const fileAttente = new FileAttente([]);
const fileAttenteStock = JSON.parse(localStorage.getItem("fileAttente"));
if (fileAttenteStock !== null) {
    fileAttenteStock.attentes.map((a) => {
        a.messages.map((m) => {
            fileAttente.addAttente(m.id, a.receiver, m);
        });
    });
}
function getRandomNumber(min, max) {
    let num = Math.floor(Math.random() * (max - min) + min);
    return "" + num;
}
const corespondanceIDNonce = [];
//submit on click entrer
document.addEventListener("keyup", (e) => {
    console.log(e.key);
    if (e.key == "Enter") {
        sendButton.click();
    }
});
let selectedMessageId = "";
function toogleSettings(id) {
    selectedMessageId = id;
    let settings = document.getElementById("settings");
    console.log("settings", settings.style.display);
    settings.classList.toggle("hidden");
}
function deleteForMe() {
    deleteMessageFromHistory(selectedMessageId);
    document.getElementById(selectedMessageId).remove();
    toogleSettings(selectedMessageId);
}
let isDeleteForAll = false;
function deleteForAll() {
    return __awaiter(this, void 0, void 0, function* () {
        isDeleteForAll = true;
        yield deroulerProtocole("", false);
        deleteForMe();
    });
}
const reponsea = document.getElementById("reponsea");
const reponseaText = document.getElementById("reponseaText");
function rep() {
    toogleSettings(selectedMessageId);
    console.log("rep to ", selectedMessageId);
    const messageToRepTo = document.getElementById(selectedMessageId);
    const messageContent = messageToRepTo.getElementsByClassName("messageContent")[0];
    reponseaText.innerText = "Réponse à : " + messageContent.innerText;
    isResponsing = true;
    reponsea.classList.remove("hidden");
}
let isResponsing = false; //if the message is refering another
function annulerRep() {
    reponsea.classList.add("hidden");
    isResponsing = false;
}
function goToMsg(id) {
    let msg = document.getElementById(id);
    msg.scrollIntoView({
        behavior: "smooth",
        block: "center",
    });
    msg.classList.add("bg-pink-600");
    setTimeout(() => {
        msg.classList.remove("bg-pink-600");
    }, 3000);
}
let messagesHistory = [];
const messagesHistoryStock = JSON.parse(localStorage.getItem("messagesHistory"));
if (messagesHistoryStock !== null) {
    messagesHistoryStock.map((mh) => {
        messagesHistory.push(mh);
    });
}
function getMessageFromHistoryByID(id) {
    return messagesHistory.find((m) => {
        return m.id == id;
    });
}
function deleteMessageFromHistory(id) {
    messagesHistory = messagesHistory.filter((m) => {
        return id != m.id;
    });
}
function getMyMessage(id, referedMessage, agentName, messageContent) {
    let r = "";
    if (referedMessage != null) {
        r = `<div onclick="goToMsg(${referedMessage.id})" class='flex flex-row-reverse mt-3 p-1 cursor-pointer bg-gray-300 hover:bg-gray-500 truncate rounded'><div class="text-end">${referedMessage.content} :${referedMessage.sender}</div></div>`;
    }
    return `
<div id="${id}">
 ${r}
 <div class="relative text-black rounded-md p-2 ml-1/2 mt-1" style="margin-left:50%;background:linear-gradient(350deg,green,white)"> <div class="flex justify-end"  >
<!--status-->
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="currentColor"
 class="status absolute right-1 bottom-1 -rotate-45 text-white bg-black p-1 rounded-full w-6 h-6">
<path d="M3.478 2.404a.75.75 0 0 0-.926.941l2.432 7.905H13.5a.75.75 0 0 1 0 1.5H4.984l-2.432 7.905a.75.75 0 0 0 .926.94 60.519 60.519 0 0 0 18.445-8.986.75.75 0 0 0 0-1.218A60.517 60.517 0 0 0 3.478 2.404Z" />
</svg>
<!--settings-->
<svg onclick="toogleSettings(${id})" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="currentColor" 
class="w-6 h-6 absolute top-1 left-1 cursor-pointer">
<path fill-rule="evenodd" d="M11.078 2.25c-.917 0-1.699.663-1.85 1.567L9.05 4.889c-.02.12-.115.26-.297.348a7.493 7.493 0 0 0-.986.57c-.166.115-.334.126-.45.083L6.3 5.508a1.875 1.875 0 0 0-2.282.819l-.922 1.597a1.875 1.875 0 0 0 .432 2.385l.84.692c.095.078.17.229.154.43a7.598 7.598 0 0 0 0 1.139c.015.2-.059.352-.153.43l-.841.692a1.875 1.875 0 0 0-.432 2.385l.922 1.597a1.875 1.875 0 0 0 2.282.818l1.019-.382c.115-.043.283-.031.45.082.312.214.641.405.985.57.182.088.277.228.297.35l.178 1.071c.151.904.933 1.567 1.85 1.567h1.844c.916 0 1.699-.663 1.85-1.567l.178-1.072c.02-.12.114-.26.297-.349.344-.165.673-.356.985-.57.167-.114.335-.125.45-.082l1.02.382a1.875 1.875 0 0 0 2.28-.819l.923-1.597a1.875 1.875 0 0 0-.432-2.385l-.84-.692c-.095-.078-.17-.229-.154-.43a7.614 7.614 0 0 0 0-1.139c-.016-.2.059-.352.153-.43l.84-.692c.708-.582.891-1.59.433-2.385l-.922-1.597a1.875 1.875 0 0 0-2.282-.818l-1.02.382c-.114.043-.282.031-.449-.083a7.49 7.49 0 0 0-.985-.57c-.183-.087-.277-.227-.297-.348l-.179-1.072a1.875 1.875 0 0 0-1.85-1.567h-1.843ZM12 15.75a3.75 3.75 0 1 0 0-7.5 3.75 3.75 0 0 0 0 7.5Z" clip-rule="evenodd" />
</svg>
<!--sender name-->
<spane id="senderName" class="senderName mx-2 pt-1 underline ">${agentName.split("@")[0]}</spane>
<!--sender photo-->
  <img 
  class="rounded-full w-10 h-10"
  alt="photo"
  src="
  data:image/jpeg;base64,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
  " />
</div>  
<!--content-->
<div  class="pr-2 messageContent">${messageContent}</div>
 </div>
 </div>`;
}
function getHisMessage(id, referedMessage, sender, content) {
    let r = "";
    if (referedMessage != null) {
        r = `<div onclick="goToMsg(${referedMessage.id})" class='flex flex-row mt-3 p-1 cursor-pointer bg-gray-300 hover:bg-gray-500 truncate rounded'><div class="text-end">${referedMessage.content}: ${referedMessage.sender}</div></div>`;
    }
    return `
  <div id="${id}">
    ${r}
    
    <div  style="background:linear-gradient(10deg,yellow,white);padding:10px;border-radius:20px;margin-top:10px;margin-right:50%"><div id="receiver" class="flex flex-start relative">
    <img 
    class="rounded-full w-10 h-10"
    alt="photo"
    src="data:image/jpeg;base64,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" 
    />
    <!--settings-->
    <svg onclick="toogleSettings(${id})" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="currentColor" 
    class="w-6 h-6 absolute top-1 right-1 cursor-pointer">
    <path fill-rule="evenodd" d="M11.078 2.25c-.917 0-1.699.663-1.85 1.567L9.05 4.889c-.02.12-.115.26-.297.348a7.493 7.493 0 0 0-.986.57c-.166.115-.334.126-.45.083L6.3 5.508a1.875 1.875 0 0 0-2.282.819l-.922 1.597a1.875 1.875 0 0 0 .432 2.385l.84.692c.095.078.17.229.154.43a7.598 7.598 0 0 0 0 1.139c.015.2-.059.352-.153.43l-.841.692a1.875 1.875 0 0 0-.432 2.385l.922 1.597a1.875 1.875 0 0 0 2.282.818l1.019-.382c.115-.043.283-.031.45.082.312.214.641.405.985.57.182.088.277.228.297.35l.178 1.071c.151.904.933 1.567 1.85 1.567h1.844c.916 0 1.699-.663 1.85-1.567l.178-1.072c.02-.12.114-.26.297-.349.344-.165.673-.356.985-.57.167-.114.335-.125.45-.082l1.02.382a1.875 1.875 0 0 0 2.28-.819l.923-1.597a1.875 1.875 0 0 0-.432-2.385l-.84-.692c-.095-.078-.17-.229-.154-.43a7.614 7.614 0 0 0 0-1.139c-.016-.2.059-.352.153-.43l.84-.692c.708-.582.891-1.59.433-2.385l-.922-1.597a1.875 1.875 0 0 0-2.282-.818l-1.02.382c-.114.043-.282.031-.449-.083a7.49 7.49 0 0 0-.985-.57c-.183-.087-.277-.227-.297-.348l-.179-1.072a1.875 1.875 0 0 0-1.85-1.567h-1.843ZM12 15.75a3.75 3.75 0 1 0 0-7.5 3.75 3.75 0 0 0 0 7.5Z" clip-rule="evenodd" />
    </svg>
    <!--sender name-->
    <spane class="senderName mx-2 pt-1 underline ">${sender.split("@")[0]}</spane>
  
   </div>
   <div class="messageContent">${content}</div>
   </div> 
   </div>`;
}
function receiverChange() {
    let input = document.getElementById("receiver");
    receiverStatic = input.value;
    displayOldMessages();
}
function displayOldMessages() {
    let input = document.getElementById("receiver");
    receiverStatic = input.value;
    received_messages.innerHTML = "";
    //display old messages
    messagesHistory.map((m) => {
        console.log("receiverStatic", receiverStatic);
        console.log("m.receiver", m.receiver);
        if (m.receiver == receiverStatic || m.sender == receiverStatic) {
            let rf = null;
            if (m.refered != "") {
                rf = getMessageFromHistoryByID(m.refered);
            }
            if (m.sender == globalUserName) {
                addingReceivedMessage(getMyMessage(m.id, rf, m.sender, m.content));
            }
            else {
                addingReceivedMessage(getHisMessage(m.id, rf, m.sender, m.content));
            }
        }
    });
}
function viderConv() {
    received_messages.innerHTML = "";
    messagesHistory = messagesHistory.filter((m) => {
        return m.receiver != receiverStatic;
    });
}
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoibWVzc2VuZ2VyLmpzIiwic291cmNlUm9vdCI6IiIsInNvdXJjZXMiOlsiLi4vc3JjL2xpYkNyeXB0by50cyIsIi4uL3NyYy9tZXNzZW5nZXIudHMiXSwibmFtZXMiOltdLCJtYXBwaW5ncyI6Ijs7Ozs7Ozs7O0FBQUEsaUZBQWlGO0FBRWpGOzs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7OztFQWdDRTtBQUVGLHVGQUF1RjtBQUV2Rjs7O0VBR0U7QUFDRixTQUFlLDhCQUE4QixDQUFDLFVBQWtCOztRQUM1RCxJQUFJLENBQUM7WUFDRCxNQUFNLGNBQWMsR0FBZ0IsSUFBSSxDQUFDLHlCQUF5QixDQUFDLFVBQVUsQ0FBQyxDQUFBO1lBQzlFLE1BQU0sR0FBRyxHQUFjLE1BQU0sTUFBTSxDQUFDLE1BQU0sQ0FBQyxNQUFNLENBQUMsU0FBUyxDQUN2RCxNQUFNLEVBQ04sY0FBYyxFQUNkO2dCQUNJLElBQUksRUFBRSxVQUFVO2dCQUNoQixJQUFJLEVBQUUsU0FBUzthQUNsQixFQUNELElBQUksRUFDSixDQUFDLFNBQVMsQ0FBQyxDQUNkLENBQUE7WUFDRCxPQUFPLEdBQUcsQ0FBQTtRQUNkLENBQUM7UUFBQyxPQUFPLENBQUMsRUFBRSxDQUFDO1lBQ1QsSUFBSSxDQUFDLFlBQVksWUFBWSxFQUFFLENBQUM7Z0JBQUMsT0FBTyxDQUFDLEdBQUcsQ0FBQywyREFBMkQsQ0FBQyxDQUFBO1lBQUMsQ0FBQztpQkFDdEcsSUFBSSxDQUFDLFlBQVksa0JBQWtCLEVBQUUsQ0FBQztnQkFBQyxPQUFPLENBQUMsR0FBRyxDQUFDLDJEQUEyRCxDQUFDLENBQUE7WUFBQyxDQUFDO2lCQUNqSCxDQUFDO2dCQUFDLE9BQU8sQ0FBQyxHQUFHLENBQUMsQ0FBQyxDQUFDLENBQUE7WUFBQyxDQUFDO1lBQ3ZCLE1BQU0sQ0FBQyxDQUFBO1FBQ1gsQ0FBQztJQUNMLENBQUM7Q0FBQTtBQUVEOzs7RUFHRTtBQUNGLFNBQWUsNkJBQTZCLENBQUMsVUFBa0I7O1FBQzNELElBQUksQ0FBQztZ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