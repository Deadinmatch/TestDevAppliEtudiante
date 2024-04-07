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
        if (globalUserName == "bob@univ-rennes.fr") {
            const input = document.getElementById("receiver");
            input.value = "alice@univ-rennes.fr";
        }
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
        if (messageHTML.value.includes("d&d") || messageHTML.value.includes("r&r")) {
            alert("r&r et d&d sont des mots résérvés");
            return;
        }
        if (!canSend || start) {
            return;
        }
        canSend = false;
        setTimeout(() => {
            canSend = true;
        }, 500);
        annulerRep();
        receiverStatic = receiver.value;
        messageStatic = messageHTML.value;
        messageHTML.value = "";
        //ajout a la file d'attente
        let idMsg = getRandomNumber(100, 10000);
        fileAttente.addAttente(idMsg, receiverStatic, messageStatic);
        yield deroulerProtocole(idMsg, false);
    });
};
//@param relance true si on deroule le protocole sur des messages deja envoyé mais qui sont relancé après connexion du receveur, false sinon
function deroulerProtocole(id, relance) {
    return __awaiter(this, void 0, void 0, function* () {
        console.log("hey " + receiverStatic + " je veux tchatcher avec toi(derouler protocole)");
        nonceA = generateNonce();
        addCores(id, nonceA);
        console.log("nonce du debut", nonceA);
        console.log("id", id);
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
                    let rf = null;
                    console.log("isResponsing", isResponsing);
                    if (messageStatic.includes("r&r")) {
                        isResponsing = true;
                        messageStatic = messageStatic.split("r&r")[1];
                    }
                    if (isResponsing) {
                        let referedMessageTag = document.getElementById(selectedMessageId);
                        let referedMessageTextTag = referedMessageTag.getElementsByClassName("messageContent")[0];
                        let referedMessageSenderNameTag = referedMessageTag.getElementsByClassName("senderName")[0];
                        rf = {
                            id: selectedMessageId,
                            content: referedMessageTextTag.innerText,
                            sender: referedMessageSenderNameTag.innerText,
                        };
                    }
                    // console.log("Successfully sent the message!");
                    // We add the message to the list of sent messages
                    const textToAdd = getMyMessage({
                        id: nonceA,
                        rf: rf,
                        sender: agentName,
                        content: messageStatic,
                        ak: false,
                        date: getDateFormat(),
                    });
                    addingReceivedMessage(textToAdd);
                    //save message in history
                    messagesHistory.push({
                        refered: selectedMessageId,
                        id: nonceA,
                        content: messageStatic,
                        sender: globalUserName,
                        receiver: receiverStatic,
                        ak: false,
                        date: getDateFormat(),
                    });
                }
                else {
                    //si c'est de la relace on considère que c'est bien recu
                    let nonceID = getCoresNonceById(id);
                    console.log("relance nonceID ", nonceID);
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
                                if (isResponsing) {
                                    //if the message i wante to send is refering another
                                    messageStatic = selectedMessageId + "r&r" + messageStatic;
                                    isResponsing = false;
                                }
                                else if (isDeleteForAll) {
                                    messageStatic = selectedMessageIdLocal + "d&d";
                                    isDeleteForAll = false;
                                }
                                console.log("messageStatic case 2", messageStatic);
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
                            console.log("messageInClear case 4", messageInClear);
                            if (messageSenderInMessage === messageSender && nonce == nonceB) {
                                fileAttente.deleteAttente(messageSenderInMessage);
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
                            // //marquer le message dans messageshistory comme aquité
                            // messagesHistory = messagesHistory.map((m) => {
                            //   console.log("noncea", noncea);
                            //   console.log("m.id", m.id);
                            //   console.log("m.nonceDebut", m.nonceDebut);
                            //   if (m.nonceDebut == noncea) {
                            //     m.ak = true;
                            //   }
                            //   return m;
                            // });
                            //supprimer l'expediteur de la file attente
                            if (messageSenderInMessage == messageSender && noncea == nonceA) {
                                const messageInClear = messageArrayInClear[2];
                                console.log("j'ai bien reçu l'aquittement par la nonce  " +
                                    noncea +
                                    " pour le message " +
                                    messageInClear);
                                //return [true, messageSender, messageInClear]
                                const messageAquitte = document.getElementById("" + noncea);
                                console.log("case 3 noncea", noncea);
                                //   messageAquitte.style.background =
                                //     "linear-gradient(45deg,green,white)";
                                const statusIcon = messageAquitte.getElementsByClassName("status")[0];
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
                            console.log("vider attent", userEnLigne);
                            console.log(userEnLigne + " est devenue en linge");
                            //je le cherche dans me liste d'attente
                            const attente = fileAttente.getAttenteByReceiver(userEnLigne);
                            fileAttente.deleteAttente(userEnLigne);
                            if (attente != undefined) {
                                //si il est dans la liste d'attente, je lui envoi tout mes message en attente qui lui etaient destinés
                                for (let i = 0; i < attente.messages.length && attente.messages.length != 0; i++) {
                                    setTimeout(() => __awaiter(this, void 0, void 0, function* () {
                                        let r = isResponsing;
                                        let d = isDeleteForAll;
                                        let m = attente.messages[i].content;
                                        if (m != undefined && m.includes("r&r")) {
                                            const split = m.split("r&r");
                                            m = split[1];
                                            isResponsing = true;
                                            selectedMessageId = split[0];
                                        }
                                        else if (m != undefined && m.includes("d&d")) {
                                            selectedMessageId = m.split("d&d")[0];
                                            isDeleteForAll = true;
                                        }
                                        const id = attente.messages[i].id;
                                        const nonceDebut = attente.messages[i].nonceDebut;
                                        messagesHistory = messagesHistory.map((m) => {
                                            if (m.id == nonceDebut) {
                                                m.ak = true;
                                            }
                                            return m;
                                        });
                                        messageStatic = m;
                                        receiverStatic = userEnLigne;
                                        yield deroulerProtocole(id, true);
                                        isResponsing = r;
                                        isDeleteForAll = d;
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
    const textToAdd = getHisMessage({
        id: idMessageRecu,
        rf: rf,
        sender: fromA,
        content: messageContent,
        date: getDateFormat(),
    });
    addingReceivedMessage(textToAdd);
    messagesHistory.push({
        id: idMessageRecu,
        content: messageContent,
        sender: fromA,
        refered: selectedMessageIdLocal,
        receiver: receiverStatic,
        ak: false,
        date: getDateFormat(),
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
                return error.message;
            }
            else {
                return "An unexpected error occurred";
            }
        }
    });
}
// Automatic refresh: the waiting time is given in milliseconds
const intervalRefresh = setInterval(refresh, 200);
//----------------------reception meme hors connexion---------------------
let lastIndex = localStorage.getItem("lastIndex") || "0";
let messagesHistory = [];
let isResponsing = false; //if the message is refering another
const reponsea = document.getElementById("reponsea");
const reponseaText = document.getElementById("reponseaText");
let isDeleteForAll = false;
let selectedMessageId = "";
const corespondanceIDNonce = [];
function addCores(id, nonce) {
    let exist = false;
    corespondanceIDNonce.map((c) => {
        if (c.id == id) {
            exist = true;
        }
    });
    if (!exist) {
        corespondanceIDNonce.push({
            id: id,
            nonce: nonce,
        });
    }
}
function getCoresNonceById(id) {
    let res = "";
    corespondanceIDNonce.map((c) => {
        if (c.id == id) {
            res = c.nonce;
        }
    });
    return res;
}
function getCoresIdByNonce(nonce) {
    let res = "";
    corespondanceIDNonce.map((c) => {
        if (c.nonce == nonce) {
            res = c.id;
        }
    });
    return res;
}
const corespondanceIDNonceStock = JSON.parse(localStorage.getItem("corespondanceIDNonce"));
if (corespondanceIDNonceStock != null) {
    corespondanceIDNonceStock.map((c) => {
        corespondanceIDNonce.push(c);
    });
}
let start = true;
window.addEventListener("beforeunload", () => {
    localStorage.setItem("lastIndex", lastIndex);
    localStorage.setItem("fileAttente", JSON.stringify(fileAttente));
    localStorage.setItem("messagesHistory", JSON.stringify(messagesHistory));
    localStorage.setItem("corespondanceIDNonce", JSON.stringify(corespondanceIDNonce));
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
        console.log("ajouté za ds attente", content);
        //response and delete request cases
        if (isResponsing) {
            //if the message i wante to send is refering another
            messageStatic = selectedMessageId + "r&r" + messageStatic;
            isResponsing = false;
        }
        else if (isDeleteForAll) {
            messageStatic = selectedMessageId + "d&d";
            isDeleteForAll = false;
        }
        //adding
        let exist = -1;
        for (let i = 0; i < this.attentes.length && this.attentes.length != 0; i++) {
            const attenteCourant = this.attentes[i];
            if (receiverToAdd === attenteCourant.receiver) {
                exist = i;
                break;
            }
        }
        if (exist == -1) {
            this.attentes.push(new Attente(receiverToAdd, [
                {
                    id: id,
                    content: content,
                    nonceDebut: nonceA,
                },
            ]));
        }
        else {
            this.attentes[exist].messages.push({
                id: id,
                content: content,
                nonceDebut: nonceA,
            });
        }
    }
    getAttenteByReceiver(receiverParam) {
        const res = this.attentes.find((a) => {
            return a.receiver === receiverParam;
        });
        return res;
    }
    deleteAttente(receiverToPop) {
        console.log("delete attente");
        console.log("avant", fileAttente.attentes);
        fileAttente.attentes = fileAttente.attentes.filter((a) => {
            return a.receiver != receiverToPop;
        });
        console.log("apres", fileAttente.attentes);
    }
}
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
            fileAttente.addAttente(m.id, a.receiver, m.content);
        });
    });
    console.log("fileAttente", fileAttente);
}
function getRandomNumber(min, max) {
    let num = Math.floor(Math.random() * (max - min) + min);
    return "" + num;
}
//submit on click entrer
document.addEventListener("keyup", (e) => {
    console.log(e.key);
    if (e.key == "Enter") {
        sendButton.click();
    }
});
function toogleSettings(id) {
    selectedMessageId = id;
    let settings = document.getElementById("settings");
    settings.classList.toggle("hidden");
    let m = getMessageFromHistoryByID(id);
    if (m != undefined) {
        let sender = m.sender;
        if (sender != globalUserName) {
            document.getElementById("supPourTous").classList.add("hidden");
        }
        else {
            document.getElementById("supPourTous").classList.remove("hidden");
        }
    }
}
function deleteForMe() {
    deleteMessageFromHistory(selectedMessageId);
    document.getElementById(selectedMessageId).remove();
    toogleSettings(selectedMessageId);
}
function deleteForAll() {
    return __awaiter(this, void 0, void 0, function* () {
        isDeleteForAll = true;
        fileAttente.addAttente("", receiverStatic, selectedMessageId + "d&d");
        yield deroulerProtocole("", false);
        deleteForMe();
        isDeleteForAll = false;
    });
}
function rep() {
    toogleSettings(selectedMessageId);
    console.log("rep to ", selectedMessageId);
    const messageToRepTo = document.getElementById(selectedMessageId);
    const messageContent = messageToRepTo.getElementsByClassName("messageContent")[0];
    reponseaText.innerText = "Réponse à : " + messageContent.innerText;
    isResponsing = true;
    reponsea.classList.remove("hidden");
}
function annulerRep() {
    reponsea.classList.add("hidden");
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
function isAk(nonce) {
    let id = getCoresIdByNonce(nonce);
    let res = true;
    fileAttente.attentes.map((a) => {
        a.messages.map((m) => {
            if (m.id == id) {
                res = true;
            }
        });
    });
    return res;
}
function getMyMessage(message) {
    if (message.content.includes("d&d")) {
        return "";
    }
    let statusColorClasses = "";
    if (message.ak) {
        statusColorClasses = "bg-white text-blue-500";
    }
    else {
        statusColorClasses = "bg-black text-white";
    }
    console.log("statusColorClasses", statusColorClasses);
    let r = "";
    if (message.rf != null) {
        let referedMessageTag = document.getElementById(message.rf.id);
        if (referedMessageTag != null) {
            r = `<div onclick="goToMsg(${message.rf.id})" class='flex flex-row-reverse mt-3 p-1 cursor-pointer bg-gray-300 hover:bg-gray-500 truncate rounded'><div class="text-end truncate">${message.rf.content} :${message.rf.sender}</div></div>`;
        }
    }
    return `
<div onclick="clickMsg(${message.id})" class="my-2" id="${message.id}">
 ${r}
 <div class="relative text-black rounded-md p-2 ml-1/2 mt-1" style="margin-left:50%;background:linear-gradient(350deg,green,white)"> <div class="flex justify-end"  >
<!--status-->
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="currentColor"
 class="status absolute right-1 bottom-1 -rotate-45 ${statusColorClasses} p-1 rounded-full w-6 h-6">
<path d="M3.478 2.404a.75.75 0 0 0-.926.941l2.432 7.905H13.5a.75.75 0 0 1 0 1.5H4.984l-2.432 7.905a.75.75 0 0 0 .926.94 60.519 60.519 0 0 0 18.445-8.986.75.75 0 0 0 0-1.218A60.517 60.517 0 0 0 3.478 2.404Z" />
</svg>
<!--settings-->
<svg onclick="toogleSettings(${message.id})" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="currentColor" 
class="w-6 h-6 absolute top-1 left-1 cursor-pointer">
<path fill-rule="evenodd" d="M11.078 2.25c-.917 0-1.699.663-1.85 1.567L9.05 4.889c-.02.12-.115.26-.297.348a7.493 7.493 0 0 0-.986.57c-.166.115-.334.126-.45.083L6.3 5.508a1.875 1.875 0 0 0-2.282.819l-.922 1.597a1.875 1.875 0 0 0 .432 2.385l.84.692c.095.078.17.229.154.43a7.598 7.598 0 0 0 0 1.139c.015.2-.059.352-.153.43l-.841.692a1.875 1.875 0 0 0-.432 2.385l.922 1.597a1.875 1.875 0 0 0 2.282.818l1.019-.382c.115-.043.283-.031.45.082.312.214.641.405.985.57.182.088.277.228.297.35l.178 1.071c.151.904.933 1.567 1.85 1.567h1.844c.916 0 1.699-.663 1.85-1.567l.178-1.072c.02-.12.114-.26.297-.349.344-.165.673-.356.985-.57.167-.114.335-.125.45-.082l1.02.382a1.875 1.875 0 0 0 2.28-.819l.923-1.597a1.875 1.875 0 0 0-.432-2.385l-.84-.692c-.095-.078-.17-.229-.154-.43a7.614 7.614 0 0 0 0-1.139c-.016-.2.059-.352.153-.43l.84-.692c.708-.582.891-1.59.433-2.385l-.922-1.597a1.875 1.875 0 0 0-2.282-.818l-1.02.382c-.114.043-.282.031-.449-.083a7.49 7.49 0 0 0-.985-.57c-.183-.087-.277-.227-.297-.348l-.179-1.072a1.875 1.875 0 0 0-1.85-1.567h-1.843ZM12 15.75a3.75 3.75 0 1 0 0-7.5 3.75 3.75 0 0 0 0 7.5Z" clip-rule="evenodd" />
</svg>
<!--sender name-->
<spane id="senderName" class="senderName mx-2 pt-1 underline ">${message.sender.split("@")[0]}</spane>
<!--sender photo-->
  <img 
  class="rounded-full w-10 h-10"
  alt="photo"
  src="
  data:image/jpeg;base64,/9j/4AAQSkZJRgABAQAAAQABAAD/2wCEAAkGBwgHBgkIBwgKCgkLDRYPDQwMDRsUFRAWIB0iIiAdHx8kKDQsJCYxJx8fLT0tMTU3Ojo6Iys/RD84QzQ5OjcBCgoKDQwNGg8PGjclHyU3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3N//AABEIAJQAmQMBIgACEQEDEQH/xAAcAAEAAgMBAQEAAAAAAAAAAAAAAQcEBQYDCAL/xABBEAABAwMBAwcHCgQHAAAAAAABAAIDBAURBhIhMQcTQVFhcYEiMlKRk7HSFBUWFyNCocHR4QhykvAkM0Nic6Ky/8QAGgEBAAMBAQEAAAAAAAAAAAAAAAEDBAIFBv/EACERAQACAgIDAAMBAAAAAAAAAAABAgMREiEEEzEFMkFR/9oADAMBAAIRAxEAPwC8VBUoghFKICKEQSihEEooRBKKEQSihEEooRBKIoQSihSgIiIChCiAiIgHcud1jrOz6RoRUXSYmV4PNUsWDLKewdXWTuWTrG8nT+l7ldWNa6Smgc6NrzuLuAz4kL5DutxrbrXS11xqJKiplcS+R5yf2HYgsHUPLZqa4SSMtYgtlPnyObZtyY7XOyPUAuQn1tqqokMkmo7tk9Dax7R4AHAWhKhB1tp5SdX2qQOhvlXO3OSyrfzwP9WSPAq3NA8s1JeKiK36jhjoauQ7LKhhxA89RyctJ8R2hfOynJ4IPuEHKlVHyC6xrLzb57HcTJLLQMa6Gc5OYycbLj1jo6x3K3EBERAREQEREBEUFAREQEREFV/xFzyRaLo4mOLWy3BgfjpAY849eD4LkdOcktLctJ09TX1U9NcqlomY5oy2JhHktc08d287wd+Ohdvy8UL6/TdohYwuL7xDGR2Oa9vvIXUsYI2tjaMNYA0Y7FTlvNYjS/BSLTO3z1eeSjU9vkJpKeO4Q+nTvAPi12D6srnJ9L6ggfsy2S4A9lM8+4L6pRcRnn+wtnxo/kvl+i0TqetIFPZKzf0yR82P+2F1NFyO32S3zVFZUU9PO2MujpW/aOe4DzSQcDq3ZV8KOnKTnmUx48Qq/wDhpncXagpzw/w8g3dPlg/kryVU8lts+a+UPWkDG4j2oZG9z9p496tZaIncMcxqdCIilAiIgIiICgqVBQEREBERBz+q4Y611vpZA0hlSyp3jpjOR+PuRe99pnunp6qNpcIzsvAHAHpXh0LJm3ybvH1xQiIqmgUqFKIY9lpmUuqK6pGNqupoWnsMZf7w/wDBdQtDbKaSS6Goc0iOJuyCfvEj91v1sxb49vPza59CIisVCIiAiIgKCpRBCIpQQilEEFaKoZzUz2dR3dy3uFrbxsMbFI7cS7Y/P8lVmruq7BbjZgIiLI9AX6a0ucGt4ncF+VlWvYkqnjOXRgHuyuqxynSvJbjWZbWJgjjawcAF+0RbnmiIiAiIgIiIIClQFKAiIgIoJABJOAtHc9V2i3sft1TZpGA/ZweWc9W7cpiJn4jcQ3q1V3iZWxcznGycg9qry48pVwnqWGjpoYKVrwXNd5b3tzvGeAyOoeK7+lqIqumiqIHbUUrA5h6wUtXrsrbvpp2VUlM8w1bDlv3h/e9e3y+n9I+pZ1bSR1cey7c4ea7qXPSU8sc/MuYeczuAHFY74+Lfjy8oZ0tftkMpmOc924FbSzU5otp8riZJPP7F422gbSt234dMRvPo9gWaSGtJJAA3knoV2LHx7lRmy8uobQEEZClVR9Y9dT3WcwQwz28vxHG8Frg0dIcOvjvBXZ2jWlouUMbnzfJZHcWT7sH+bgr5rLNyh0ihflkjZGh8bmuaeDmnIK/a5dIUoiAoUoggKVAUoC0eo9R01ljDSOdqnjLIgceJPQFs7lVsoKCerk3tiYXY6+xU3W1U1dVy1VS7alkdtO/TuVmOnKe3F7a+My63243V5+VVDubP+kzyWDw6fFaipBNO8NGSRjAXoi0xER8UTMy0hBB37j2qwuTS7c5BLaZjl8WZIMn7vSPA7/FcNXy7cuyODNx71FsrpbZcIK2Dz4X7WM+cOkeIyq713Dus6Xi5zWtL3uAaBkuO4Ada4ur1cTeGS00bXUceW72+U8HiQejsXWzCjuWnpah55ylnpy8fy4z61VoiGBvKt8TDW++UPJ/MeblwTStJ1vtatLUxVdPHUU7w+OQZaR/f4LnOUG7/ADfaPkkLsT1mW9oZ94/l4rY6LggbpznGnZdzj3SOcer9gFV+prq68Xieqz9iDsQjqYOHr3nxWeccReY/x6mHNOTDW8/Zhq+78FtKAObTAOBG88Vg0kvNTAng7cVt1dBLMtt2rrY8Ooql8YzvZnLD3jgrC0xqqG7kU9Q0Q1mPNz5L+1v6KsF+o3uie2SNxY9p2muHEHrXN8cTCa2mF4hStZpy5fOtogqjgSEbMgHQ4cf18Vs1lmNL4nYiKESBSoClBzPKDKY9OPYD/mysaff+SrFWLykuxZ6ZvXUg+prv1VdLTh/VRk+iIvKB+26Uei/Cs24YtxiwRK3gdzu9YS3UjBJG5juBC0z2GN7mu4g4USmHX6a1AYtM3Czyuw7ANPk8Wud5Y8M58Vihc5FIYpGyN4tK6FkjXxiQEbJGe5a/E1FZh83+dx3nJW/81pm1V9NBpOotsL/t6uctP+2ItG168Y8SuOXtVzc/O5/Rwb3LxAJIAGSsuTU3mYe54dLY/HpS32IZVBFzku04eSz3rZLzgi5mJrOnp71FU/m4Se0e9RC96oiLoWByaTF1FWwneGStcPEfsu0XBcmTvtLizrEZ/wDS7xZMn7S0U+JRQi4dAUqApQc7rGzVd6paaGjMQMchc7nHEdGOgFcr9BLx6dH7V3wqzEXdclq9Q5msSrP6B3j06P2rvhWPTcn98jklLn0OHHIxM74VaihT7bI9cK0+gl49Oj9q74ViVnJ1e5nB0b6HON+ZXfCrWUp7bHrhT/1bX/06D27vgWQzQOomUjqfboN53Hn3bh0jzFa6YU1zXr8V5PHx5YiLR87VB9W1/wDToPbu+Be1Lyc3yOXbkfQ4HDEzjv8A6VbKlc+yyzhCs/oJePTo/au+FY9byf32aMNjfQ5znfM74VaalT7bHrhWQ0Jecb30ef8Ald8Kn6CXj06P2rvhVmIntseuHJ6O09X2WpqX1boC2VjQ3m3knIJ6wF1alFxMzM7l1EaERFCUBSiICIiAiIgIiICIiAiIgIiICIiAiIgIiIP/2Q==
  " />
</div>  
<!--content-->
<div  class="pr-2 messageContent">${message.content}</div>

 </div>
 <div id="${message.id + "date"}" class="text-center hidden text-sm" >${message.date}</div>
 </div>`;
}
function getHisMessage(message) {
    if (message.date == undefined) {
        message.date = getDateFormat();
    }
    console.log(" message.date", message.date);
    let r = "";
    if (message.rf != null) {
        let referedMessageTag = document.getElementById(message.rf.id);
        if (referedMessageTag != null) {
            r = `<div onclick="goToMsg(${message.rf.id})" class='flex flex-row mt-3 p-1 cursor-pointer bg-gray-300 hover:bg-gray-500 truncate rounded'><div class="text-end"> ${message.rf.sender}: ${message.rf.content}</div></div>`;
        }
    }
    return `
  <div onclick="clickMsg(${message.id})" class="my-2" id="${message.id}">
    ${r}
    
    <div class="relative" style="background:linear-gradient(10deg,yellow,white);padding:10px;border-radius:20px;margin-top:10px;margin-right:50%">
    <div id="receiver" class="flex flex-start relative">
    <img 
    class="rounded-full w-10 h-10"
    alt="photo"
    src="data:image/jpeg;base64,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" 
    />
    <!--settings-->
    <svg onclick="toogleSettings(${message.id})" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="currentColor" 
    class="w-6 h-6 absolute top-1 right-1 cursor-pointer">
    <path fill-rule="evenodd" d="M11.078 2.25c-.917 0-1.699.663-1.85 1.567L9.05 4.889c-.02.12-.115.26-.297.348a7.493 7.493 0 0 0-.986.57c-.166.115-.334.126-.45.083L6.3 5.508a1.875 1.875 0 0 0-2.282.819l-.922 1.597a1.875 1.875 0 0 0 .432 2.385l.84.692c.095.078.17.229.154.43a7.598 7.598 0 0 0 0 1.139c.015.2-.059.352-.153.43l-.841.692a1.875 1.875 0 0 0-.432 2.385l.922 1.597a1.875 1.875 0 0 0 2.282.818l1.019-.382c.115-.043.283-.031.45.082.312.214.641.405.985.57.182.088.277.228.297.35l.178 1.071c.151.904.933 1.567 1.85 1.567h1.844c.916 0 1.699-.663 1.85-1.567l.178-1.072c.02-.12.114-.26.297-.349.344-.165.673-.356.985-.57.167-.114.335-.125.45-.082l1.02.382a1.875 1.875 0 0 0 2.28-.819l.923-1.597a1.875 1.875 0 0 0-.432-2.385l-.84-.692c-.095-.078-.17-.229-.154-.43a7.614 7.614 0 0 0 0-1.139c-.016-.2.059-.352.153-.43l.84-.692c.708-.582.891-1.59.433-2.385l-.922-1.597a1.875 1.875 0 0 0-2.282-.818l-1.02.382c-.114.043-.282.031-.449-.083a7.49 7.49 0 0 0-.985-.57c-.183-.087-.277-.227-.297-.348l-.179-1.072a1.875 1.875 0 0 0-1.85-1.567h-1.843ZM12 15.75a3.75 3.75 0 1 0 0-7.5 3.75 3.75 0 0 0 0 7.5Z" clip-rule="evenodd" />
    </svg>
    <!--sender name-->
    <spane class="senderName mx-2 pt-1 underline ">${message.sender.split("@")[0]}</spane>
  
   </div>
   <div class="messageContent">${message.content}</div>

   </div> 
   <div id="${message.id + "date"}" class="text-center hidden text-sm" >${message.date}</div>

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
                const message = {
                    id: m.id,
                    rf: rf,
                    sender: m.sender,
                    content: m.content,
                    ak: m.ak,
                    date: m.date,
                };
                addingReceivedMessage(getMyMessage(message));
            }
            else {
                const message = {
                    id: m.id,
                    rf: rf,
                    sender: m.sender,
                    content: m.content,
                    ak: m.ak,
                    date: m.date,
                };
                addingReceivedMessage(getHisMessage(message));
            }
        }
    });
}
function viderConv() {
    received_messages.innerHTML = "";
    messagesHistory = [];
}
function getDateFormat() {
    let date = new Date();
    // Get year, month, day, hours, and minutes
    var year = date.getFullYear();
    var month = ("0" + (date.getMonth() + 1)).slice(-2); // Months are zero based, so add 1
    var day = ("0" + date.getDate()).slice(-2);
    var hours = ("0" + date.getHours()).slice(-2);
    var minutes = ("0" + date.getMinutes()).slice(-2);
    // Format the date and time
    var formattedDate = year + "/" + month + "/" + day + " " + hours + ":" + minutes;
    return formattedDate;
}
function clickMsg(id) {
    let tag = document.getElementById(id + "date");
    tag.classList.toggle("hidden");
}
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoibWVzc2VuZ2VyLmpzIiwic291cmNlUm9vdCI6IiIsInNvdXJjZXMiOlsiLi4vc3JjL2xpYkNyeXB0by50cyIsIi4uL3NyYy9tZXNzZW5nZXIudHMiXSwibmFtZXMiOltdLCJtYXBwaW5ncyI6Ijs7Ozs7Ozs7O0FBQUEsaUZBQWlGO0FBRWpGOzs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7OztFQWdDRTtBQUVGLHVGQUF1RjtBQUV2Rjs7O0VBR0U7QUFDRixTQUFlLDhCQUE4QixDQUFDLFVBQWtCOztRQUM1RCxJQUFJLENBQUM7WUFDRCxNQUFNLGNBQWMsR0FBZ0IsSUFBSSxDQUFDLHlCQUF5QixDQUFDLFVBQVUsQ0FBQyxDQUFBO1lBQzlFLE1BQU0sR0FBRyxHQUFjLE1BQU0sTUFBTSxDQUFDLE1BQU0sQ0FBQyxNQUFNLENBQUMsU0FBUyxDQUN2RCxNQUFNLEVBQ04sY0FBYyxFQUNkO2dCQUNJLElBQUksRUFBRSxVQUFVO2dCQUNoQixJQUFJLEVBQUUsU0FBUzthQUNsQixFQUNELElBQUksRUFDSixDQUFDLFNBQVMsQ0FBQyxDQUNkLENBQUE7WUFDRCxPQUFPLEdBQUcsQ0FBQTtRQUNkLENBQUM7UUFBQyxPQUFPLENBQUMsRUFBRSxDQUFDO1lBQ1QsSUFBSSxDQUFDLFlBQVksWUFBWSxFQUFFLENBQUM7Z0JBQUMsT0FBTyxDQUFDLEdBQUcsQ0FBQywyREFBMkQsQ0FBQyxDQUFBO1lBQUMsQ0FBQztpQkFDdEcsSUFBSSxDQUFDLFlBQVksa0JBQWtCLEVBQUUsQ0FBQztnQkFBQyxPQUFPLENBQUMsR0FBRyxDQUFDLDJEQUEyRCxDQUFDLENBQUE7WUFBQyxDQUFDO2lCQUNqSCxDQUFDO2dCQUFDLE9BQU8sQ0FBQyxHQUFHLENBQUMsQ0FBQyxDQUFDLENBQUE7WUFBQyxDQUFDO1lBQ3ZCLE1BQU0sQ0FBQyxDQUFBO1FBQ1gsQ0FBQztJQUNMLENBQUM7Q0FBQTtBQUVEOzs7RUFHRTtBQUNGLFNBQWUsNkJBQTZCLENBQUMsVUFBa0I7O1FBQzNELElBQUksQ0FBQztZ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