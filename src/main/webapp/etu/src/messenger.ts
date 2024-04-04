
/* tsc --inlineSourceMap  true -outFile JS/messenger.js src/libCrypto.ts src/messenger.ts --target es2015 */

// To detect if we can use window.crypto.subtle
if (!window.isSecureContext) alert("Not secure context!")

// Message for user name
class CasUserName {
    constructor(public username: string) { }
}

// Requesting keys
class KeyRequest {
    constructor(public ownerOfTheKey: string, public publicKey: boolean, public encryption: boolean) { }
}

class KeyResult {
    constructor(public success: boolean, public key: string, public errorMessage: string) { }
}

// The message format
class ExtMessage {
    constructor(public sender: string, public receiver: string, public content: string) { }
}

// Sending a message Result format
class SendResult {
    constructor(public success: boolean, public errorMessage: string) { }
}

// Message for requiring history
class HistoryRequest {
    constructor(public agentName: string, public index: number) { }
}

// Result of history request
class HistoryAnswer {
    constructor(public success: boolean,
        public failureMessage: string,
        public index: number,
        public allMessages: ExtMessage[]) { }
}

const userButtonLabel = document.getElementById("user-name") as HTMLLabelElement

const sendButton = document.getElementById("send-button") as HTMLButtonElement
const receiver = document.getElementById("receiver") as HTMLInputElement
const messageHTML = document.getElementById("message") as HTMLInputElement
const received_messages = document.getElementById("exchanged-messages") as HTMLLabelElement

let globalUserName = ""


// Basic utilities for adding/clearing received messages in the page
function clearingMessages() {
    received_messages.textContent = ""
}

function stringToHTML(str: string): HTMLDivElement {
    var div_elt = document.createElement('div')
    div_elt.innerHTML = str
    return div_elt
}

function addingReceivedMessage(message: string) {
    received_messages.append(stringToHTML(`<p></p><p></p>` + message))
}

// WARNING!
// It is necessary to pass the URL parameters, called `urlParams` below, to 
// every GET/POST query you send to the server. This is mandatory to have the possibility 
// to use alternative identities like alice@univ-rennes.fr, bob@univ-rennes.fr, etc. 
// for debugging purposes.

async function fetchCasName(): Promise<string> {
    const urlParams = new URLSearchParams(window.location.search);
    const namerequest = await fetch("/getuser?" + urlParams, {
        method: "GET",
        headers: {
            "Content-type": "application/json; charset=UTF-8"
        }
    });
    if (!namerequest.ok) {
        throw new Error(`Error! status: ${namerequest.status}`)
    }
    const nameResult = (await namerequest.json()) as CasUserName
    console.log("Fetched CAS name= " + nameResult.username)
    return nameResult.username
}

async function setCasName() {
    globalUserName = await fetchCasName()
    // We replace the name of the user of the application as the default name
    // In the window
    userButtonLabel.textContent = globalUserName
}

setCasName()

// WARNING!
// It is necessary to provide the name of the owner of the application. Each pair of student are
// the owner of their application. Other students may use it but they are only users and not owners.
// Messages sent to the server are separated w.r.t. the name of the application (i.e. the name of their owners).
// The name of the owners is the name of the folder of the application where the web pages of the application are stored. 
// E.g, for teachers' application this name is "ens"

function getOwnerName(): string {
    const path = window.location.pathname
    const name = path.split("/", 2)[1]
    return name
}

let ownerName = getOwnerName()
let lastIndex=localStorage.getItem('lastIndex')|| ''
// WARNING!
// It is necessary to pass the URL parameters, called `urlParams` below, to 
// every GET/POST query you send to the server. This is mandatory to have the possibility 
// to use alternative identities like alice@univ-rennes.fr, bob@univ-rennes.fr, etc. 
// for debugging purposes.

async function fetchKey(user: string, publicKey: boolean, encryption: boolean): Promise<CryptoKey> {
    // Getting the public/private key of user.
    // For public key the boolean 'publicKey' is true.
    // For private key the boolean 'publicKey' is false.
    // If the key is used for encryption/decryption then the boolean 'encryption' is true.
    // If the key is used for signature/signature verification then the boolean is false.
    const keyRequestMessage =
        new KeyRequest(user, publicKey, encryption)
    // For CAS authentication we need to add the authentication ticket
    // It is contained in urlParams
    const urlParams = new URLSearchParams(window.location.search);
    // For getting a key we do not need the ownerName param
    // Because keys are independant of the applications
    const keyrequest = await fetch("/getKey?" + urlParams, {
        method: "POST",
        body: JSON.stringify(keyRequestMessage),
        headers: {
            "Content-type": "application/json; charset=UTF-8"
        }
    });
    if (!keyrequest.ok) {
        throw new Error(`Error! status: ${keyrequest.status}`);
    }
    const keyResult = (await keyrequest.json()) as KeyResult;
    if (!keyResult.success) alert(keyResult.errorMessage)
    else {
        if (publicKey && encryption) return await stringToPublicKeyForEncryption(keyResult.key)
        else if (!publicKey && encryption) return await stringToPrivateKeyForEncryption(keyResult.key)
        else if (publicKey && !encryption) return await stringToPublicKeyForSignature(keyResult.key)
        else if (!publicKey && !encryption) return await stringToPrivateKeyForSignature(keyResult.key)
    }
}

// WARNING!
// It is necessary to pass the URL parameters, called `urlParams` below, to 
// every GET/POST query you send to the server. This is mandatory to have the possibility 
// to use alternative identities like alice@univ-rennes.fr, bob@univ-rennes.fr, etc. 
// for debugging purposes.
// 
// We also need to provide the ownerName

async function sendMessage(agentName: string, receiverName: string, messageContent: string): Promise<SendResult> {
    try {
        let messageToSend =
            new ExtMessage(agentName, receiverName, messageContent)
        const urlParams = new URLSearchParams(window.location.search);

        const request = await fetch("/sendingMessage/" + ownerName + "?" + urlParams, {
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
        console.log(`Sent message from ${agentName} to ${receiverName}: ${messageContent}`)
        return (await request.json()) as SendResult
    }
    catch (error) {
        if (error instanceof Error) {
            console.log('error message: ', error.message);
            return new SendResult(false, error.message)
        } else {
            console.log('unexpected error: ', error);
            return new SendResult(false, 'An unexpected error occurred')
        }
    }
}

let messageStatic = ""


sendButton.onclick = async function () {
    nonceA = generateNonce()
    let agentName = globalUserName
    let receiverName = receiver.value
    messageStatic = messageHTML.value
    let contentToEncrypt = JSON.stringify([agentName])
    try {
        const kb = await fetchKey(receiverName, true, true)
        // We encrypt
        const encryptedMessage = await encryptWithPublicKey(kb, contentToEncrypt)
        // And send
        const sendResult = await sendMessage(agentName, receiverName, encryptedMessage)
        if (!sendResult.success) console.log(sendResult.errorMessage)
        else {
            console.log("Successfully sent the message!")
            // We add the message to the list of sent messages
            const textToAdd = `<font color="blue" id="${nonceA}"> ${agentName} -> ${receiverName} : ${messageHTML.value} </font>`
            addingReceivedMessage(textToAdd)
        }
    } catch (e) {
        if (e instanceof Error) {
            console.log('error message: ', e.message)
        } else {
            console.log('unexpected error: ', e);
        }
    }
}

let nonceB = ""
let nonceA

// Parsing/Recognizing a message sent to app_user
// The first element of the tuple is a boolean saying if the message was for the user
// If this boolean is true, then the second element is the name of the sender
// and the third is the content of the message
async function analyseMessage(message: ExtMessage): Promise<[boolean, string, string]> {
    const user = globalUserName
    try {
        const messageSender = message.sender
        const messageContent = message.content
        if (message.receiver !== user) {
            // If the message is not sent to the user, we do not consider it
            return [false, "", ""]
        }
        else {
            //we fetch user private key to decrypt the message
            try {
                const privkey = await fetchKey(user, false, true)
                const messageInClearString = await decryptWithPrivateKey(privkey, messageContent)
                //console.log(messageInClearString)

                const messageArrayInClear = JSON.parse(messageInClearString) as string[];
                const messageSenderInMessage = messageArrayInClear[0]
                switch (messageArrayInClear.length) {
                    //demande envoie de nonce pour authentifie
                    case 1:
                        let agentName = globalUserName
                        nonceB = generateNonce()
                        let contentToEncrypt = JSON.stringify([agentName, nonceB])
                        try {
                            const kb = await fetchKey(messageSenderInMessage, true, true)
                            // We encrypt
                            const encryptedMessage = await encryptWithPublicKey(kb, contentToEncrypt)
                            // And send
                            const sendResult = await sendMessage(agentName, messageSenderInMessage, encryptedMessage)
                            if (!sendResult.success) console.log(sendResult.errorMessage)
                            else {
                                console.log("Successfully sent the nonce!")
                            }
                        } catch (e) {
                            if (e instanceof Error) {
                                console.log('error nonce: ', e.message)
                            } else {
                                console.log('unexpected error: ', e);
                            }
                        }
                        break;
                    //reception de la nonce on renvoie le message avec la nonce
                    case 2:
                        if (messageSenderInMessage == messageSender) {
                            const nonce = messageArrayInClear[1] //nonce reçu
                            let agentName = globalUserName
                            let contentToEncrypt = JSON.stringify([agentName, nonce, nonceA, messageStatic])
                            try {
                                const kb = await fetchKey(messageSenderInMessage, true, true)
                                // We encrypt
                                const encryptedMessage = await encryptWithPublicKey(kb, contentToEncrypt)
                                // And send
                                const sendResult = await sendMessage(agentName, messageSenderInMessage, encryptedMessage)
                                if (!sendResult.success) console.log(sendResult.errorMessage)
                                else {
                                    console.log("Successfully sent the nonce and secret!")
                                }
                            } catch (e) {
                                if (e instanceof Error) {
                                    console.log('error nonce: ', e.message)
                                } else {
                                    console.log('unexpected error: ', e);
                                }
                            }
                        }
                        break;
                    //message reçu authentifié --> 3.
                    case 4:
                        const nonce = messageArrayInClear[1]
                        const messageInClear = messageArrayInClear[3]
                        console.log(messageInClear)
                        if (messageSenderInMessage == messageSender && nonce == nonceB) {
                            const noncea = messageArrayInClear[2] //nonce reçu
                            let agentName = globalUserName
                            let contentToEncrypt = JSON.stringify([agentName, noncea, messageStatic])
                            try {
                                const kb = await fetchKey(messageSenderInMessage, true, true)
                                // We encrypt
                                const encryptedMessage = await encryptWithPublicKey(kb, contentToEncrypt)
                                // And send
                                const sendResult = await sendMessage(agentName, messageSenderInMessage, encryptedMessage)
                                if (!sendResult.success) console.log(sendResult.errorMessage)
                                else {
                                    console.log("Successfully sent the acquit !")
                                }
                            } catch (e) {
                                if (e instanceof Error) {
                                    console.log('error nonce: ', e.message)
                                } else {
                                    console.log('unexpected error: ', e);
                                }
                            }
                            return [true, messageSender, messageInClear]
                        } else {
                            console.log("Real message sender and message sender name in the message do not coincide")
                        }
                        break;

                    case 3: //acquit --> 4.
                        const noncea = messageArrayInClear[1]
                        if(messageSenderInMessage == messageSender && noncea == nonceA){
                            const messageInClear = messageArrayInClear[2]
                            console.log("acquit succesfull ", noncea)
                            //return [true, messageSender, messageInClear]
                            const messageAquitte=document.getElementById(''+noncea)
                            console.log(messageAquitte)
                            messageAquitte.style.color='green'

                        }
                        else{
                            console.log("Acquit fail")
                        }



                        break;
                }

            } catch (e) {
                console.log("analyseMessage: decryption failed because of " + e)
                return [false, "", ""]
            }
        }
    } catch (e) {
        console.log("analyseMessage: decryption failed because of " + e)
        return [false, "", ""]
    }
}

// action for receiving message
// 1. A -> B: A,{message}Kb
function actionOnMessageOne(fromA: string, messageContent: string) {
    const user = globalUserName
    const textToAdd = `${fromA} -> ${user} : ${messageContent}`
    addingReceivedMessage(textToAdd)
}

//Index of the last read message
let lastIndexInHistory = 0

// function for refreshing the content of the window (automatic or manual see below)
async function refresh() {
    try {
        const user = globalUserName
        const historyRequest =
            new HistoryRequest(user, lastIndexInHistory)
        const urlParams = new URLSearchParams(window.location.search);
        const request = await fetch("/history/" + ownerName + "?" + urlParams
            , {
                method: "POST",
                body: JSON.stringify(historyRequest),
                headers: {
                    "Content-type": "application/json; charset=UTF-8"
                }
            });
        if (!request.ok) {
            throw new Error(`Error! status: ${request.status}`);
        }
        const result = (await request.json()) as HistoryAnswer
        if (!result.success) { alert(result.failureMessage) }
        else {
            // This is the place where you can perform trigger any operations for refreshing the page
            //addingReceivedMessage("Dummy message!")
            lastIndexInHistory = result.index
           /* console.log('non vu length',result.index-parseInt(lastIndex))
            let interv=result.index-parseInt(lastIndex)
            console.log('allmessage length ',result.allMessages.length)
            let deb=result.allMessages.length-interv
            console.log('deb',deb)
           for (let m=deb;m<result.allMessages.length;m++){
               const message=result.allMessages[m]
               console.log('message m',message)
               const msgenc=message.content
               const privkey = await fetchKey(user, false, true)
               const messageInClearString = await decryptWithPrivateKey(privkey, msgenc)
               const messageArrayInClear = JSON.parse(messageInClearString) as string[];

               console.log('content array length ',messageArrayInClear.length)
               console.log('content array ',messageArrayInClear[0])

               //console.log(result.allMessages[m].content)*/
           }
            lastIndex=result.index+''
            if (result.allMessages.length != 0) {
                //console.log("je suis dans le if avant ma boucle for")
                for(let i=0; i<result.allMessages.length; i++ ){
                    let [b, sender, msgContent] = await analyseMessage(result.allMessages[i])
                    if (b) actionOnMessageOne(sender, msgContent)
                    else console.log("Msg " + result.allMessages[i] + " cannot be exploited by " + user)
                }
            }
        }
    }
    catch (error) {
        if (error instanceof Error) {
            console.log('error message: ', error.message);
            return error.message;
        } else {
            console.log('unexpected error: ', error);
            return 'An unexpected error occurred';
        }
    }
}

// Automatic refresh: the waiting time is given in milliseconds
const intervalRefresh = setInterval(refresh, 500)


window.addEventListener('beforeunload', function (e) {
    localStorage.setItem('lastIndex',lastIndex);
});
