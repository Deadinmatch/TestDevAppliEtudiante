/* tsc --inlineSourceMap  true -outFile JS/messengerNaive.js src/libCrypto.ts src/messengerNaive.ts --target es2015 */

// To detect if we can use window.crypto.subtle
if (!window.isSecureContext) alert("Not secure context!")

//Index of the last read message
let lastIndexInHistory = 0

// Message for user name
class CasUserName {
    constructor(public username: string) { }
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

// Sending messages
// The message format
class ExtMessage {
    constructor(public sender: string, public receiver: string, public content: string) { }
}

// Sending a message Result format
class SendResult {
    constructor(public success: boolean, public errorMessage: string) { }
}

// Requesting keys
class KeyRequest {
    constructor(public ownerOfTheKey: string, public publicKey: boolean, public encryption: boolean) { }
}

class KeyResult {
    constructor(public success: boolean, public key: string, public errorMessage: string) { }
}

const userButtonLabel = document.getElementById("user-name") as HTMLLabelElement

const sendButton = document.getElementById("send-button") as HTMLButtonElement
const receiver = document.getElementById("receiver") as HTMLInputElement
const message = document.getElementById("message") as HTMLInputElement
const received_messages = document.getElementById("exchanged-messages") as HTMLLabelElement

function clearingMessages() {
    received_messages.textContent = ""
}

function stringToHTML(str: string): HTMLDivElement {
    var div_elt = document.createElement('div')
    div_elt.innerHTML = str
    return div_elt
}

function addingReceivedMessage(message: string) {
    received_messages.append(stringToHTML('<p></p><p></p>' + message))
}

/* Name of the user of the application... can be Alice/Bob for attacking purposes */
let globalUserName = ""

async function fetchCasName(): Promise<string> {
    const urlParams = new URLSearchParams(window.location.search);
    const namerequest = await fetch("/getuser?" + urlParams, {
        method: "GET",
        headers: {
            "Content-type": "application/json; charset=UTF-8"
        }
    });
    if (!namerequest.ok) {
        throw new Error(`Error! status: ${namerequest.status}`);
    }
    const nameResult = (await namerequest.json()) as CasUserName;
    return nameResult.username
}

async function setCasName() {
    globalUserName = await fetchCasName()
    // We replace the name of the user of the application as the default name
    // In the window
    userButtonLabel.textContent = globalUserName
}

setCasName()

/* Name of the owner/developper of the application, i.e, the name of the folder 
   where the web page of the application is stored. E.g, for teachers' application
   this name is "ens" */

function getOwnerName(): string {
    const path = window.location.pathname
    const name = path.split("/", 2)[1]
    return name
}

let ownerName = getOwnerName()


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


sendButton.onclick = async function () {
    let agentName = globalUserName
    let receiverName = receiver.value
    let contentToEncrypt = JSON.stringify([agentName, message.value])
    // we fetch the public key of B
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
            const textToAdd = `<font color="blue"> ${agentName} -> ${receiverName} : ${message.value} </font>`
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
                // The next lines contain several intentional programming errors
                // 1) This is not the safest way to obtain an object from a JSON string!
                const messageArrayInClear = eval(`${messageInClearString}`) as string[]
                const messageSenderInMessage = messageArrayInClear[0]
                const messageInClear = messageArrayInClear[1]
                if (messageSenderInMessage == messageSender) {
                    if (messageInClear.indexOf("\\") == -1) {
                        return [true, messageSender, messageInClear]
                    } else {
                        // If the string contains escaped characters like \" \n etc
                        // we remove them using eval.
                        // Using eval to build a value is *always* a bad programming practice
                        const result = `[true, messageSender, ${messageInClear}]`
                        return eval(`${result}`)
                    }
                }
                else {
                    console.log("Real message sender and message sender name in the message do not coincide")
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
            // We update the index with the index of last read message from message server
            lastIndexInHistory = result.index
            if (result.allMessages.length != 0) {
                for (var m of result.allMessages) {
                    let [b, sender, msgContent] = await analyseMessage(m)
                    if (b) actionOnMessageOne(sender, msgContent)
                    else console.log("Msg " + m + " cannot be exploited by " + user)
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

// Automatic refresh
const intervalRefresh = setInterval(refresh, 2000)


