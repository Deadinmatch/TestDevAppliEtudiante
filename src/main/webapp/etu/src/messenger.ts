/* tsc --inlineSourceMap  true -outFile JS/messenger.js src/libCrypto.ts src/messenger.ts --target es2015 */

// To detect if we can use window.crypto.subtle
if (!window.isSecureContext) alert("Not secure context!");

// Message for user name
class CasUserName {
  constructor(public username: string) {}
}

// Requesting keys
class KeyRequest {
  constructor(
    public ownerOfTheKey: string,
    public publicKey: boolean,
    public encryption: boolean
  ) {}
}

class KeyResult {
  constructor(
    public success: boolean,
    public key: string,
    public errorMessage: string
  ) {}
}

// The message format
class ExtMessage {
  constructor(
    public sender: string,
    public receiver: string,
    public content: string
  ) {}
}

// Sending a message Result format
class SendResult {
  constructor(public success: boolean, public errorMessage: string) {}
}

// Message for requiring history
class HistoryRequest {
  constructor(public agentName: string, public index: number) {}
}

// Result of history request
class HistoryAnswer {
  constructor(
    public success: boolean,
    public failureMessage: string,
    public index: number,
    public allMessages: ExtMessage[]
  ) {}
}

const userButtonLabel = document.getElementById(
  "user-name"
) as HTMLLabelElement;

const sendButton = document.getElementById("send-button") as HTMLButtonElement;
const receiver = document.getElementById("receiver") as HTMLInputElement;
const messageHTML = document.getElementById("message") as HTMLInputElement;
const received_messages = document.getElementById(
  "exchanged-messages"
) as HTMLDivElement;

let globalUserName = "";

// Basic utilities for adding/clearing received messages in the page
function clearingMessages() {
  received_messages.textContent = "";
}

function stringToHTML(str: string): HTMLDivElement {
  var div_elt = document.createElement("div");
  div_elt.innerHTML = str;
  div_elt.id = "test";
  return div_elt;
}

function addingReceivedMessage(message: string) {
  received_messages.append(stringToHTML(`<div>${message}</div>`));
  window.scrollTo(0, document.body.scrollHeight);
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
      "Content-type": "application/json; charset=UTF-8",
    },
  });
  if (!namerequest.ok) {
    throw new Error(`Error! status: ${namerequest.status}`);
  }
  const nameResult = (await namerequest.json()) as CasUserName;
  console.log("Fetched CAS name= " + nameResult.username);
  return nameResult.username;
}

async function setCasName() {
  globalUserName = await fetchCasName();
  // We replace the name of the user of the application as the default name
  // In the window
  userButtonLabel.textContent = globalUserName.split("@")[0];
  if (globalUserName == "bob@univ-rennes.fr") {
    const input = document.getElementById("receiver") as HTMLInputElement;
    input.value = "alice@univ-rennes.fr";
  }
  displayOldMessages();
}

setCasName();

// WARNING!
// It is necessary to provide the name of the owner of the application. Each pair of student are
// the owner of their application. Other students may use it but they are only users and not owners.
// Messages sent to the server are separated w.r.t. the name of the application (i.e. the name of their owners).
// The name of the owners is the name of the folder of the application where the web pages of the application are stored.
// E.g, for teachers' application this name is "ens"

function getOwnerName(): string {
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

async function fetchKey(
  user: string,
  publicKey: boolean,
  encryption: boolean
): Promise<CryptoKey> {
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
  const keyrequest = await fetch("/getKey?" + urlParams, {
    method: "POST",
    body: JSON.stringify(keyRequestMessage),
    headers: {
      "Content-type": "application/json; charset=UTF-8",
    },
  });
  if (!keyrequest.ok) {
    throw new Error(`Error! status: ${keyrequest.status}`);
  }
  const keyResult = (await keyrequest.json()) as KeyResult;
  if (!keyResult.success) alert(keyResult.errorMessage);
  else {
    if (publicKey && encryption)
      return await stringToPublicKeyForEncryption(keyResult.key);
    else if (!publicKey && encryption)
      return await stringToPrivateKeyForEncryption(keyResult.key);
    else if (publicKey && !encryption)
      return await stringToPublicKeyForSignature(keyResult.key);
    else if (!publicKey && !encryption)
      return await stringToPrivateKeyForSignature(keyResult.key);
  }
}

// WARNING!
// It is necessary to pass the URL parameters, called `urlParams` below, to
// every GET/POST query you send to the server. This is mandatory to have the possibility
// to use alternative identities like alice@univ-rennes.fr, bob@univ-rennes.fr, etc.
// for debugging purposes.
//
// We also need to provide the ownerName

async function sendMessage(
  agentName: string,
  receiverName: string,
  messageContent: string
): Promise<SendResult> {
  try {
    let messageToSend = new ExtMessage(agentName, receiverName, messageContent);
    const urlParams = new URLSearchParams(window.location.search);

    const request = await fetch(
      "/sendingMessage/" + ownerName + "?" + urlParams,
      {
        method: "POST",
        body: JSON.stringify(messageToSend),
        headers: {
          "Content-type": "application/json; charset=UTF-8",
        },
      }
    );
    if (!request.ok) {
      throw new Error(`Error! status: ${request.status}`);
    }
    // Dealing with the answer of the message server
    console
      .log
      //`Sent message from ${agentName} to ${receiverName}: ${messageContent}`
      ();
    return (await request.json()) as SendResult;
  } catch (error) {
    if (error instanceof Error) {
      console.log("error message: ", error.message);
      return new SendResult(false, error.message);
    } else {
      console.log("unexpected error: ", error);
      return new SendResult(false, "An unexpected error occurred");
    }
  }
}

let messageStatic = "";
let receiverStatic = "";
let canSend = true; //to avoid multiple sendings in a little interval
sendButton.onclick = async function () {
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
  }, 1000);

  if (messageHTML.value.length > 80) {
    let grandM = messageHTML.value;
    receiverStatic = receiver.value;
    messageHTML.value = "";
    nonceA = generateNonce();

    let i = 0;
    const bigMInterv = setInterval(async () => {
      if (i > grandM.length) {
        clearInterval(bigMInterv);
      }
      let substr: string;
      if (i + 80 > grandM.length) {
        substr = grandM.substring(i, grandM.length);
      } else {
        substr = grandM.substring(i, i + 80);
      }

      messageStatic = substr;
      console.log("paginaaaaaaaaation", messageStatic);

      //ajout a la file d'attente
      let idMsg = getRandomNumber(100, 10000);
      fileAttente.addAttente(idMsg, receiverStatic, messageStatic);
      await deroulerProtocole(idMsg, false);
      i += 80;
    }, 1500);
    annulerRep();

    return;
  }

  receiverStatic = receiver.value;
  messageStatic = messageHTML.value;

  messageHTML.value = "";
  //ajout a la file d'attente
  let idMsg = getRandomNumber(100, 10000);
  nonceA = generateNonce();
  fileAttente.addAttente(idMsg, receiverStatic, messageStatic);
  await deroulerProtocole(idMsg, false);
  annulerRep();
};
//@param relance true si on deroule le protocole sur des messages deja envoyé mais qui sont relancé après connexion du receveur, false sinon
async function deroulerProtocole(id: string, relance: boolean) {
  // console.log(
  //   "hey " + receiverStatic + " je veux tchatcher avec toi(derouler protocole)"
  // );
  addCores(id, nonceA);

  let agentName = globalUserName;
  let contentToEncrypt = JSON.stringify([agentName]);
  try {
    const kb = await fetchKey(receiverStatic, true, true);
    // We encrypt
    const encryptedMessage = await encryptWithPublicKey(kb, contentToEncrypt);
    // And send
    const sendResult = await sendMessage(
      agentName,
      receiverStatic,
      encryptedMessage
    );
    if (isDeleteForAll) {
      return;
    }
    if (!sendResult.success) console.log(sendResult.errorMessage);
    else {
      if (!relance) {
        let rf = null;
        if (messageStatic.includes("r&r")) {
          isResponsing = true;
          messageStatic = messageStatic.split("r&r")[1];
        }
        if (isResponsing) {
          let referedMessageTag = document.getElementById(selectedMessageId);

          let referedMessageTextTag = referedMessageTag.getElementsByClassName(
            "messageContent"
          )[0] as HTMLDivElement;

          let referedMessageSenderNameTag =
            referedMessageTag.getElementsByClassName(
              "senderName"
            )[0] as HTMLSpanElement;
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
          nonceDebut: nonceA,
        });
      } else {
        //si c'est de la relace on considère que c'est bien recu
        let nonceID = getCoresNonceById(id);
        console.log("relance nonceID ", nonceID);

        const msgAlreadyDisplayed = document.getElementById(nonceID);
        const statusIcon =
          msgAlreadyDisplayed.getElementsByClassName("status")[0];
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
  } catch (e) {
    if (e instanceof Error) {
      console.log("error message: ", e.message);
    } else {
      console.log("unexpected error: ", e);
    }
  }
}

let nonceB = "";
let nonceA: string = "";
let idMessageRecu = "";
// Parsing/Recognizing a message sent to app_user
// The first element of the tuple is a boolean saying if the message was for the user
// If this boolean is true, then the second element is the name of the sender
// and the third is the content of the message
async function analyseMessage(
  message: ExtMessage
): Promise<[boolean, string, string]> {
  const user = globalUserName;
  try {
    const messageSender = message.sender;
    const messageContent = message.content;
    if (message.receiver !== user) {
      // If the message is not sent to the user, we do not consider it
      return [false, "", ""];
    } else {
      //we fetch user private key to decrypt the message
      try {
        const privkey = await fetchKey(user, false, true);
        const messageInClearString = await decryptWithPrivateKey(
          privkey,
          messageContent
        );
        //console.log(messageInClearString)

        const messageArrayInClear = JSON.parse(
          messageInClearString
        ) as string[];
        const messageSenderInMessage = messageArrayInClear[0];
        switch (messageArrayInClear.length) {
          //demande envoie de nonce pour authentifie
          case 1:
            const kb = await fetchKey(messageSenderInMessage, true, true);
            let agentName = globalUserName;
            nonceB = generateNonce();
            // console.log(
            //   messageSenderInMessage +
            //     " , je sais que tu veux me parler donc tiens cette nonce " +
            //     nonceB +
            //     " (case 1)"
            // );

            let contentToEncrypt = JSON.stringify([agentName, nonceB]);
            try {
              // We encrypt
              const encryptedMessage = await encryptWithPublicKey(
                kb,
                contentToEncrypt
              );
              // And send
              const sendResult = await sendMessage(
                agentName,
                messageSenderInMessage,
                encryptedMessage
              );
              if (!sendResult.success) console.log(sendResult.errorMessage);
              else {
                //console.log("Successfully sent the nonce!");
              }
            } catch (e) {
              if (e instanceof Error) {
                console.log("error nonce: ", e.message);
              } else {
                console.log("unexpected error: ", e);
              }
            }
            break;
          //reception de la nonce on renvoie le message avec la nonce
          case 2:
            fileAttente.deleteAttente(messageSenderInMessage);
            if (messageSenderInMessage == messageSender) {
              const nonce = messageArrayInClear[1]; //nonce reçu

              // console.log(
              //   "merci pour ta nonce " +
              //     nonce +
              //     " je t'envoi le message: " +
              //     messageStatic +
              //     " et une none" +
              //     nonceA +
              //     "(case 2)"
              // );

              let agentName = globalUserName;
              let contentToEncrypt: string;
              let selectedMessageIdLocal = selectedMessageId;

              if (isResponsing) {
                //if the message i wante to send is refering another
                messageStatic = selectedMessageId + "r&r" + messageStatic;
                isResponsing = false;
              } else if (isDeleteForAll) {
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
                const kb = await fetchKey(messageSenderInMessage, true, true);
                // We encrypt
                const encryptedMessage = await encryptWithPublicKey(
                  kb,
                  contentToEncrypt
                );
                // And send
                const sendResult = await sendMessage(
                  agentName,
                  messageSenderInMessage,
                  encryptedMessage
                );
                if (!sendResult.success) console.log(sendResult.errorMessage);
                else {
                  //console.log("Successfully sent the nonce and secret!");
                }
              } catch (e) {
                if (e instanceof Error) {
                  console.log("error nonce: ", e.message);
                } else {
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
              const noncea = messageArrayInClear[2]; //nonce reçu
              idMessageRecu = noncea;
              console.log(
                messageArrayInClear,
                " merci pour ce tableau avec ton secret dedans, tiens ta nonce:" +
                  noncea +
                  "comme aquit(case 4)"
              );

              let agentName = globalUserName;
              let contentToEncrypt = JSON.stringify([
                agentName,
                noncea,
                messageStatic,
              ]);
              try {
                const kb = await fetchKey(messageSenderInMessage, true, true);
                // We encrypt
                const encryptedMessage = await encryptWithPublicKey(
                  kb,
                  contentToEncrypt
                );
                // And send
                const sendResult = await sendMessage(
                  agentName,
                  messageSenderInMessage,
                  encryptedMessage
                );
                if (!sendResult.success) console.log(sendResult.errorMessage);
                else {
                  console.log("Successfully sent the acquit !");
                }
              } catch (e) {
                if (e instanceof Error) {
                  console.log("error nonce: ", e.message);
                } else {
                  console.log("unexpected error: ", e);
                }
              }
              return [true, messageSender, messageInClear];
            } else {
              console.log(
                "Real message sender and message sender name in the message do not coincide"
              );
            }
            break;

          case 3: //reception de acquit --> 4.
            const noncea = messageArrayInClear[1];

            //marquer le message dans messageshistory comme aquité
            messagesHistory = messagesHistory.map((m) => {
              if (m.nonceDebut == noncea) {
                m.ak = true;
              }
              return m;
            });
            if (messageSenderInMessage == messageSender && noncea == nonceA) {
              const messageInClear = messageArrayInClear[2];
              // console.log(
              //   "j'ai bien reçu l'aquittement par la nonce  " +
              //     noncea +
              //     " pour le message " +
              //     messageInClear
              // );
              //return [true, messageSender, messageInClear]
              const messageAquitte = document.getElementById("" + noncea);
              //   messageAquitte.style.background =
              //     "linear-gradient(45deg,green,white)";
              const statusIcon =
                messageAquitte.getElementsByClassName("status")[0];

              statusIcon.classList.remove("text-white");
              statusIcon.classList.remove("bg-black");

              statusIcon.classList.add("text-blue-500");
              statusIcon.classList.add("bg-white");
            } else {
              console.log("Acquit fail");
            }

            break;
          case 5: //quelqu'un est devenu en ligne
            const userEnLigne = messageArrayInClear[0];

            //je le cherche dans me liste d'attente
            const attente = fileAttente.getAttenteByReceiver(userEnLigne);
            fileAttente.deleteAttente(userEnLigne);

            if (attente != undefined) {
              //si il est dans la liste d'attente, je lui envoi tout mes message en attente qui lui etaient destinés
              for (
                let i = 0;
                i < attente.messages.length && attente.messages.length != 0;
                i++
              ) {
                setTimeout(async () => {
                  let r = isResponsing;
                  let d = isDeleteForAll;
                  let m = attente.messages[i].content;

                  if (m != undefined && m.includes("r&r")) {
                    const split = m.split("r&r");
                    m = split[1];
                    isResponsing = true;
                    selectedMessageId = split[0];
                  } else if (m != undefined && m.includes("d&d")) {
                    selectedMessageId = m.split("d&d")[0];
                    isDeleteForAll = true;
                  }
                  const id = attente.messages[i].id;
                  const nonceDebut = attente.messages[i].nonceDebut;
                  messagesHistory = messagesHistory.map((mh) => {
                    if (mh.id == nonceDebut) {
                      mh.ak = true;
                    }
                    return mh;
                  });
                  messageStatic = m;
                  receiverStatic = userEnLigne;
                  nonceA = generateNonce();
                  await deroulerProtocole(id, true);
                  isResponsing = r;
                  isDeleteForAll = d;
                }, i * 1000);
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
              console.log(
                messageArrayInClear,
                " merci pour ce tableau avec ton secret dedans, tiens ta nonce:" +
                  noncea +
                  "comme aquit(case 4)"
              );

              let agentName = globalUserName;
              let contentToEncrypt = JSON.stringify([
                agentName,
                noncea,
                messageStatic,
              ]);
              try {
                const kb = await fetchKey(messageSenderInMessage, true, true);
                // We encrypt
                const encryptedMessage = await encryptWithPublicKey(
                  kb,
                  contentToEncrypt
                );
                // And send
                const sendResult = await sendMessage(
                  agentName,
                  messageSenderInMessage,
                  encryptedMessage
                );
                if (!sendResult.success) console.log(sendResult.errorMessage);
                else {
                  console.log("Successfully sent the acquit !");
                }
              } catch (e) {
                if (e instanceof Error) {
                  console.log("error nonce: ", e.message);
                } else {
                  console.log("unexpected error: ", e);
                }
              }
              return [true, messageSender, messageInClear6];
            } else {
              console.log(
                "Real message sender and message sender name in the message do not coincide"
              );
            }
            break;
        }
      } catch (e) {
        console.log("analyseMessage: decryption failed because of " + e);
        return [false, "", ""];
      }
    }
  } catch (e) {
    console.log("analyseMessage: decryption failed because of " + e);
    return [false, "", ""];
  }
}

// action for receiving message
// 1. A -> B: A,{message}Kb
function actionOnMessageOne(fromA: string, messageContent: string) {
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

    let referedMessageTextTag = referedRealMessageTag.getElementsByClassName(
      "messageContent"
    )[0] as HTMLDivElement;

    let referedMessageSenderNameTag =
      referedRealMessageTag.getElementsByClassName(
        "senderName"
      )[0] as HTMLSpanElement;
    rf = {
      id: selectedMessageIdLocal,
      content: referedMessageTextTag.innerText,
      sender: referedMessageSenderNameTag.innerText,
    };
  } else if (messageContent.includes("d&d")) {
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
    nonceDebut: nonceA,
  });
}

//Index of the last read message
let lastIndexInHistory = 0;

// function for refreshing the content of the window (automatic or manual see below)
async function refresh() {
  try {
    const user = globalUserName;
    const historyRequest = new HistoryRequest(user, lastIndexInHistory);
    const urlParams = new URLSearchParams(window.location.search);
    const request = await fetch("/history/" + ownerName + "?" + urlParams, {
      method: "POST",
      body: JSON.stringify(historyRequest),
      headers: {
        "Content-type": "application/json; charset=UTF-8",
      },
    });
    if (!request.ok) {
      throw new Error(`Error! status: ${request.status}`);
    }
    const result = (await request.json()) as HistoryAnswer;
    if (!result.success) {
      alert(result.failureMessage);
    } else {
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
          let [b, sender, msgContent] = await analyseMessage(
            result.allMessages[i]
          );
          if (b) actionOnMessageOne(sender, msgContent);
          else
            console
              .log
              // "Msg " + result.allMessages[i] + " cannot be exploited by " + user
              ();
        }
      }
    }
  } catch (error) {
    if (error instanceof Error) {
      return error.message;
    } else {
      return "An unexpected error occurred";
    }
  }
}

// Automatic refresh: the waiting time is given in milliseconds
const intervalRefresh = setInterval(refresh, 150);

//----------------------reception meme hors connexion---------------------
let lastIndex = localStorage.getItem("lastIndex") || "0";
let messagesHistory: any[] = [];
let isResponsing = false; //if the message is refering another
const reponsea = document.getElementById("reponsea");
const reponseaText = document.getElementById("reponseaText");
let isDeleteForAll = false;
let selectedMessageId: string = "";

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
function getCoresNonceById(id: string): string {
  let res = "";
  corespondanceIDNonce.map((c) => {
    if (c.id == id) {
      res = c.nonce;
    }
  });
  return res;
}
function getCoresIdByNonce(nonce: string) {
  let res = "";
  corespondanceIDNonce.map((c) => {
    if (c.nonce == nonce) {
      res = c.id;
    }
  });
  return res;
}
const corespondanceIDNonceStock = JSON.parse(
  localStorage.getItem("corespondanceIDNonce")
);
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
  localStorage.setItem(
    "corespondanceIDNonce",
    JSON.stringify(corespondanceIDNonce)
  );

  //localStorage.clear();
});
class Attente {
  constructor(public receiver: string, public messages: any[]) {}
}
class FileAttente {
  constructor(public attentes: Attente[]) {}
  //ajouter un historique relatif à un receveur
  addAttente(id: any, receiverToAdd: string, content: string) {
    //response and delete request cases
    if (isResponsing) {
      //if the message i wante to send is refering another
      messageStatic = selectedMessageId + "r&r" + messageStatic;
      isResponsing = false;
    } else if (isDeleteForAll) {
      messageStatic = selectedMessageId + "d&d";
      isDeleteForAll = false;
    }
    //adding
    let exist = -1;
    for (
      let i = 0;
      i < this.attentes.length && this.attentes.length != 0;
      i++
    ) {
      const attenteCourant = this.attentes[i];
      if (receiverToAdd === attenteCourant.receiver) {
        exist = i;
        break;
      }
    }

    if (exist == -1) {
      this.attentes.push(
        new Attente(receiverToAdd, [
          {
            id: id,
            content: content,
            nonceDebut: nonceA,
          },
        ])
      );
    } else {
      this.attentes[exist].messages.push({
        id: id,
        content: content,
        nonceDebut: nonceA,
      });
    }
  }
  getAttenteByReceiver(receiverParam: string): Attente {
    const res = this.attentes.find((a) => {
      return a.receiver === receiverParam;
    });
    return res;
  }
  deleteAttente(receiverToPop: string) {
    fileAttente.attentes = fileAttente.attentes.filter((a: Attente) => {
      return a.receiver != receiverToPop;
    });
  }
}
let contactRequests: ExtMessage[] = [];
setTimeout(async () => {
  const privkey = await fetchKey(globalUserName, false, true);
  const alreadySentTo = []; //to prevent sending multiple connexion signal to the same person
  for (let i = 0; i < contactRequests.length; i++) {
    const contactReq = contactRequests[i];
    if (contactReq == undefined) {
      continue;
    }
    const messageInClearString = await decryptWithPrivateKey(
      privkey,
      contactReq.content
    );

    const messageArrayInClear = JSON.parse(messageInClearString) as string[];
    const messageSenderInMessage = messageArrayInClear[0];
    if (alreadySentTo.includes(messageSenderInMessage)) {
      continue;
    }
    alreadySentTo.push(messageSenderInMessage);
    const kb = await fetchKey(messageSenderInMessage, true, true);

    //signaler que je suis en ligne
    const connexionSignalContent = JSON.stringify([
      globalUserName,
      "en ligne",
      "",
      "",
      "",
    ]);
    const connexionSignalContentEncrypted = await encryptWithPublicKey(
      kb,
      connexionSignalContent
    );
    console.log(messageSenderInMessage, "sait que je suis en ligne");

    await sendMessage(
      globalUserName,
      messageSenderInMessage,
      connexionSignalContentEncrypted
    );
  }

  contactRequests = [];
}, 2000);
const fileAttente: FileAttente = new FileAttente([]);
const fileAttenteStock: FileAttente = JSON.parse(
  localStorage.getItem("fileAttente")
);
if (fileAttenteStock !== null) {
  fileAttenteStock.attentes.map((a: Attente) => {
    a.messages.map((m: any) => {
      fileAttente.addAttente(m.id, a.receiver, m.content);
    });
  });
}
function getRandomNumber(min: number, max: number): string {
  let num = Math.floor(Math.random() * (max - min) + min);
  return "" + num;
}

//submit on click entrer
document.addEventListener("keyup", (e) => {
  if (e.key == "Enter") {
    sendButton.click();
  }
});

function toogleSettings(id: string) {
  selectedMessageId = id;
  let settings = document.getElementById("settings");
  settings.classList.toggle("hidden");

  let m = getMessageFromHistoryByID(id);
  if (m != undefined) {
    let sender = m.sender;
    if (sender != globalUserName) {
      document.getElementById("supPourTous").classList.add("hidden");
    } else {
      document.getElementById("supPourTous").classList.remove("hidden");
    }
  }
}

function deleteForMe() {
  deleteMessageFromHistory(selectedMessageId);
  document.getElementById(selectedMessageId).remove();
  toogleSettings(selectedMessageId);
}

async function deleteForAll() {
  isDeleteForAll = true;
  nonceA = generateNonce();
  fileAttente.addAttente(nonceA, receiverStatic, selectedMessageId + "d&d");
  await deroulerProtocole("", false);
  deleteForMe();
  isDeleteForAll = false;
}

function rep() {
  toogleSettings(selectedMessageId);
  const messageToRepTo = document.getElementById(selectedMessageId);
  const messageContent = messageToRepTo.getElementsByClassName(
    "messageContent"
  )[0] as HTMLDivElement;

  reponseaText.innerText = "Réponse à : " + messageContent.innerText;
  isResponsing = true;
  reponsea.classList.remove("hidden");
}

function annulerRep() {
  selectedMessageId = "";
  isResponsing = false;
  reponsea.classList.add("hidden");
}
function goToMsg(id: string) {
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

const messagesHistoryStock = JSON.parse(
  localStorage.getItem("messagesHistory")
);
if (messagesHistoryStock !== null) {
  messagesHistoryStock.map((mh: any) => {
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

function getMyMessage(message: any): string {
  if (message.content.includes("d&d") || message.content.length == 0) {
    return "";
  }
  //big message case
  let existingMsg = document.getElementById(message.id);
  console.log("getMyMessage exist ", existingMsg);

  if (existingMsg != null) {
    let msgContentTag = existingMsg.getElementsByClassName(
      "messageContent"
    )[0] as HTMLDivElement;
    msgContentTag.innerText += message.content;
    return "";
  }

  let statusColorClasses = "";
  if (message.ak) {
    statusColorClasses = "bg-white text-blue-500";
  } else {
    statusColorClasses = "bg-black text-white";
  }

  let r = "";
  if (message.rf != null) {
    let referedMessageTag = document.getElementById(
      message.rf.id
    ) as HTMLDivElement;
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
<svg onclick="toogleSettings(${
    message.id
  })" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="currentColor" 
class="w-6 h-6 absolute top-1 left-1 cursor-pointer">
<path fill-rule="evenodd" d="M11.078 2.25c-.917 0-1.699.663-1.85 1.567L9.05 4.889c-.02.12-.115.26-.297.348a7.493 7.493 0 0 0-.986.57c-.166.115-.334.126-.45.083L6.3 5.508a1.875 1.875 0 0 0-2.282.819l-.922 1.597a1.875 1.875 0 0 0 .432 2.385l.84.692c.095.078.17.229.154.43a7.598 7.598 0 0 0 0 1.139c.015.2-.059.352-.153.43l-.841.692a1.875 1.875 0 0 0-.432 2.385l.922 1.597a1.875 1.875 0 0 0 2.282.818l1.019-.382c.115-.043.283-.031.45.082.312.214.641.405.985.57.182.088.277.228.297.35l.178 1.071c.151.904.933 1.567 1.85 1.567h1.844c.916 0 1.699-.663 1.85-1.567l.178-1.072c.02-.12.114-.26.297-.349.344-.165.673-.356.985-.57.167-.114.335-.125.45-.082l1.02.382a1.875 1.875 0 0 0 2.28-.819l.923-1.597a1.875 1.875 0 0 0-.432-2.385l-.84-.692c-.095-.078-.17-.229-.154-.43a7.614 7.614 0 0 0 0-1.139c-.016-.2.059-.352.153-.43l.84-.692c.708-.582.891-1.59.433-2.385l-.922-1.597a1.875 1.875 0 0 0-2.282-.818l-1.02.382c-.114.043-.282.031-.449-.083a7.49 7.49 0 0 0-.985-.57c-.183-.087-.277-.227-.297-.348l-.179-1.072a1.875 1.875 0 0 0-1.85-1.567h-1.843ZM12 15.75a3.75 3.75 0 1 0 0-7.5 3.75 3.75 0 0 0 0 7.5Z" clip-rule="evenodd" />
</svg>
<!--sender name-->
<spane id="senderName" class="senderName mx-2 pt-1 underline ">${
    message.sender.split("@")[0]
  }</spane>
<!--sender photo-->
  <img 
  class="rounded-full w-10 h-10"
  alt="photo"
  src="
  data:image/jpeg;base64,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
  " />
</div>  
<!--content-->
<div style="overflow:hidden" class="pr-4 messageContent">${
    message.content
  }</div>

 </div>
 <!--date et heure-->
 <div id="${
   message.id + "date"
 }" class="text-center hidden text-sm text-gray-400" >${message.date}</div>
 </div>`;
}
function getHisMessage(message): string {
  if (message.date == undefined) {
    message.date = getDateFormat();
  }

  //big message case
  let existingMsg = document.getElementById(message.id);
  console.log("getMyMessage exist ", existingMsg);

  if (existingMsg != null) {
    let msgContentTag = existingMsg.getElementsByClassName(
      "messageContent"
    )[0] as HTMLDivElement;
    msgContentTag.innerText += message.content;
    return "";
  }

  let r = "";
  if (message.rf != null) {
    let referedMessageTag = document.getElementById(
      message.rf.id
    ) as HTMLDivElement;
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
    <svg onclick="toogleSettings(${
      message.id
    })" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="currentColor" 
    class="w-6 h-6 absolute top-1 right-1 cursor-pointer">
    <path fill-rule="evenodd" d="M11.078 2.25c-.917 0-1.699.663-1.85 1.567L9.05 4.889c-.02.12-.115.26-.297.348a7.493 7.493 0 0 0-.986.57c-.166.115-.334.126-.45.083L6.3 5.508a1.875 1.875 0 0 0-2.282.819l-.922 1.597a1.875 1.875 0 0 0 .432 2.385l.84.692c.095.078.17.229.154.43a7.598 7.598 0 0 0 0 1.139c.015.2-.059.352-.153.43l-.841.692a1.875 1.875 0 0 0-.432 2.385l.922 1.597a1.875 1.875 0 0 0 2.282.818l1.019-.382c.115-.043.283-.031.45.082.312.214.641.405.985.57.182.088.277.228.297.35l.178 1.071c.151.904.933 1.567 1.85 1.567h1.844c.916 0 1.699-.663 1.85-1.567l.178-1.072c.02-.12.114-.26.297-.349.344-.165.673-.356.985-.57.167-.114.335-.125.45-.082l1.02.382a1.875 1.875 0 0 0 2.28-.819l.923-1.597a1.875 1.875 0 0 0-.432-2.385l-.84-.692c-.095-.078-.17-.229-.154-.43a7.614 7.614 0 0 0 0-1.139c-.016-.2.059-.352.153-.43l.84-.692c.708-.582.891-1.59.433-2.385l-.922-1.597a1.875 1.875 0 0 0-2.282-.818l-1.02.382c-.114.043-.282.031-.449-.083a7.49 7.49 0 0 0-.985-.57c-.183-.087-.277-.227-.297-.348l-.179-1.072a1.875 1.875 0 0 0-1.85-1.567h-1.843ZM12 15.75a3.75 3.75 0 1 0 0-7.5 3.75 3.75 0 0 0 0 7.5Z" clip-rule="evenodd" />
    </svg>
    <!--sender name-->
    <spane class="senderName mx-2 pt-1 underline ">${
      message.sender.split("@")[0]
    }</spane>
  
   </div>
   <div style="overflow:hidden" class="messageContent">${message.content}</div>

   </div> 
   <div id="${
     message.id + "date"
   }" class="text-center hidden text-sm text-gray-400" >${message.date}</div>

   </div>`;
}
function receiverChange() {
  let input = document.getElementById("receiver") as HTMLInputElement;
  receiverStatic = input.value;
  displayOldMessages();
}
function displayOldMessages() {
  let input = document.getElementById("receiver") as HTMLInputElement;
  receiverStatic = input.value;
  received_messages.innerHTML = "";
  //display old messages
  messagesHistory.map((m: any) => {
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
      } else {
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
  var formattedDate =
    year + "/" + month + "/" + day + " " + hours + ":" + minutes;
  return formattedDate;
}
function clickMsg(id) {
  let tag = document.getElementById(id + "date");
  tag.classList.remove("hidden");
  setTimeout(() => {
    tag.classList.add("hidden");
  }, 3000);
}
let lightMode = true;
const switchTheme = () => {
  let theme = document.getElementById("theme");
  let dark = document.getElementById("dark");
  let light = document.getElementById("light");
  if (lightMode) {
    document.body.style.backgroundColor = "black";
    dark.classList.remove("text-black");
    dark.classList.add("text-white");
    light.classList.remove("text-white");
    light.classList.add("text-black");
    theme.style.background = "linear-gradient(90deg,white,black)";
  } else {
    document.body.style.backgroundColor = "white";
    dark.classList.remove("text-white");
    dark.classList.add("text-black");
    light.classList.remove("text-black");
    light.classList.add("text-white");
    theme.style.background = "linear-gradient(90deg,black,white)";
  }
  lightMode = !lightMode;
};
const textTheme = (): string => {
  if (lightMode) {
    return "text-black";
  } else {
    return "text-white";
  }
};

const copier = () => {
  let message = document.getElementById(selectedMessageId);
  let contentDiv = message.getElementsByClassName(
    "messageContent"
  )[0] as HTMLDivElement;
  navigator.clipboard.writeText(contentDiv.innerText);
  toogleSettings(selectedMessageId);
  let copiedMessage = document.getElementById("copiedMessage");
  copiedMessage.classList.remove("hidden");
  setTimeout(() => {
    copiedMessage.classList.add("hidden");
  }, 3000);
};
//scroll to the end of the conv
window.scrollTo(0, document.body.scrollHeight);
