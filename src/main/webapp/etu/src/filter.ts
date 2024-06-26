/* tsc --inlineSourceMap  true -outFile JS/filter.js src/filter.ts --target es2015 */

// Message for user name
class CasUserName {
    constructor(public username: string) { }
}

// Message for application's owner name
class OwnerName {
    constructor(public ownername: string) { }
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

// Filtering of messages
class FilterRequest {
    constructor(public from: string, public to: string, public indexmin: string) { }
}

class FilteredMessage {
    constructor(public message: ExtMessage,
        public index: number,
        public deleted: boolean,
        public deleter: string) { }
}

// Result of filtering request
class FilteringAnswer {
    constructor(public success: boolean,
        public failureMessage: string,
        public allMessages: FilteredMessage[]) { }
}

// Sending a message Result format
class SendResult {
    constructor(public success: boolean, public errorMessage: string) { }
}

class ExtMessage {
    constructor(public sender: string, public receiver: string, public content: string) { }
}

const filterButton = document.getElementById("filter-button") as HTMLButtonElement
const from = document.getElementById("from") as HTMLInputElement
const to = document.getElementById("to") as HTMLInputElement
const indexminElt = document.getElementById("indexmin") as HTMLInputElement
const filtered_messages = document.getElementById("filtered-messages") as HTMLLabelElement

/* Name of the owner/developper of the application, i.e, the name of the folder 
   where the web page of the application is stored. E.g, for teachers' application
   this name is "ens" */

function getOwnerName(): string {
    const path = window.location.pathname
    const name = path.split("/", 2)[1]
    return name
}

let ownerName = getOwnerName()

function clearingMessages() {
    filtered_messages.textContent = ""
}

function stringToHTML(str: string): HTMLDivElement {
    var div_elt = document.createElement('div')
    div_elt.innerHTML = str
    return div_elt
}

function addingFilteredMessage(message: string) {
    filtered_messages.append(stringToHTML('<p></p><p></p>' + message))
}

filterButton.onclick = async function () {
    try {
        const fromText = from.value
        const toText = to.value
        const indexmin = indexminElt.value
        const filterRequest =
            new FilterRequest(fromText, toText, indexmin)
        const urlParams = new URLSearchParams(window.location.search);

        const request = await fetch("/filtering/" + ownerName + "?" + urlParams, {
            method: "POST",
            body: JSON.stringify(filterRequest),
            headers: {
                "Content-type": "application/json; charset=UTF-8"
            }
        });
        if (!request.ok) {
            throw new Error(`Error! status: ${request.status}`);
        }
        const result = (await request.json()) as FilteringAnswer
        if (!result.success) { alert(result.failureMessage) }
        else {
            clearingMessages()
            for (var filt_message of result.allMessages) {
                if (filt_message.deleted) {
                    addingFilteredMessage(`Index: ${filt_message.index} Deleted by: ${filt_message.deleter} <strike> From: ${filt_message.message.sender} To: ${filt_message.message.receiver} Content: ${filt_message.message.content} </strike>`)
                } else {
                    addingFilteredMessage(`Index: ${filt_message.index} From: ${filt_message.message.sender} To: ${filt_message.message.receiver} Content: ${filt_message.message.content}`)
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


