var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
/* tsc --inlineSourceMap  true -outFile JS/filter.js src/filter.ts --target es2015 */
// Message for user name
class CasUserName {
    constructor(username) {
        this.username = username;
    }
}
// Message for application's owner name
class OwnerName {
    constructor(ownername) {
        this.ownername = ownername;
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
class ExtMessage {
    constructor(sender, receiver, content) {
        this.sender = sender;
        this.receiver = receiver;
        this.content = content;
    }
}
const filterButton = document.getElementById("filter-button");
const from = document.getElementById("from");
const to = document.getElementById("to");
const indexminElt = document.getElementById("indexmin");
const filtered_messages = document.getElementById("filtered-messages");
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
filterButton.onclick = function () {
    return __awaiter(this, void 0, void 0, function* () {
        try {
            const fromText = from.value;
            const toText = to.value;
            const indexmin = indexminElt.value;
            const filterRequest = new FilterRequest(fromText, toText, indexmin);
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
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiZmlsdGVyLmpzIiwic291cmNlUm9vdCI6IiIsInNvdXJjZXMiOlsiLi4vc3JjL2ZpbHRlci50cyJdLCJuYW1lcyI6W10sIm1hcHBpbmdzIjoiOzs7Ozs7Ozs7QUFBQSxxRkFBcUY7QUFFckYsd0JBQXdCO0FBQ3hCLE1BQU0sV0FBVztJQUNiLFlBQW1CLFFBQWdCO1FBQWhCLGFBQVEsR0FBUixRQUFRLENBQVE7SUFBSSxDQUFDO0NBQzNDO0FBRUQsdUNBQXVDO0FBQ3ZDLE1BQU0sU0FBUztJQUNYLFlBQW1CLFNBQWlCO1FBQWpCLGNBQVMsR0FBVCxTQUFTLENBQVE7SUFBSSxDQUFDO0NBQzVDO0FBRUQsZ0NBQWdDO0FBQ2hDLE1BQU0sY0FBYztJQUNoQixZQUFtQixTQUFpQixFQUFTLEtBQWE7UUFBdkMsY0FBUyxHQUFULFNBQVMsQ0FBUTtRQUFTLFVBQUssR0FBTCxLQUFLLENBQVE7SUFBSSxDQUFDO0NBQ2xFO0FBRUQsNEJBQTRCO0FBQzVCLE1BQU0sYUFBYTtJQUNmLFlBQW1CLE9BQWdCLEVBQ3hCLGNBQXNCLEVBQ3RCLEtBQWEsRUFDYixXQUF5QjtRQUhqQixZQUFPLEdBQVAsT0FBTyxDQUFTO1FBQ3hCLG1CQUFjLEdBQWQsY0FBYyxDQUFRO1FBQ3RCLFVBQUssR0FBTCxLQUFLLENBQVE7UUFDYixnQkFBVyxHQUFYLFdBQVcsQ0FBYztJQUFJLENBQUM7Q0FDNUM7QUFFRCx3QkFBd0I7QUFDeEIsTUFBTSxhQUFhO0lBQ2YsWUFBbUIsSUFBWSxFQUFTLEVBQVUsRUFBUyxRQUFnQjtRQUF4RCxTQUFJLEdBQUosSUFBSSxDQUFRO1FBQVMsT0FBRSxHQUFGLEVBQUUsQ0FBUTtRQUFTLGFBQVEsR0FBUixRQUFRLENBQVE7SUFBSSxDQUFDO0NBQ25GO0FBRUQsTUFBTSxlQUFlO0lBQ2pCLFlBQW1CLE9BQW1CLEVBQzNCLEtBQWEsRUFDYixPQUFnQixFQUNoQixPQUFlO1FBSFAsWUFBTyxHQUFQLE9BQU8sQ0FBWTtRQUMzQixVQUFLLEdBQUwsS0FBSyxDQUFRO1FBQ2Is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