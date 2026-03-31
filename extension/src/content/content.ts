//interface describes what an object looks like
// This says: "The data we extract will always have a 'url' string
// and a 'textContent' string." This helps catch mistakes early --
// if we accidentally forget one of these fields, TypeScript will
// warn us before we even run the code.

interface PageData {
    url: string;
    textContent: string;
}

//function that reads page content
//grabs:(1) current page URL & (2) visible text on page
//trimming text and cap it to 5000 characters to avoid sending too much data to the server

function extractPageData(): PageData {
    const url = window.location.href;
    const rawText: string = document.body.innerText || "";
    const textContent: string = rawText.trim().substring(0,5000);
    
    return {
        url: url,
        textContent: textContent
    };
}

// Listen for messages from the popup script
// chrome.runtime.onMessage is Chrome's messaging system.
// When the popup sends a message, this listener receives it

//listener receives:
//message = data sent by popup
//sender = info about who sent message
//sendResponse = function to send a reply back to the popup

chrome.runtime.onMessage.addListener(
   (
     message: { action: string },
     sender: chrome.runtime.MessageSender,
     sendResponse: (response:PageData) => void
   ) => {
     if (message.action === "scanPage") {
        const pageData = extractPageData();
        sendResponse(pageData);
     }
     return true;
 } 
);