const API_URL = "http://127.0.0.1:8000/analyze";

async function analyzeURL(url) {
    try {
        const response = await fetch(API_URL, {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify({
                message: url
            })
        });

        if (!response.ok) {
            throw new Error("THEREAT AI API error");
        }

        return await response.json();

    } catch (error) {
        console.error("THEREAT AI:", error);
        return null;
    }
}


async function checkCurrentTab(tabId, url) {

    if (!url) return;

    if (
        url.startsWith("chrome://") ||
        url.startsWith("chrome-extension://") ||
        url.startsWith("edge://") ||
        url.startsWith("about:")
    ) {
        return;
    }

    const result = await analyzeURL(url);

    if (!result) {
        return;
    }

    console.log("THEREAT AI result:", result);

    if (result.risk === "HIGH") {

        await chrome.storage.local.set({
            blockedURL: url,
            threatResult: result
        });

        chrome.tabs.update(tabId, {
            url: chrome.runtime.getURL(
                "blocked.html?url=" +
                encodeURIComponent(url)
            )
        });
    }
}


chrome.tabs.onUpdated.addListener(
    (tabId, changeInfo, tab) => {

        if (changeInfo.status === "loading" && tab.url) {
            checkCurrentTab(tabId, tab.url);
        }
    }
);