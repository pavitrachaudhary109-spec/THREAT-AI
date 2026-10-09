async function loadThreat() {

    const data = await chrome.storage.local.get([
        "blockedURL",
        "threatResult"
    ]);

    document.getElementById("url").textContent =
        data.blockedURL || "Unknown URL";

    if (data.threatResult) {

        const result = data.threatResult;

        if (result.reasons && result.reasons.length > 0) {

            document.getElementById("reasons").innerHTML =
                result.reasons
                    .map(reason => "• " + reason)
                    .join("<br>");

        } else {

            document.getElementById("reasons").textContent =
                "Multiple suspicious indicators were detected.";
        }
    }
}

loadThreat();