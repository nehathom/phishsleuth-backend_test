document.addEventListener('DOMContentLoaded', () => {
  chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
    const tab = tabs[0];
    if (!tab) return;

    chrome.runtime.sendMessage(
      { type: "GET_ANALYSIS", tabId: tab.id },
      (response) => {
        if (!response || !response.success) {
          document.getElementById("result").innerText = "Failed to get analysis";
          return;
        }

        const topShap = response.data.top_shap_features;
        if (!topShap) {
          document.getElementById("result").innerText = "No SHAP explanations received";
          return;
        }

        const explanations = Object.entries(topShap)
          .slice(0, 3)
          .map(([feature, { shap_value, explanation }]) =>
            `${feature}: ${shap_value.toFixed(3)}\n${explanation}`
          )
          .join("\n\n");

        document.getElementById("result").innerText = explanations;
      }
    );
  });
});
