function extractData() {
  const url = window.location.href;
  const hostname = window.location.hostname;
  const domText = document.body.innerText;
  const htmlContent = document.documentElement.outerHTML;
  const title = document.title;

  // Extract all links on the page for feature extraction
  const links = Array.from(document.querySelectorAll('a')).map(a => a.href);

  // Extract favicon URL
  let favicon = null;
  const faviconElement = document.querySelector('link[rel~="icon"]');
  if (faviconElement) {
    favicon = faviconElement.href;
  }

  chrome.runtime.sendMessage({
    type: "PAGE_DATA",
    payload: {
      url,
      hostname,
      domText: domText.slice(0, 5000),        // limit size to avoid large payload
      htmlContent: htmlContent.slice(0, 5000),
      title,
      links,
      favicon,
      
    }
  });
}

extractData();

// Listener to show alert banner if phishing detected
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === "ALERT_USER") {
    showWarningBanner(message.payload.message || "⚠️ This page may be a phishing site!");
  }
});

function showWarningBanner(text) {
  const banner = document.createElement("div");
  banner.innerText = text;
  banner.style.position = "fixed";
  banner.style.top = "0";
  banner.style.left = "0";
  banner.style.right = "0";
  banner.style.backgroundColor = "red";
  banner.style.color = "white";
  banner.style.fontSize = "16px";
  banner.style.fontWeight = "bold";
  banner.style.padding = "10px";
  banner.style.zIndex = "9999";
  banner.style.textAlign = "center";
  banner.style.boxShadow = "0 2px 8px rgba(0,0,0,0.3)";
  document.body.appendChild(banner);
}
