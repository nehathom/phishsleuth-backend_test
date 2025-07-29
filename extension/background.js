chrome.runtime.onMessage.addListener(async (message, sender, sendResponse) => {
  if (message.type === "PAGE_DATA") {
    const tabId = sender.tab.id;

    const features = extractFeatures({
      url: message.payload.url,
      hostname: message.payload.hostname,
      ...message.payload,
    });

    console.log("Sending features:", features);

    try {
      const response = await fetch("http://127.0.0.1:8000/analyze", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(features)
      });

      const { prediction } = await response.json();

      if (prediction === "phishing") {
        chrome.tabs.sendMessage(tabId, {
          type: "ALERT_USER",
          payload: { message: "⚠️ This page may be a phishing site!" }
        }, (resp) => {
          if (chrome.runtime.lastError) {
            console.warn("Message failed:", chrome.runtime.lastError.message);
          }
        });
      }

    } catch (err) {
      console.error("Error during prediction fetch:", err);
    }
  }
});



function extractFeatures(payload) {
  const { url, hostname, domText, htmlContent, title, links, favicon } = payload || {};

  // Helpers
  const isValidString = (str) => typeof str === 'string' && str.trim().length > 0;
  const countOccurrences = (str, regex) => isValidString(str) ? (str.match(regex) || []).length : 0;
  const safeUrl = isValidString(url) ? url : '';
  const safeHostname = isValidString(hostname) ? hostname : '';

  // Count subdomains
  function countSubdomains(hostname) {
    if (!isValidString(hostname)) return 0;
    const parts = hostname.toLowerCase().split('.');

    const multiLevelTLDs = ['co.uk', 'org.uk', 'gov.uk', 'ac.uk', 'co.jp', 'co.in', 'com.au'];
    const lastTwo = parts.slice(-2).join('.');
    const isMultiLevel = multiLevelTLDs.includes(lastTwo);

    if (isMultiLevel) {
      return parts.length > 3 ? parts.length - 3 : 0;
    } else {
      return parts.length > 2 ? parts.length - 2 : 0;
    }
  }
  const nb_subdomains = countSubdomains(safeHostname);

  // URL basic parts
  const urlObj = new URL(safeUrl);
  
  // Check if domain is IP address
  const IsDomainIP = /^(\d{1,3}\.){3}\d{1,3}$/.test(safeHostname) ? 1 : 0;

  // Has HTTPS
  const IsHTTPS = urlObj.protocol === "https:" ? 1 : 0;

  // Count special characters in URL
  const NoOfEqualsInURL = countOccurrences(safeUrl, /=/g);
  const NoOfQMarkInURL = countOccurrences(safeUrl, /\?/g);
  const NoOfAmpersandInURL = countOccurrences(safeUrl, /&/g);
  const NoOfOtherSpecialCharsInURL = countOccurrences(safeUrl, /[^a-zA-Z0-9\-._~:/?#[\]@!$&'()*+,;=%]/g); // rough estimate
  const SpacialCharRatioInURL = safeUrl.length > 0 ? NoOfOtherSpecialCharsInURL / safeUrl.length : 0;

  // Letters and digits in URL
  const letters = (safeUrl.match(/[a-zA-Z]/g) || []).length;
  const digits = (safeUrl.match(/\d/g) || []).length;
  const NoOfLettersInURL = letters;
  const LetterRatioInURL = safeUrl.length > 0 ? letters / safeUrl.length : 0;
  const NoOfDegitsInURL = digits;
  const DegitRatioInURL = safeUrl.length > 0 ? digits / safeUrl.length : 0;

  // Obfuscation features (simple heuristic)
  const HasObfuscation = (safeUrl.includes("@") || safeUrl.includes("//")) ? 1 : 0;
  const NoOfObfuscatedChar = countOccurrences(safeUrl, /[@\/]/g);
  const ObfuscationRatio = safeUrl.length > 0 ? NoOfObfuscatedChar / safeUrl.length : 0;

  // Title info
  const HasTitle = isValidString(title) ? 1 : 0;
  // DomainTitleMatchScore and URLTitleMatchScore are harder, simplistic version:
  const DomainTitleMatchScore = HasTitle && safeHostname && title.toLowerCase().includes(safeHostname.toLowerCase()) ? 1.0 : 0.0;
  const URLTitleMatchScore = HasTitle && safeUrl && title.toLowerCase().includes(safeUrl.toLowerCase()) ? 1.0 : 0.0;

  // Check robots meta tag
  const Robots = /<meta\s+name=["']robots["']\s+content=["'][^"']*noindex[^"']*["']\s*\/?>/i.test(htmlContent) ? 1 : 0;

  // Check responsive design presence (viewport meta)
  const IsResponsive = /<meta\s+name=["']viewport["']\s+content=["'][^"']*width=device-width[^"']*["']\s*\/?>/i.test(htmlContent) ? 1 : 0;

  // Count redirects, iframe, popup, submit buttons, password fields from DOM/text
  // These require more complex scripts or external HTTP request for redirects
  // For simplicity, set defaults or heuristics here:
  const NoOfURLRedirect = 0; // could be improved with fetch + redirects
  const NoOfSelfRedirect = 0;
  const NoOfPopup = countOccurrences(domText, /popup/i);
  const NoOfiFrame = countOccurrences(htmlContent, /<iframe\b/i);
  const HasExternalFormSubmit = /<form[^>]+action=["']http/i.test(htmlContent) ? 1 : 0;
  const HasSubmitButton = /<input[^>]+type=["']submit["']/i.test(htmlContent) ? 1 : 0;
  const HasHiddenFields = /<input[^>]+type=["']hidden["']/i.test(htmlContent) ? 1 : 0;
  const HasPasswordField = /<input[^>]+type=["']password["']/i.test(htmlContent) ? 1 : 0;

  // Brand, Bank, Pay, Crypto, HasCopyrightInfo, etc. could be keyword checks on URL or text
  // Simplified versions (replace with real lists):
  const brandKeywords = ["amazon", "paypal", "google", "microsoft"];
  const Bank = brandKeywords.some(k => safeUrl.toLowerCase().includes(k)) ? 1 : 0;
  const Pay = safeUrl.toLowerCase().includes("pay") ? 1 : 0;
  const Crypto = safeUrl.toLowerCase().includes("crypto") ? 1 : 0;
  const HasCopyrightInfo = /©|copyright/i.test(domText) ? 1 : 0;

  // Count assets
  const NoOfImage = countOccurrences(htmlContent, /<img\b/i);
  const NoOfCSS = countOccurrences(htmlContent, /<link[^>]+rel=["']stylesheet["']/i);
  const NoOfJS = countOccurrences(htmlContent, /<script\b/i);

  // Refs counts (rough heuristic)
  const NoOfSelfRef = countOccurrences(htmlContent, /href=["']#["']/i);
  const NoOfEmptyRef = countOccurrences(htmlContent, /href=["']["']/i);
  const NoOfExternalRef = countOccurrences(htmlContent, new RegExp(`href=["']https?://(?!${safeHostname.replace(/\./g, "\\.")})`, "i"));

  return {
  URLLength: safeUrl.length,                             // int
  DomainLength: safeHostname.length,                     // int
  IsDomainIP: IsDomainIP,                                // int (0 or 1)
  NoOfSubDomain: nb_subdomains,                          // int
  HasObfuscation: HasObfuscation,                        // int (0 or 1)
  NoOfObfuscatedChar: NoOfObfuscatedChar,                // int
  ObfuscationRatio: ObfuscationRatio,                    // float
  NoOfLettersInURL: NoOfLettersInURL,                    // int
  LetterRatioInURL: LetterRatioInURL,                    // float
  NoOfDegitsInURL: NoOfDegitsInURL,                      // int (keep typo if model expects it)
  DegitRatioInURL: DegitRatioInURL,                      // float
  NoOfEqualsInURL: NoOfEqualsInURL,                      // int
  NoOfQMarkInURL: NoOfQMarkInURL,                        // int
  NoOfAmpersandInURL: NoOfAmpersandInURL,                // int
  NoOfOtherSpecialCharsInURL: NoOfOtherSpecialCharsInURL,// int
  SpacialCharRatioInURL: SpacialCharRatioInURL,          // float
  IsHTTPS: IsHTTPS,                                      // int (0 or 1)
  LineOfCode: domText ? domText.split('\n').length : 0, // int
  LargestLineLength: domText ? Math.max(...domText.split('\n').map(l => l.length)) : 0, //int
  HasFavicon: favicon ? 1 : 0,                           // int (0 or 1)
  Robots: Robots,                                        // int (0 or 1)
  IsResponsive: IsResponsive,                            // int (0 or 1)
  NoOfURLRedirect: 0,                                    // int (default)
  NoOfSelfRedirect: 0,                                   // int (default)
  HasDescription: /<meta\s+name=["']description["']\s+content=["'][^"']+["']\s*\/?>/i.test(htmlContent) ? 1 : 0, // int (0 or 1)
  NoOfPopup: NoOfPopup,                                  // int
  NoOfiFrame: NoOfiFrame,                                // int
  HasExternalFormSubmit: HasExternalFormSubmit,          // int (0 or 1)
  HasSocialNet: /<a[^>]+href=["']https?:\/\/(www\.)?(facebook|twitter|instagram|linkedin|youtube)\.com/i.test(htmlContent) ? 1 : 0, // int (0 or 1)
  HasSubmitButton: HasSubmitButton,                      // int (0 or 1)
  HasHiddenFields: HasHiddenFields,                      // int (0 or 1)
  HasPasswordField: HasPasswordField,                    // int (0 or 1)
  Bank: Bank,                                            // int (0 or 1)
  Pay: Pay,                                              // int (0 or 1)
  Crypto: Crypto,                                        // int (0 or 1)
  HasCopyrightInfo: HasCopyrightInfo,                    // int (0 or 1)
  NoOfImage: NoOfImage,                                  // int
  NoOfCSS: NoOfCSS,                                      // int
  NoOfJS: NoOfJS,                                        // int
  NoOfSelfRef: NoOfSelfRef,                              // int
  NoOfEmptyRef: NoOfEmptyRef,                            // int
  NoOfExternalRef: NoOfExternalRef                       // int
};

}
