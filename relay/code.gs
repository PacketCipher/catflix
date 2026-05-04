// code.gs – CatFlix relay (return base64 of backend response)
const SCRIPT_PROPS = PropertiesService.getScriptProperties();
const BACKEND_URL = SCRIPT_PROPS.getProperty('BACKEND_URL');

function doGet(e) {
  return _handleRequest(e);
}

function doPost(e) {
  return _handleRequest(e);
}

function _handleRequest(e) {
  e = e || {};
  var q = e.parameter && e.parameter.q;
  if (!q && e.postData && e.postData.contents) {
    var parts = e.postData.contents.split('=');
    if (parts.length > 1) {
      q = decodeURIComponent(parts.slice(1).join('=').replace(/\+/g, ' '));
    }
  }
  if (!BACKEND_URL) {
    return ContentService.createTextOutput("FATAL: BACKEND_URL not set");
  }
  if (q !== undefined && q !== null && q !== '') {
    const options = {
      method: 'post',
      payload: JSON.stringify({ q: q }),
      contentType: 'application/json',
      muteHttpExceptions: true,
      followRedirects: false
    };
    try {
      const response = UrlFetchApp.fetch(BACKEND_URL, options);
      const bodyBinary = response.getContent();
      const bodyBase64 = Utilities.base64Encode(bodyBinary);
      console.log("Relay: status=" + response.getResponseCode() + " size=" + bodyBinary.length);
      return ContentService.createTextOutput(bodyBase64)
        .setMimeType(ContentService.MimeType.TEXT);
    } catch (err) {
      console.error("UrlFetchApp error: " + err);
      return ContentService.createTextOutput("Relay Error: " + err.toString());
    }
  }
  try {
    const template = HtmlService.createTemplateFromFile('Index');
    template.BACKEND_URL = BACKEND_URL;
    return template.evaluate()
      .setTitle('😺 CatFlix – Endless Cat Stream')
      .setFaviconUrl('https://ssl.gstatic.com/docs/script/images/favicon.ico')
      .setXFrameOptionsMode(HtmlService.XFrameOptionsMode.ALLOWALL);
  } catch (htmlError) {
    return HtmlService.createHtmlOutput('<h1>Error</h1><p>' + htmlError.toString() + '</p>');
  }
}
