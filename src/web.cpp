#include "web.h"

#ifdef ESP32_C6_ASYNC_WEB
AsyncWebServer *WebManager::server = nullptr;
#else
HTTPServer *WebManager::server = nullptr;
uint8_t *WebManager::certData = nullptr;
uint8_t *WebManager::pkData = nullptr;
SSLCert *WebManager::cert = nullptr;
HTTPSServer *WebManager::serverSecure = nullptr;
#endif
bool WebManager::rebootRequired = false;
bool WebManager::rebootNextLoop = false;
uint8_t *WebManager::buffer = new uint8_t[ESP_GW_WEBSERVER_BUFFER_SIZE];

bool WebManager::init()
{
#ifdef ESP32_C6_ASYNC_WEB
  // ESP32-C6: AsyncWebServer (HTTP-only, no HTTPS due to mbedtls compatibility)
  Serial.println("Starting AsyncWebServer (HTTP-only for ESP32-C6)");
  
  // Mount SPIFFS once
  if (!SPIFFS.begin(true))
  {
    Serial.println("Failed to mount SPIFFS");
    return false;
  }
  Serial.println("SPIFFS mounted");
  
  server = new AsyncWebServer(ESP_GW_WEBSERVER_PORT);
  
  // Handle root
  server->on("/", HTTP_GET, handleHome);
  
  // Handle config GET
  server->on("/config", HTTP_GET, handleConfigGet);
  
  // Handle config POST with body
  server->on("/config", HTTP_POST, 
    [](AsyncWebServerRequest *request) {
      // This is called after body handler completes
      request->send(200, "text/plain", "OK");
    },
    NULL,
    handleConfigSet);
  
  // Handle factory reset
  server->on("/factoryReset", HTTP_GET, handleFactoryReset);
  
  // Handle 404
  server->onNotFound(handleNotFound);
  
  server->begin();
  Serial.println("AsyncWebServer started on port " + String(ESP_GW_WEBSERVER_PORT));
  meminfo();
#else
  if (!initCertificate())
  {
    Serial.println("Could not init HTTPS certificate");
    return false;
  }

  serverSecure = new HTTPSServer(cert, ESP_GW_WEBSERVER_SECURE_PORT, 1);
  serverSecure->addMiddleware(middlewareAuthentication);
  serverSecure->registerNode(new ResourceNode("/", "GET", handleHome));
  serverSecure->registerNode(new ResourceNode("/config", "GET", handleConfigGet));
  serverSecure->registerNode(new ResourceNode("/config", "POST", handleConfigSet));
  serverSecure->registerNode(new ResourceNode("/factoryReset", "GET", handleFactoryReset));
  serverSecure->setDefaultNode(new ResourceNode("", "", handleNotFound));
  serverSecure->start();

  Serial.println("HTTPS started");
  meminfo();

  server = new HTTPServer(ESP_GW_WEBSERVER_PORT, 1);
  server->setDefaultNode(new ResourceNode("", "", handleRedirect));
  server->start();
  Serial.println("HTTP started");
  meminfo();
#endif

  return true;
}

void WebManager::loop()
{
  if (rebootRequired)
  {
    // delay the reboot one more loop
    if (rebootNextLoop)
    {
      ESP.restart();
    }
    rebootNextLoop = true;
  }
#ifndef ESP32_C6_ASYNC_WEB
  server->loop();
  serverSecure->loop();
#endif
  // AsyncWebServer handles requests automatically, no loop() needed
}

#ifndef ESP32_C6_ASYNC_WEB
bool WebManager::initCertificate()
{
  if (GwSettings::hasCert())
  {
    Serial.println("Loading stored HTTPS certificate");

    // if name does not match the certificate name, don't load but regenerate instead
    if (strcmp(GwSettings::getCertName(), GwSettings::getName()) == 0)
    {
      Serial.printf("Loaded cert from nvs [%s.local][cert=%d][pk=%d]\n",
                    GwSettings::getCertName(),
                    GwSettings::getCertLen(),
                    GwSettings::getPkLen());

      cert = new SSLCert(GwSettings::getCert(), GwSettings::getCertLen(), GwSettings::getPk(), GwSettings::getPkLen());
    }
  }

  if (cert == nullptr)
  {
    // requires larger stack #define CONFIG_ARDUINO_LOOP_STACK_SIZE 10240
    // should run this in a separate task as sdk can't be configured via platformio.ini
    Serial.println("Generating new HTTPS certificate");

    cert = new SSLCert();
    std::string dn = "CN=";
    dn += GwSettings::getName();
    dn += ".local,O=FancyCompany,C=RO";
    int createCertResult = createSelfSignedCert(
        *cert,
        KEYSIZE_2048,
        dn,
        "20190101000000",
        "20300101000000");

    if (createCertResult != 0)
    {
      Serial.printf("Cerating certificate failed. Error Code = 0x%02X, check SSLCert.hpp for details", createCertResult);
      return false;
    }
    Serial.printf("Creating the certificate was successful [%s.local][cert=%d][pk=%d]\n", GwSettings::getName(), cert->getCertLength(), cert->getPKLength());
    GwSettings::setCertName(GwSettings::getName(), GwSettings::getNameLen());
    GwSettings::setCert(cert->getCertData(), cert->getCertLength());
    GwSettings::setPk(cert->getPKData(), cert->getPKLength());
  }

  return true;
}

void WebManager::middlewareAuthentication(HTTPRequest *req, HTTPResponse *res, std::function<void()> next)
{
  Serial.println("Auth middleware started");
  std::string reqPassword = req->getBasicAuthPassword();

  if (reqPassword.length() == 0 || strcmp(GwSettings::getPassword(), reqPassword.c_str()) != 0)
  {
    res->setStatusCode(401);
    res->setStatusText("Unauthorized");
    res->setHeader("Content-Type", "text/plain");
    res->setHeader("WWW-Authenticate", "Basic realm=\"Gateway admin area\"");
    res->println("401. Unauthorized (defaults are admin/admin)");
    Serial.println("Auth failed");
  }
  else
  {
    Serial.println("Auth success");
    next();
  }
}

void WebManager::handleHome(HTTPRequest *req, HTTPResponse *res)
{
  res->setHeader("Content-Type", "text/html");
  res->setHeader("Content-Encoding", "gzip");

  SPIFFS.begin();
  File file = SPIFFS.open("/index.html.gz", "r");
  size_t length = 0;
  do
  {
    length = file.read(buffer, ESP_GW_WEBSERVER_BUFFER_SIZE);
    res->write(buffer, length);
  } while (length > 0);
  file.close();
  SPIFFS.end();

  meminfo();
}

void WebManager::handleConfigGet(HTTPRequest *req, HTTPResponse *res)
{
  res->setHeader("Content-Type", "application/json");
  res->setHeader("Connection", "close");

  StaticJsonDocument<128> config;

  config["name"] = GwSettings::getName();

  if (GwSettings::getSsidLen() > 0)
  {
    config["wifi_ssid"] = GwSettings::getSsid();
  }

  if (GwSettings::getPassLen() > 0)
  {
    config["wifi_pass"] = GwSettings::getPass();
  }

  config["aes_key"] = GwSettings::getAes();

  size_t configLength = serializeJson(config, buffer, ESP_GW_WEBSERVER_BUFFER_SIZE);
  config.clear();

  res->write((uint8_t *)buffer, configLength);

  meminfo();
}

void WebManager::handleConfigSet(HTTPRequest *req, HTTPResponse *res)
{
  res->setHeader("Connection", "close");

  size_t idx = 0;
  while (!req->requestComplete() && idx < ESP_GW_WEBSERVER_BUFFER_SIZE)
  {
    idx += req->readChars((char *)buffer + idx, ESP_GW_WEBSERVER_BUFFER_SIZE - idx);
  }

  if (!req->requestComplete())
  {
    Serial.println("Request entity too large");
    Serial.println((char *)buffer);
    res->setStatusCode(413);
    res->setStatusText("Request entity too large");
    res->println("413 Request entity too large");
    return;
  }

  buffer[idx + 1] = '\0';

  StaticJsonDocument<128> config;
  DeserializationError error = deserializeJson(config, buffer, idx + 1);

  if (error != DeserializationError::Ok)
  {
    Serial.println("Invalid JSON format");
    Serial.println((char *)buffer);
    res->setStatusCode(400);
    res->setStatusText("Invalid JSON format");
    res->println("400 Invalid JSON format");
    return;
  }

  Serial.println("Checking for config changes");

  const char *name = config["name"];
  if (name && strlen(name) > 0)
  {
    Serial.printf("Setting new name [%s]\n", name);
    GwSettings::setName(name, strlen(name) + 1);
    rebootRequired = true;
  }

  const char *newPassword = config["password"];
  if (newPassword && strlen(newPassword) > 0)
  {
    Serial.printf("Setting new admin password [%s]\n", newPassword);
    GwSettings::setPassword(newPassword, strlen(newPassword) + 1);
    rebootRequired = true;
  }

  const char *ssid = config["wifi_ssid"];
  if (ssid && strlen(ssid) > 0)
  {
    Serial.printf("Setting new WiFi SSID [%s]\n", ssid);
    GwSettings::setSsid(ssid, strlen(ssid) + 1);
    rebootRequired = true;
  }

  const char *pass = config["wifi_pass"];
  if (pass && strlen(pass) > 0)
  {
    Serial.printf("Setting new WiFi Password [%s]\n", pass);
    GwSettings::setPass(pass, strlen(pass) + 1);
    rebootRequired = true;
  }

  res->setHeader("Content-Type", "text/plain");
  res->setStatusCode(200);
  res->setStatusText("OK");
  res->print("OK");

  if (rebootRequired)
  {
    Serial.println("Rebooting");
  }
  meminfo();
}

void WebManager::handleFactoryReset(HTTPRequest *req, HTTPResponse *res)
{
  GwSettings::clear();
  res->setHeader("Content-Type", "text/html");
  res->setHeader("Connection", "close");
  res->setStatusCode(200);
  res->setStatusText("OK");
  res->print("OK");

  Serial.println("Rebooting");
  rebootRequired = true;
}

void WebManager::handleRedirect(HTTPRequest *req, HTTPResponse *res)
{
  res->setHeader("Connection", "close");

  std::string dn;
  dn = "https://";
  dn += GwSettings::getName();
  dn += ".local";
  res->setHeader("Location", dn);
  res->setStatusCode(301);
  res->setStatusText("Moved Permanently");
}

void WebManager::handleNotFound(HTTPRequest *req, HTTPResponse *res)
{
  res->setHeader("Content-Type", "text/html");
  res->setHeader("Connection", "close");
  res->setStatusCode(404);
  res->setStatusText("NOT FOUND");
  res->println("NOT FOUND");
}
#else
// ESP32-C6 AsyncWebServer implementations

bool WebManager::checkAuthentication(AsyncWebServerRequest *request)
{
  if (!request->authenticate("admin", GwSettings::getPassword()))
  {
    request->requestAuthentication();
    Serial.println("Auth failed");
    return false;
  }
  Serial.println("Auth success");
  return true;
}

void WebManager::handleHome(AsyncWebServerRequest *request)
{
  if (!checkAuthentication(request)) return;
  
  if (!SPIFFS.exists("/index.html.gz"))
  {
    Serial.println("File /index.html.gz not found");
    request->send(404, "text/plain", "File not found");
    return;
  }
  
  AsyncWebServerResponse *response = request->beginResponse(SPIFFS, "/index.html.gz", "text/html");
  response->addHeader("Content-Encoding", "gzip");
  request->send(response);
  
  Serial.println("Sent index.html.gz");
  meminfo();
}

void WebManager::handleConfigGet(AsyncWebServerRequest *request)
{
  if (!checkAuthentication(request)) return;
  
  StaticJsonDocument<128> config;

  config["name"] = GwSettings::getName();

  if (GwSettings::getSsidLen() > 0)
  {
    config["wifi_ssid"] = GwSettings::getSsid();
  }

  if (GwSettings::getPassLen() > 0)
  {
    config["wifi_pass"] = GwSettings::getPass();
  }

  config["aes_key"] = GwSettings::getAes();

  size_t configLength = serializeJson(config, buffer, ESP_GW_WEBSERVER_BUFFER_SIZE);
  config.clear();

  AsyncWebServerResponse *response = request->beginResponse(200, "application/json", String((char*)buffer));
  response->addHeader("Connection", "close");
  request->send(response);

  meminfo();
}

void WebManager::handleConfigSet(AsyncWebServerRequest *request, uint8_t *data, size_t len, size_t index, size_t total)
{
  if (!checkAuthentication(request)) return;
  
  // Copy data to buffer
  if (index == 0)
  {
    memset(buffer, 0, ESP_GW_WEBSERVER_BUFFER_SIZE);
  }
  
  if (index + len > ESP_GW_WEBSERVER_BUFFER_SIZE)
  {
    Serial.println("Request entity too large");
    request->send(413, "text/plain", "413 Request entity too large");
    return;
  }
  
  memcpy(buffer + index, data, len);
  
  // Process when all data received
  if (index + len == total)
  {
    buffer[total] = '\0';

    StaticJsonDocument<128> config;
    DeserializationError error = deserializeJson(config, buffer, total);

    if (error != DeserializationError::Ok)
    {
      Serial.println("Invalid JSON format");
      Serial.println((char *)buffer);
      request->send(400, "text/plain", "400 Invalid JSON format");
      return;
    }

    Serial.println("Checking for config changes");

    const char *name = config["name"];
    if (name && strlen(name) > 0)
    {
      Serial.printf("Setting new name [%s]\n", name);
      GwSettings::setName(name, strlen(name) + 1);
      rebootRequired = true;
    }

    const char *newPassword = config["password"];
    if (newPassword && strlen(newPassword) > 0)
    {
      Serial.printf("Setting new admin password [%s]\n", newPassword);
      GwSettings::setPassword(newPassword, strlen(newPassword) + 1);
      rebootRequired = true;
    }

    const char *ssid = config["wifi_ssid"];
    if (ssid && strlen(ssid) > 0)
    {
      Serial.printf("Setting new WiFi SSID [%s]\n", ssid);
      GwSettings::setSsid(ssid, strlen(ssid) + 1);
      rebootRequired = true;
    }

    const char *pass = config["wifi_pass"];
    if (pass && strlen(pass) > 0)
    {
      Serial.printf("Setting new WiFi Password [%s]\n", pass);
      GwSettings::setPass(pass, strlen(pass) + 1);
      rebootRequired = true;
    }

    if (rebootRequired)
    {
      Serial.println("Rebooting");
    }
    meminfo();
  }
}

void WebManager::handleFactoryReset(AsyncWebServerRequest *request)
{
  if (!checkAuthentication(request)) return;
  
  GwSettings::clear();
  request->send(200, "text/plain", "OK");

  Serial.println("Rebooting");
  rebootRequired = true;
}

void WebManager::handleNotFound(AsyncWebServerRequest *request)
{
  request->send(404, "text/html", "NOT FOUND");
}
#endif
