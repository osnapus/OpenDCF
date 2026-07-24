/*
  ============================================================
  OpenDCF NTP Server na WT32-ETH01
  Wersja 1.0.0

  Funkcje:
  - Ethernet LAN8720
  - statyczny adres IPv4
  - DS3231 przez I2C
  - WWW: status i ustawianie czasu UTC
  - własny serwer NTP/SNTP UDP port 123
  - statystyki zapytań NTP
  - diagnostyka sygnału DCF77 na GPIO35
  - pełne dekodowanie ramek czasu DCF77
  - kontrola parzystości, daty i strefy CET/CEST
  - synchronizacja DS3231 po 3 kolejnych pełnych poprawnych ramkach
  - limit dopuszczalnej różnicy RTC/DCF77: 10 minut
  - obsługa pamięci 24C32
  - trwała konfiguracja z CRC32
  - trwałe statystyki synchronizacji DCF77

  DS3231 przechowuje UTC.

  Połączenie DS3231:
  VCC -> 3V3
  GND -> GND
  SDA -> GPIO33 / 485_EN
  SCL -> GPIO32 / CFG
  SQW -> GPIO36 / IO36, podciągnięcie 4,7-10 kΩ do 3,3 V
  DCF77 DATA -> dzielnik 5 V / 3,3 V -> GPIO35 / IO35
  ============================================================
*/

#include <Arduino.h>

#define ETH_PHY_TYPE  ETH_PHY_LAN8720
#define ETH_PHY_ADDR  1
#define ETH_PHY_MDC   23
#define ETH_PHY_MDIO  18
#define ETH_PHY_POWER 16
#define ETH_CLK_MODE  ETH_CLOCK_GPIO0_IN

#include <ETH.h>
#include <WebServer.h>
#include <NetworkUdp.h>
#include <Wire.h>
#include <RTClib.h>
#include <esp_timer.h>
#include <esp_system.h>
#include <mbedtls/sha256.h>

struct NtpTimestamp
{
  uint32_t seconds;
  uint32_t fraction;
};

struct DcfDecodedTime
{
  bool valid;
  uint16_t year;
  uint8_t month;
  uint8_t day;
  uint8_t weekday;
  uint8_t hour;
  uint8_t minute;
  bool cest;
  bool cet;
  bool dstChangeAnnouncement;
  bool leapSecondAnnouncement;
  bool minuteParityOk;
  bool hourParityOk;
  bool dateParityOk;
  uint32_t localUnix;
  uint32_t utcUnix;
};


struct __attribute__((packed)) OpenDcfPersistentConfig
{
  char magic[4];                 // "ODCF"
  uint16_t formatVersion;        // wersja formatu EEPROM
  uint16_t structureSize;
  uint32_t crc32;

  char hostname[32];
  uint8_t useDhcp;
  uint8_t ip[4];
  uint8_t mask[4];
  uint8_t gateway[4];
  uint8_t dns1[4];
  uint8_t dns2[4];

  uint32_t bootCount;
  uint32_t totalDcfSyncCount;
  uint32_t lastDcfSyncUtc;
  int32_t lastRtcCorrectionSeconds;
  uint32_t lastConfigWriteUtc;
  uint32_t successfulStorageWrites;

  uint8_t reserved[80];
};

// ============================================================
// Sieć
// ============================================================

IPAddress localIP(192, 168, 200, 150);
IPAddress gateway(192, 168, 200, 254);
IPAddress subnet(255, 255, 0, 0);
IPAddress primaryDNS(8, 8, 8, 8);
IPAddress secondaryDNS(1, 1, 1, 1);

constexpr char DEFAULT_HOSTNAME[] = "opendcf-ntp";
constexpr uint16_t HTTP_PORT = 80;
constexpr uint16_t NTP_PORT = 123;

// ============================================================
// I2C / RTC
// ============================================================

constexpr uint8_t I2C_SDA_PIN = 33;
constexpr uint8_t I2C_SCL_PIN = 32;
constexpr uint32_t I2C_FREQUENCY = 100000;
constexpr uint8_t SQW_PIN = 36;
constexpr uint8_t DCF77_PIN = 35;

// Różnica między epoką Unix (1970) i NTP (1900).
constexpr uint32_t NTP_UNIX_EPOCH_OFFSET = 2208988800UL;
constexpr size_t NTP_PACKET_SIZE = 48;

// Zasady automatycznej synchronizacji DCF77 -> DS3231.
constexpr uint8_t DCF_FRAMES_REQUIRED_FOR_SYNC = 3;
constexpr int32_t DCF_MAX_SYNC_DIFFERENCE_SECONDS = 10 * 60;

// 24C32: 4096 bajtów, strony zapisu po 32 bajty.
constexpr uint16_t EEPROM_24C32_SIZE = 4096;
constexpr uint8_t EEPROM_24C32_PAGE_SIZE = 32;
constexpr uint16_t EEPROM_CONFIG_ADDRESS = 0;
constexpr uint16_t EEPROM_FORMAT_VERSION = 1;
constexpr uint32_t STORAGE_PERIODIC_SAVE_MS = 6UL * 60UL * 60UL * 1000UL;

// Uwierzytelnianie WWW.
// Dane hasła są przechowywane jako sól + SHA-256 w polu reserved 24C32.
constexpr uint32_t AUTH_SESSION_TIMEOUT_MS = 30UL * 60UL * 1000UL;
constexpr size_t AUTH_SALT_SIZE = 16;
constexpr size_t AUTH_HASH_SIZE = 32;
constexpr size_t AUTH_MAGIC_OFFSET = 0;
constexpr size_t AUTH_SALT_OFFSET = 4;
constexpr size_t AUTH_HASH_OFFSET = AUTH_SALT_OFFSET + AUTH_SALT_SIZE;
constexpr char DEFAULT_ADMIN_PASSWORD[] = "admin";

// ============================================================
// Obiekty
// ============================================================

WebServer server(HTTP_PORT);
NetworkUDP ntpUdp;
RTC_DS3231 rtc;

// ============================================================
// Stan
// ============================================================

volatile bool ethernetConnected = false;
volatile bool ethernetHasIP = false;

bool rtcReady = false;
bool rtcLostPower = true;

bool ntpSocketStarted = false;
bool ntpStartRequested = false;

uint64_t ntpRequestCount = 0;
uint64_t ntpResponseCount = 0;
uint64_t ntpInvalidPacketCount = 0;

IPAddress lastNtpClientIP;
uint16_t lastNtpClientPort = 0;
uint32_t lastNtpRequestMillis = 0;

// Kotwica programowego zegara z ułamkami sekundy.
// Aktualizowana przy wykryciu zmiany sekundy w DS3231.
uint32_t clockAnchorUnix = 0;
int64_t clockAnchorMicros = 0;
uint32_t lastRtcSecondSeen = 0;
bool clockAnchorValid = false;

volatile int64_t sqwEdgeMicros = 0;
volatile uint32_t sqwPulseCount = 0;
volatile bool sqwEdgePending = false;
bool sqwSignalValid = false;
uint32_t lastSqwHandledMillis = 0;
int32_t lastSqwPeriodErrorUs = 0;

// Odbiór DCF77 v2: ISR zapisuje każde zbocze do kolejki FIFO.
// Rozmiar musi być potęgą liczby 2.
struct DcfEdgeEvent
{
  uint32_t timestampUs;
  uint8_t levelAfterEdge;
};

constexpr uint8_t DCF_EDGE_QUEUE_SIZE = 32;
constexpr uint8_t DCF_EDGE_QUEUE_MASK = DCF_EDGE_QUEUE_SIZE - 1;
constexpr uint8_t DCF_POLARITY_CONFIRM_PULSES = 3;
constexpr uint32_t DCF_SIGNAL_TIMEOUT_MS = 3500;

volatile DcfEdgeEvent dcfEdgeQueue[DCF_EDGE_QUEUE_SIZE];
volatile uint8_t dcfEdgeQueueHead = 0;
volatile uint8_t dcfEdgeQueueTail = 0;
volatile uint32_t dcfEdgeQueueOverflowCount = 0;
volatile uint32_t dcfLastEdgeMicros = 0;
volatile uint32_t dcfEdgeCount = 0;

uint32_t dcfParserPreviousEdgeMicros = 0;
uint8_t dcfParserPreviousLevel = LOW;
bool dcfParserPrimed = false;
uint8_t dcfPolarityCandidateCount[2] = {0, 0};
uint32_t dcfLastAnyEdgeMillis = 0;
uint32_t dcfLastHandledOverflowCount = 0;
uint32_t dcfParserResetCount = 0;

bool dcfSignalDetected = false;
int8_t dcfActiveLevel = -1;  // -1 nieznany, 0 LOW, 1 HIGH
uint16_t dcfLastPulseMs = 0;
int8_t dcfLastBit = -1;
uint32_t dcfValidPulseCount = 0;
uint32_t dcfZeroCount = 0;
uint32_t dcfOneCount = 0;
uint32_t dcfInvalidPulseCount = 0;
uint32_t dcfMinuteMarkerCount = 0;
uint32_t dcfLastValidPulseMillis = 0;
uint32_t dcfLastPulseStartMicros = 0;

uint8_t dcfFrameBits[59] = {0};
uint8_t dcfBitsInCurrentMinute = 0;
bool dcfMinuteAligned = false;
String dcfBitBuffer;

uint32_t dcfFrameAttemptCount = 0;
uint32_t dcfValidFrameCount = 0;
uint32_t dcfInvalidFrameCount = 0;
uint8_t dcfConsecutiveValidFrames = 0;
uint32_t dcfLastFrameMillis = 0;
uint32_t dcfPreviousValidUtcUnix = 0;

DcfDecodedTime dcfLastDecoded = {};
String dcfLastFrameStatus = "Oczekiwanie na pełną ramkę";
String dcfLastFrameError = "---";
String dcfLastCompleteFrameBits;

// Stan automatycznej synchronizacji DCF77 -> DS3231.
uint8_t dcfFramesQualifiedForSync = 0;
uint32_t dcfSyncAttemptCount = 0;
uint32_t dcfSyncSuccessCount = 0;
uint32_t dcfSyncRejectedCount = 0;
uint32_t dcfRtcCorrectionCount = 0;
int32_t dcfLastRtcDifferenceSeconds = 0;
uint32_t dcfLastSyncUtcUnix = 0;
uint32_t dcfLastSyncMillis = 0;
bool dcfReferenceEstablished = false;
String dcfLastSyncStatus = "Oczekiwanie na 3 poprawne ramki";
String dcfLastSyncReason = "---";

uint32_t referenceUnix = 0;

String webMessage;
bool webMessageIsError = false;

bool restartRequested = false;
uint32_t restartAtMillis = 0;

String authSessionToken;
uint32_t authSessionLastActivityMillis = 0;
uint32_t authFailedLoginCount = 0;

// Stan pamięci 24C32.
OpenDcfPersistentConfig persistentConfig = {};
bool storageDetected = false;
bool storageConfigValid = false;
bool storageDirty = false;
bool storageWriteInProgress = false;
bool storageSavedFirstSyncThisBoot = false;
uint8_t storageI2cAddress = 0;
uint32_t storageLastSaveMillis = 0;
uint32_t storageReadErrorCount = 0;
uint32_t storageWriteErrorCount = 0;
String storageLastStatus = "Nie zainicjalizowano";

// ============================================================
// Pamięć 24C32 i trwała konfiguracja
// ============================================================

uint32_t calculateCrc32(const uint8_t *data, size_t length)
{
  uint32_t crc = 0xFFFFFFFFUL;

  for (size_t i = 0; i < length; i++)
  {
    crc ^= data[i];

    for (uint8_t bit = 0; bit < 8; bit++)
    {
      crc = (crc & 1UL)
          ? (crc >> 1) ^ 0xEDB88320UL
          : (crc >> 1);
    }
  }

  return crc ^ 0xFFFFFFFFUL;
}

uint32_t calculateConfigCrc(OpenDcfPersistentConfig config)
{
  config.crc32 = 0;

  return calculateCrc32(
      reinterpret_cast<const uint8_t *>(&config),
      sizeof(config)
  );
}

void copyIpToArray(const IPAddress &source, uint8_t destination[4])
{
  for (uint8_t i = 0; i < 4; i++)
    destination[i] = source[i];
}

IPAddress arrayToIp(const uint8_t source[4])
{
  return IPAddress(
      source[0],
      source[1],
      source[2],
      source[3]
  );
}

bool i2cDevicePresent(uint8_t address)
{
  Wire.beginTransmission(address);
  return Wire.endTransmission() == 0;
}

bool detect24C32()
{
  // Moduły DS3231 + 24C32 najczęściej używają adresu 0x57,
  // ale zależnie od zworek A0-A2 możliwy jest zakres 0x50-0x57.
  for (uint8_t address = 0x50; address <= 0x57; address++)
  {
    if (i2cDevicePresent(address))
    {
      storageI2cAddress = address;
      return true;
    }
  }

  return false;
}

bool eepromReadBytes(
    uint16_t memoryAddress,
    uint8_t *destination,
    size_t length)
{
  if (!storageDetected)
    return false;

  size_t completed = 0;

  while (completed < length)
  {
    size_t chunk = min(
        static_cast<size_t>(28),
        length - completed
    );

    uint16_t address =
        memoryAddress + static_cast<uint16_t>(completed);

    Wire.beginTransmission(storageI2cAddress);
    Wire.write(static_cast<uint8_t>(address >> 8));
    Wire.write(static_cast<uint8_t>(address & 0xFF));

    if (Wire.endTransmission(false) != 0)
    {
      storageReadErrorCount++;
      return false;
    }

    size_t received = Wire.requestFrom(
        static_cast<int>(storageI2cAddress),
        static_cast<int>(chunk)
    );

    if (received != chunk)
    {
      storageReadErrorCount++;
      return false;
    }

    for (size_t i = 0; i < chunk; i++)
      destination[completed + i] = Wire.read();

    completed += chunk;
  }

  return true;
}

bool eepromWriteBytes(
    uint16_t memoryAddress,
    const uint8_t *source,
    size_t length)
{
  if (!storageDetected)
    return false;

  size_t completed = 0;

  while (completed < length)
  {
    uint16_t address =
        memoryAddress + static_cast<uint16_t>(completed);

    uint8_t pageOffset =
        static_cast<uint8_t>(address % EEPROM_24C32_PAGE_SIZE);

    size_t bytesUntilPageEnd =
        EEPROM_24C32_PAGE_SIZE - pageOffset;

    // 2 bajty adresu + maks. 30 bajtów danych w buforze Wire.
    size_t chunk = min(
        static_cast<size_t>(30),
        min(bytesUntilPageEnd, length - completed)
    );

    Wire.beginTransmission(storageI2cAddress);
    Wire.write(static_cast<uint8_t>(address >> 8));
    Wire.write(static_cast<uint8_t>(address & 0xFF));
    Wire.write(source + completed, chunk);

    if (Wire.endTransmission() != 0)
    {
      storageWriteErrorCount++;
      return false;
    }

    // Typowy czas wewnętrznego cyklu zapisu 24C32.
    delay(6);
    completed += chunk;
  }

  return true;
}

void loadDefaultPersistentConfig()
{
  memset(&persistentConfig, 0, sizeof(persistentConfig));

  memcpy(persistentConfig.magic, "ODCF", 4);
  persistentConfig.formatVersion = EEPROM_FORMAT_VERSION;
  persistentConfig.structureSize = sizeof(persistentConfig);

  strncpy(
      persistentConfig.hostname,
      DEFAULT_HOSTNAME,
      sizeof(persistentConfig.hostname) - 1
  );

  persistentConfig.useDhcp = 0;
  copyIpToArray(localIP, persistentConfig.ip);
  copyIpToArray(subnet, persistentConfig.mask);
  copyIpToArray(gateway, persistentConfig.gateway);
  copyIpToArray(primaryDNS, persistentConfig.dns1);
  copyIpToArray(secondaryDNS, persistentConfig.dns2);

  setStoredPassword(DEFAULT_ADMIN_PASSWORD);

  persistentConfig.crc32 =
      calculateConfigCrc(persistentConfig);
}

bool persistentConfigLooksValid()
{
  if (memcmp(persistentConfig.magic, "ODCF", 4) != 0)
    return false;

  if (persistentConfig.formatVersion != EEPROM_FORMAT_VERSION)
    return false;

  if (persistentConfig.structureSize != sizeof(persistentConfig))
    return false;

  uint32_t storedCrc = persistentConfig.crc32;
  uint32_t calculatedCrc =
      calculateConfigCrc(persistentConfig);

  return storedCrc == calculatedCrc;
}

void applyPersistentNetworkConfig()
{
  localIP = arrayToIp(persistentConfig.ip);
  subnet = arrayToIp(persistentConfig.mask);
  gateway = arrayToIp(persistentConfig.gateway);
  primaryDNS = arrayToIp(persistentConfig.dns1);
  secondaryDNS = arrayToIp(persistentConfig.dns2);
}

bool savePersistentConfig(const String &reason)
{
  if (!storageDetected || storageWriteInProgress)
    return false;

  storageWriteInProgress = true;

  persistentConfig.crc32 = 0;
  persistentConfig.crc32 =
      calculateConfigCrc(persistentConfig);

  bool writeOk = eepromWriteBytes(
      EEPROM_CONFIG_ADDRESS,
      reinterpret_cast<const uint8_t *>(&persistentConfig),
      sizeof(persistentConfig)
  );

  if (!writeOk)
  {
    storageWriteInProgress = false;
    storageLastStatus = "Błąd zapisu: " + reason;
    return false;
  }

  OpenDcfPersistentConfig verification = {};

  bool readOk = eepromReadBytes(
      EEPROM_CONFIG_ADDRESS,
      reinterpret_cast<uint8_t *>(&verification),
      sizeof(verification)
  );

  if (!readOk ||
      memcmp(&verification,
             &persistentConfig,
             sizeof(persistentConfig)) != 0)
  {
    storageWriteErrorCount++;
    storageWriteInProgress = false;
    storageLastStatus = "Błąd weryfikacji zapisu";
    return false;
  }

  persistentConfig.successfulStorageWrites++;
  persistentConfig.crc32 =
      calculateConfigCrc(persistentConfig);

  // Aktualizujemy licznik zapisów także w EEPROM.
  if (!eepromWriteBytes(
          EEPROM_CONFIG_ADDRESS,
          reinterpret_cast<const uint8_t *>(&persistentConfig),
          sizeof(persistentConfig)))
  {
    storageWriteInProgress = false;
    storageLastStatus =
        "Zapis danych OK, błąd zapisu licznika";
    return false;
  }

  storageDirty = false;
  storageLastSaveMillis = millis();
  storageLastStatus = "Zapisano: " + reason;
  storageWriteInProgress = false;

  Serial.print("[24C32] ");
  Serial.println(storageLastStatus);
  return true;
}

void markStorageDirty()
{
  storageDirty = true;
}

void initializeStorage()
{
  Serial.println("[24C32] Wykrywanie pamięci...");

  storageDetected = detect24C32();

  if (!storageDetected)
  {
    storageLastStatus = "Nie wykryto 24C32";
    Serial.println("[24C32] Nie wykryto urządzenia 0x50-0x57");
    return;
  }

  Serial.print("[24C32] Wykryto pod adresem 0x");
  Serial.println(storageI2cAddress, HEX);

  bool readOk = eepromReadBytes(
      EEPROM_CONFIG_ADDRESS,
      reinterpret_cast<uint8_t *>(&persistentConfig),
      sizeof(persistentConfig)
  );

  storageConfigValid = readOk && persistentConfigLooksValid();

  if (!storageConfigValid)
  {
    Serial.println(
        "[24C32] Brak poprawnej konfiguracji — zapis domyślnej"
    );

    loadDefaultPersistentConfig();

    if (savePersistentConfig("konfiguracja fabryczna"))
      storageConfigValid = true;
  }
  else
  {
    storageLastStatus = "Konfiguracja i CRC poprawne";
    Serial.println("[24C32] Konfiguracja i CRC poprawne");
  }

  if (storageConfigValid)
  {
    if (!authRecordPresent())
    {
      Serial.println(
          "[AUTH] Brak danych logowania — ustawiam hasło fabryczne"
      );

      setStoredPassword(DEFAULT_ADMIN_PASSWORD);
      savePersistentConfig("inicjalizacja hasła WWW");
    }

    applyPersistentNetworkConfig();

    persistentConfig.bootCount++;
    markStorageDirty();

    // Jeden zapis na uruchomienie utrwala licznik startów.
    savePersistentConfig("licznik uruchomień");
  }
}

void processStorage()
{
  if (!storageDetected || !storageDirty)
    return;

  // Pierwszą synchronizację po starcie zapisujemy natychmiast.
  if (!storageSavedFirstSyncThisBoot &&
      persistentConfig.lastDcfSyncUtc != 0)
  {
    if (savePersistentConfig(
            "pierwsza synchronizacja DCF77 po uruchomieniu"))
    {
      storageSavedFirstSyncThisBoot = true;
    }

    return;
  }

  // Kolejne zmiany statystyk zapisujemy maksymalnie raz na 6 h.
  if (millis() - storageLastSaveMillis >=
      STORAGE_PERIODIC_SAVE_MS)
  {
    savePersistentConfig("okresowy zapis statystyk");
  }
}

String storageAddressText()
{
  if (!storageDetected)
    return "---";

  String result = "0x";

  if (storageI2cAddress < 0x10)
    result += "0";

  result += String(storageI2cAddress, HEX);
  result.toUpperCase();
  return result;
}

String storageCrcText()
{
  if (!storageDetected)
    return "---";

  return storageConfigValid ? "OK" : "BŁĄD";
}

// ============================================================
// Uwierzytelnianie WWW
// ============================================================

uint8_t *authReserved()
{
  return persistentConfig.reserved;
}

bool authRecordPresent()
{
  return memcmp(
      authReserved() + AUTH_MAGIC_OFFSET,
      "AUTH",
      4
  ) == 0;
}

void calculatePasswordHash(
    const String &password,
    const uint8_t salt[AUTH_SALT_SIZE],
    uint8_t output[AUTH_HASH_SIZE])
{
  uint8_t buffer[AUTH_SALT_SIZE + 64] = {0};
  size_t passwordLength =
      min(password.length(), static_cast<size_t>(64));

  memcpy(buffer, salt, AUTH_SALT_SIZE);
  memcpy(
      buffer + AUTH_SALT_SIZE,
      password.c_str(),
      passwordLength
  );

  mbedtls_sha256(
      buffer,
      AUTH_SALT_SIZE + passwordLength,
      output,
      0
  );
}

bool constantTimeEquals(
    const uint8_t *left,
    const uint8_t *right,
    size_t length)
{
  uint8_t difference = 0;

  for (size_t i = 0; i < length; i++)
    difference |= left[i] ^ right[i];

  return difference == 0;
}

void setStoredPassword(const String &password)
{
  uint8_t *reserved = authReserved();
  uint8_t salt[AUTH_SALT_SIZE];
  uint8_t hash[AUTH_HASH_SIZE];

  for (size_t i = 0; i < AUTH_SALT_SIZE; i += 4)
  {
    uint32_t randomValue = esp_random();
    size_t bytesToCopy =
        min(static_cast<size_t>(4), AUTH_SALT_SIZE - i);

    memcpy(salt + i, &randomValue, bytesToCopy);
  }

  calculatePasswordHash(password, salt, hash);

  memset(reserved, 0, 80);
  memcpy(reserved + AUTH_MAGIC_OFFSET, "AUTH", 4);
  memcpy(reserved + AUTH_SALT_OFFSET, salt, AUTH_SALT_SIZE);
  memcpy(reserved + AUTH_HASH_OFFSET, hash, AUTH_HASH_SIZE);
}

bool verifyStoredPassword(const String &password)
{
  if (!authRecordPresent())
    return false;

  uint8_t calculatedHash[AUTH_HASH_SIZE];

  calculatePasswordHash(
      password,
      authReserved() + AUTH_SALT_OFFSET,
      calculatedHash
  );

  return constantTimeEquals(
      calculatedHash,
      authReserved() + AUTH_HASH_OFFSET,
      AUTH_HASH_SIZE
  );
}

String createSessionToken()
{
  char token[33];

  for (uint8_t i = 0; i < 16; i++)
  {
    uint8_t value =
        static_cast<uint8_t>(esp_random() & 0xFF);

    snprintf(
        token + i * 2,
        3,
        "%02x",
        value
    );
  }

  token[32] = '\0';
  return String(token);
}

String cookieValue(const String &cookieHeader,
                   const String &name)
{
  String prefix = name + "=";
  int start = cookieHeader.indexOf(prefix);

  if (start < 0)
    return "";

  start += prefix.length();
  int end = cookieHeader.indexOf(';', start);

  if (end < 0)
    end = cookieHeader.length();

  String value = cookieHeader.substring(start, end);
  value.trim();
  return value;
}

bool isAuthenticated()
{
  if (authSessionToken.isEmpty())
    return false;

  if (millis() - authSessionLastActivityMillis >
      AUTH_SESSION_TIMEOUT_MS)
  {
    authSessionToken = "";
    return false;
  }

  String token = cookieValue(
      server.header("Cookie"),
      "ODCFSESSION"
  );

  if (token != authSessionToken)
    return false;

  authSessionLastActivityMillis = millis();
  return true;
}

void redirectToLogin()
{
  String target = server.uri();

  if (target.isEmpty())
    target = "/";

  server.sendHeader(
      "Location",
      "/login?next=" + target
  );
  server.send(303);
}

bool requireAuthentication()
{
  if (isAuthenticated())
    return true;

  redirectToLogin();
  return false;
}

bool requireAuthenticationJson()
{
  if (isAuthenticated())
    return true;

  server.send(
      401,
      "application/json; charset=utf-8",
      "{\"success\":false,\"message\":\"Wymagane logowanie.\"}"
  );

  return false;
}

// ============================================================
// Walidacja konfiguracji sieci
// ============================================================

bool parseIPv4(const String &text, IPAddress &result)
{
  int octets[4] = {0, 0, 0, 0};
  uint8_t part = 0;
  uint8_t digits = 0;

  if (text.length() < 7 || text.length() > 15)
    return false;

  for (size_t i = 0; i <= text.length(); i++)
  {
    char c = (i < text.length()) ? text[i] : '.';

    if (c >= '0' && c <= '9')
    {
      if (part > 3 || digits >= 3)
        return false;

      octets[part] =
          octets[part] * 10 + (c - '0');

      digits++;

      if (octets[part] > 255)
        return false;
    }
    else if (c == '.')
    {
      if (digits == 0 || part > 3)
        return false;

      part++;
      digits = 0;

      if (part == 4 && i != text.length())
        return false;
    }
    else
    {
      return false;
    }
  }

  if (part != 4)
    return false;

  result = IPAddress(
      octets[0],
      octets[1],
      octets[2],
      octets[3]
  );

  return true;
}

bool isValidNetmask(const IPAddress &mask)
{
  uint32_t value =
      (static_cast<uint32_t>(mask[0]) << 24) |
      (static_cast<uint32_t>(mask[1]) << 16) |
      (static_cast<uint32_t>(mask[2]) << 8) |
      static_cast<uint32_t>(mask[3]);

  if (value == 0)
    return false;

  bool zeroSeen = false;

  for (int bit = 31; bit >= 0; bit--)
  {
    bool one = ((value >> bit) & 1U) != 0;

    if (!one)
      zeroSeen = true;
    else if (zeroSeen)
      return false;
  }

  return true;
}

bool isValidHostname(const String &hostname)
{
  if (hostname.length() < 1 ||
      hostname.length() > 31)
  {
    return false;
  }

  if (hostname[0] == '-' ||
      hostname[hostname.length() - 1] == '-')
  {
    return false;
  }

  for (size_t i = 0; i < hostname.length(); i++)
  {
    char c = hostname[i];

    bool valid =
        (c >= 'a' && c <= 'z') ||
        (c >= 'A' && c <= 'Z') ||
        (c >= '0' && c <= '9') ||
        c == '-' ||
        c == '_';

    if (!valid)
      return false;
  }

  return true;
}

String synchronizationBadge()
{
  if (dcfReferenceEstablished)
    return "<span class='sync-badge sync-ok'>DCF LOCK</span>";

  if (timeIsValid())
    return "<span class='sync-badge sync-warn'>RTC ONLY</span>";

  return "<span class='sync-badge sync-error'>NO SYNC</span>";
}

bool storedNetworkDiffersFromActive()
{
  if (!storageConfigValid)
    return false;

  if (String(persistentConfig.hostname) !=
      String(ETH.getHostname()))
  {
    return true;
  }

  if (persistentConfig.useDhcp)
    return false;

  return
      arrayToIp(persistentConfig.ip) != ETH.localIP() ||
      arrayToIp(persistentConfig.mask) != ETH.subnetMask() ||
      arrayToIp(persistentConfig.gateway) != ETH.gatewayIP();
}

// ============================================================
// Narzędzia tekstowe
// ============================================================

String twoDigits(uint8_t value)
{
  return value < 10 ? "0" + String(value) : String(value);
}

String formatDate(const DateTime &dt)
{
  return String(dt.year()) + "-" +
         twoDigits(dt.month()) + "-" +
         twoDigits(dt.day());
}

String formatTime(const DateTime &dt)
{
  return twoDigits(dt.hour()) + ":" +
         twoDigits(dt.minute()) + ":" +
         twoDigits(dt.second());
}

String formatDateTime(const DateTime &dt)
{
  return formatDate(dt) + " " + formatTime(dt);
}

String formatUptime()
{
  uint32_t total = millis() / 1000;
  uint32_t days = total / 86400;
  total %= 86400;
  uint8_t hours = total / 3600;
  total %= 3600;
  uint8_t minutes = total / 60;
  uint8_t seconds = total % 60;

  return String(days) + " d " +
         twoDigits(hours) + ":" +
         twoDigits(minutes) + ":" +
         twoDigits(seconds);
}

String formatLastNtpClient()
{
  if (ntpRequestCount == 0)
    return "---";

  return lastNtpClientIP.toString() + ":" + String(lastNtpClientPort);
}

String formatLastNtpAge()
{
  if (ntpRequestCount == 0)
    return "---";

  return String((millis() - lastNtpRequestMillis) / 1000) + " s temu";
}

bool isLeapYear(uint16_t year)
{
  return ((year % 4 == 0) && (year % 100 != 0)) ||
         (year % 400 == 0);
}

uint8_t daysInMonth(uint16_t year, uint8_t month)
{
  static const uint8_t days[] =
  {
    31, 28, 31, 30, 31, 30,
    31, 31, 30, 31, 30, 31
  };

  if (month < 1 || month > 12)
    return 0;

  if (month == 2 && isLeapYear(year))
    return 29;

  return days[month - 1];
}

bool isValidDateTime(int year, int month, int day,
                     int hour, int minute, int second)
{
  if (year < 2000 || year > 2099) return false;
  if (month < 1 || month > 12) return false;
  if (day < 1 || day > daysInMonth(year, month)) return false;
  if (hour < 0 || hour > 23) return false;
  if (minute < 0 || minute > 59) return false;
  if (second < 0 || second > 59) return false;
  return true;
}

void setWebMessage(const String &message, bool error)
{
  webMessage = message;
  webMessageIsError = error;
}

// ============================================================
// Zegar programowy oparty na RTC
// ============================================================

void resetClockAnchor(uint32_t unixSeconds)
{
  clockAnchorUnix = unixSeconds;
  clockAnchorMicros = esp_timer_get_time();
  lastRtcSecondSeen = unixSeconds;
  clockAnchorValid = true;
}

void IRAM_ATTR onSqwFallingEdge()
{
  sqwEdgeMicros = esp_timer_get_time();
  sqwPulseCount++;
  sqwEdgePending = true;
}

void processSqwPulse()
{
  if (!rtcReady || !sqwEdgePending)
    return;

  noInterrupts();
  int64_t edgeMicros = sqwEdgeMicros;
  sqwEdgePending = false;
  interrupts();

  uint32_t rtcUnix = rtc.now().unixtime();

  if (clockAnchorValid)
  {
    int64_t period = edgeMicros - clockAnchorMicros;
    lastSqwPeriodErrorUs = static_cast<int32_t>(period - 1000000LL);
  }

  clockAnchorUnix = rtcUnix;
  clockAnchorMicros = edgeMicros;
  lastRtcSecondSeen = rtcUnix;
  clockAnchorValid = true;
  sqwSignalValid = true;
  lastSqwHandledMillis = millis();
}

void pollRtcClock()
{
  processSqwPulse();

  // Awaryjny fallback, gdy zniknie sygnał SQW.
  if (!rtcReady)
    return;

  if (sqwSignalValid && millis() - lastSqwHandledMillis <= 2500)
    return;

  sqwSignalValid = false;

  static uint32_t previousPoll = 0;
  if (millis() - previousPoll < 20)
    return;

  previousPoll = millis();
  uint32_t currentUnix = rtc.now().unixtime();

  if (!clockAnchorValid || currentUnix != lastRtcSecondSeen)
    resetClockAnchor(currentUnix);
}

NtpTimestamp currentNtpTimestamp()
{
  NtpTimestamp result = {0, 0};

  if (!clockAnchorValid)
    return result;

  int64_t elapsedMicros = esp_timer_get_time() - clockAnchorMicros;
  if (elapsedMicros < 0)
    elapsedMicros = 0;

  uint32_t wholeSeconds = static_cast<uint32_t>(elapsedMicros / 1000000LL);
  uint32_t remainingMicros =
      static_cast<uint32_t>(elapsedMicros % 1000000LL);

  result.seconds =
      clockAnchorUnix + wholeSeconds + NTP_UNIX_EPOCH_OFFSET;

  result.fraction =
      static_cast<uint32_t>(
          (static_cast<uint64_t>(remainingMicros) << 32) / 1000000ULL
      );

  return result;
}

NtpTimestamp unixToNtpTimestamp(uint32_t unixSeconds)
{
  NtpTimestamp result;
  result.seconds = unixSeconds + NTP_UNIX_EPOCH_OFFSET;
  result.fraction = 0;
  return result;
}

void writeUint32BE(uint8_t *buffer, size_t offset, uint32_t value)
{
  buffer[offset]     = static_cast<uint8_t>(value >> 24);
  buffer[offset + 1] = static_cast<uint8_t>(value >> 16);
  buffer[offset + 2] = static_cast<uint8_t>(value >> 8);
  buffer[offset + 3] = static_cast<uint8_t>(value);
}

void writeTimestamp(uint8_t *buffer, size_t offset,
                    const NtpTimestamp &timestamp)
{
  writeUint32BE(buffer, offset, timestamp.seconds);
  writeUint32BE(buffer, offset + 4, timestamp.fraction);
}

bool timeIsValid()
{
  return rtcReady && !rtcLostPower && clockAnchorValid;
}

uint8_t currentNtpStratum()
{
  // Stratum 0 oznacza odpowiedź alarmową / Kiss-o'-Death.
  if (!timeIsValid())
    return 0;

  // Po potwierdzonej synchronizacji radiowej DCF77 urządzenie
  // jest bezpośrednio związane ze wzorcem czasu.
  return dcfReferenceEstablished ? 1 : 2;
}

String currentTimeSourceText()
{
  if (!timeIsValid())
    return "NIESYNCHRONIZOWANY";

  return dcfReferenceEstablished
      ? "DCF77"
      : "RTC ustawiony ręcznie";
}

// ============================================================
// NTP
// ============================================================

void startNtpServer()
{
  if (ntpSocketStarted || !ethernetHasIP)
    return;

  if (ntpUdp.begin(NTP_PORT))
  {
    ntpSocketStarted = true;
    Serial.println("[NTP] Serwer uruchomiony na UDP/123");
  }
  else
  {
    Serial.println("[NTP] BLAD otwarcia UDP/123");
  }

  ntpStartRequested = false;
}

void stopNtpServer()
{
  if (!ntpSocketStarted)
    return;

  ntpUdp.stop();
  ntpSocketStarted = false;
  Serial.println("[NTP] Serwer zatrzymany");
}

void handleNtpPackets()
{
  if (!ntpSocketStarted)
    return;

  int packetSize = ntpUdp.parsePacket();
  if (packetSize <= 0)
    return;

  ntpRequestCount++;
  lastNtpClientIP = ntpUdp.remoteIP();
  lastNtpClientPort = ntpUdp.remotePort();
  lastNtpRequestMillis = millis();

  uint8_t request[NTP_PACKET_SIZE] = {0};
  uint8_t response[NTP_PACKET_SIZE] = {0};

  int bytesToRead = min(packetSize, static_cast<int>(NTP_PACKET_SIZE));
  int bytesRead = ntpUdp.read(request, bytesToRead);

  // Usuń ewentualną pozostałą część datagramu.
  while (ntpUdp.available())
    ntpUdp.read();

  if (packetSize < static_cast<int>(NTP_PACKET_SIZE) ||
      bytesRead < static_cast<int>(NTP_PACKET_SIZE))
  {
    ntpInvalidPacketCount++;
    return;
  }

  uint8_t clientMode = request[0] & 0x07;
  uint8_t clientVersion = (request[0] >> 3) & 0x07;

  // Windows w32tm może użyć NTPv1 lub trybu symmetric active.
  if ((clientMode != 3 && clientMode != 1) ||
      clientVersion < 1 || clientVersion > 4)
  {
    ntpInvalidPacketCount++;
    return;
  }

  const bool synchronized = timeIsValid();

  // Znacznik odbioru możliwie wcześnie po walidacji nagłówka.
  NtpTimestamp receiveTimestamp = currentNtpTimestamp();

  uint8_t leapIndicator = synchronized ? 0 : 3;
  uint8_t serverVersion = clientVersion;
  uint8_t serverMode = (clientMode == 1) ? 2 : 4;

  response[0] =
      static_cast<uint8_t>((leapIndicator << 6) |
                           (serverVersion << 3) |
                           serverMode);

  response[1] = currentNtpStratum();     // stratum
  response[2] = request[2];              // poll - kopiowany z zapytania
  response[3] =
      static_cast<uint8_t>(sqwSignalValid ? -16 : -6);

  // Dla serwera pierwotnego Stratum 1 RFC/SNTP zaleca zero.
  // Dla RTC-only pozostawiamy małą, realistyczną dyspersję 15,625 ms.
  writeUint32BE(response, 4, 0x00000000UL);  // Root Delay

  uint32_t rootDispersion = 0;

  if (synchronized && !dcfReferenceEstablished)
    rootDispersion = 0x00000400UL;  // 1/64 s = 15,625 ms

  writeUint32BE(response, 8, rootDispersion);

  if (!synchronized)
  {
    response[12] = 'I';
    response[13] = 'N';
    response[14] = 'I';
    response[15] = 'T';
  }
  else if (dcfReferenceEstablished)
  {
    // Kod źródła pierwotnego: "DCF", lewostronnie,
    // dopełniony bajtem zerowym zgodnie z RFC.
    response[12] = 'D';
    response[13] = 'C';
    response[14] = 'F';
    response[15] = 0;
  }
  else
  {
    response[12] = 'L';
    response[13] = 'O';
    response[14] = 'C';
    response[15] = 'L';
  }

  // Originate Timestamp musi być dokładną kopią Transmit Timestamp
  // z zapytania klienta.
  memcpy(response + 24, request + 40, 8);

  if (synchronized)
  {
    uint32_t safeReferenceUnix = referenceUnix;

    // Reference Timestamp nie może być późniejszy niż odbiór pakietu.
    uint32_t receiveUnix =
        receiveTimestamp.seconds - NTP_UNIX_EPOCH_OFFSET;

    if (safeReferenceUnix == 0 ||
        safeReferenceUnix > receiveUnix)
    {
      safeReferenceUnix =
          receiveUnix > 0 ? receiveUnix - 1 : receiveUnix;
    }

    NtpTimestamp referenceTimestamp =
        unixToNtpTimestamp(safeReferenceUnix);

    writeTimestamp(response, 16, referenceTimestamp);
    writeTimestamp(response, 32, receiveTimestamp);

    NtpTimestamp transmitTimestamp =
        currentNtpTimestamp();

    writeTimestamp(response, 40, transmitTimestamp);
  }
  // Przy braku synchronizacji pola Reference, Receive i Transmit
  // pozostają zerowe. Originate nadal jest kopiowany z zapytania.

  if (ntpUdp.beginPacket(lastNtpClientIP, lastNtpClientPort))
  {
    ntpUdp.write(response, NTP_PACKET_SIZE);

    if (ntpUdp.endPacket())
      ntpResponseCount++;
  }
}


// ============================================================
// Odbiór i dekodowanie DCF77
// ============================================================

void IRAM_ATTR onDcf77Change()
{
  const uint32_t now = micros();
  const uint8_t currentLevel =
      static_cast<uint8_t>(digitalRead(DCF77_PIN));

  const uint8_t head = dcfEdgeQueueHead;
  const uint8_t nextHead =
      static_cast<uint8_t>((head + 1U) & DCF_EDGE_QUEUE_MASK);

  if (nextHead == dcfEdgeQueueTail)
  {
    // Kolejka pełna: nie nadpisujemy starszych danych.
    dcfEdgeQueueOverflowCount++;
  }
  else
  {
    dcfEdgeQueue[head].timestampUs = now;
    dcfEdgeQueue[head].levelAfterEdge = currentLevel;
    dcfEdgeQueueHead = nextHead;
  }

  dcfLastEdgeMicros = now;
  dcfEdgeCount++;
}

bool popDcfEdgeEvent(DcfEdgeEvent &event)
{
  bool available = false;

  noInterrupts();

  const uint8_t tail = dcfEdgeQueueTail;

  if (tail != dcfEdgeQueueHead)
  {
    event.timestampUs = dcfEdgeQueue[tail].timestampUs;
    event.levelAfterEdge = dcfEdgeQueue[tail].levelAfterEdge;
    dcfEdgeQueueTail =
        static_cast<uint8_t>((tail + 1U) & DCF_EDGE_QUEUE_MASK);
    available = true;
  }

  interrupts();
  return available;
}

String dcfPolarityText()
{
  if (dcfActiveLevel < 0)
    return "nierozpoznana";

  return dcfActiveLevel == HIGH
      ? "impuls aktywny HIGH"
      : "impuls aktywny LOW";
}

String dcfLastBitText()
{
  return dcfLastBit < 0 ? "---" : String(dcfLastBit);
}

String dcfSignalAgeText()
{
  if (dcfValidPulseCount == 0)
    return "---";

  return String((millis() - dcfLastValidPulseMillis) / 1000) + " s temu";
}

String dcfLastFrameAgeText()
{
  if (dcfFrameAttemptCount == 0)
    return "---";

  return String((millis() - dcfLastFrameMillis) / 1000) + " s temu";
}

String dcfZoneText()
{
  if (!dcfLastDecoded.valid)
    return "---";

  if (dcfLastDecoded.cest)
    return "CEST / UTC+2";

  if (dcfLastDecoded.cet)
    return "CET / UTC+1";

  return "nieprawidłowa";
}

String boolText(bool value)
{
  return value ? "TAK" : "NIE";
}

String parityText(bool value)
{
  return value ? "OK" : "BŁĄD";
}

uint8_t decodeWeightedBits(
    const uint8_t *bits,
    const uint8_t *positions,
    const uint8_t *weights,
    uint8_t count)
{
  uint8_t value = 0;

  for (uint8_t i = 0; i < count; i++)
  {
    if (bits[positions[i]])
      value += weights[i];
  }

  return value;
}

bool evenParityInclusive(
    const uint8_t *bits,
    uint8_t first,
    uint8_t last)
{
  uint8_t parity = 0;

  for (uint8_t i = first; i <= last; i++)
    parity ^= bits[i];

  return parity == 0;
}

void resetDcfCurrentFrame()
{
  memset(dcfFrameBits, 0, sizeof(dcfFrameBits));
  dcfBitsInCurrentMinute = 0;
  dcfBitBuffer = "";
}

bool decodeDcfFrame(const uint8_t *bits, DcfDecodedTime &decoded,
                    String &error)
{
  decoded = {};
  error = "";

  // Bit 20 oznacza początek kodowanej informacji czasu.
  if (bits[20] != 1)
  {
    error = "Bit startowy S (20) nie ma wartości 1";
    return false;
  }

  decoded.cet = bits[17] == 0 && bits[18] == 1;
  decoded.cest = bits[17] == 1 && bits[18] == 0;

  if (!decoded.cet && !decoded.cest)
  {
    error = "Nieprawidłowa kombinacja bitów strefy Z1/Z2";
    return false;
  }

  decoded.dstChangeAnnouncement = bits[16] == 1;
  decoded.leapSecondAnnouncement = bits[19] == 1;

  decoded.minuteParityOk = evenParityInclusive(bits, 21, 28);
  decoded.hourParityOk = evenParityInclusive(bits, 29, 35);
  decoded.dateParityOk = evenParityInclusive(bits, 36, 58);

  if (!decoded.minuteParityOk)
  {
    error = "Błąd parzystości minut P1";
    return false;
  }

  if (!decoded.hourParityOk)
  {
    error = "Błąd parzystości godzin P2";
    return false;
  }

  if (!decoded.dateParityOk)
  {
    error = "Błąd parzystości daty P3";
    return false;
  }

  static const uint8_t minutePositions[] = {21, 22, 23, 24, 25, 26, 27};
  static const uint8_t minuteWeights[]   = { 1,  2,  4,  8, 10, 20, 40};

  static const uint8_t hourPositions[] = {29, 30, 31, 32, 33, 34};
  static const uint8_t hourWeights[]   = { 1,  2,  4,  8, 10, 20};

  static const uint8_t dayPositions[] = {36, 37, 38, 39, 40, 41};
  static const uint8_t dayWeights[]   = { 1,  2,  4,  8, 10, 20};

  static const uint8_t weekdayPositions[] = {42, 43, 44};
  static const uint8_t weekdayWeights[]   = { 1,  2,  4};

  static const uint8_t monthPositions[] = {45, 46, 47, 48, 49};
  static const uint8_t monthWeights[]   = { 1,  2,  4,  8, 10};

  static const uint8_t yearPositions[] = {50, 51, 52, 53, 54, 55, 56, 57};
  static const uint8_t yearWeights[]   = { 1,  2,  4,  8, 10, 20, 40, 80};

  decoded.minute = decodeWeightedBits(
      bits, minutePositions, minuteWeights, 7);

  decoded.hour = decodeWeightedBits(
      bits, hourPositions, hourWeights, 6);

  decoded.day = decodeWeightedBits(
      bits, dayPositions, dayWeights, 6);

  decoded.weekday = decodeWeightedBits(
      bits, weekdayPositions, weekdayWeights, 3);

  decoded.month = decodeWeightedBits(
      bits, monthPositions, monthWeights, 5);

  decoded.year = 2000 + decodeWeightedBits(
      bits, yearPositions, yearWeights, 8);

  if (!isValidDateTime(
          decoded.year,
          decoded.month,
          decoded.day,
          decoded.hour,
          decoded.minute,
          0))
  {
    error = "Odebrano niemożliwą datę lub godzinę";
    return false;
  }

  if (decoded.weekday < 1 || decoded.weekday > 7)
  {
    error = "Nieprawidłowy dzień tygodnia";
    return false;
  }

  DateTime localTime(
      decoded.year,
      decoded.month,
      decoded.day,
      decoded.hour,
      decoded.minute,
      0);

  uint8_t calculatedWeekday =
      localTime.dayOfTheWeek() == 0
          ? 7
          : localTime.dayOfTheWeek();

  if (calculatedWeekday != decoded.weekday)
  {
    error = "Dzień tygodnia nie zgadza się z datą";
    return false;
  }

  decoded.localUnix = localTime.unixtime();

  uint32_t zoneOffsetSeconds =
      decoded.cest ? 2UL * 3600UL : 1UL * 3600UL;

  if (decoded.localUnix < zoneOffsetSeconds)
  {
    error = "Błąd konwersji czasu lokalnego na UTC";
    return false;
  }

  decoded.utcUnix = decoded.localUnix - zoneOffsetSeconds;
  decoded.valid = true;
  return true;
}

String signedSecondsText(int32_t seconds)
{
  String result;

  if (seconds > 0)
    result += "+";

  result += String(seconds);
  result += " s";
  return result;
}

String dcfLastSyncAgeText()
{
  if (dcfLastSyncUtcUnix == 0)
    return "---";

  return String((millis() - dcfLastSyncMillis) / 1000UL) + " s temu";
}

String dcfLastSyncUtcText()
{
  if (dcfLastSyncUtcUnix == 0)
    return "---";

  return formatDateTime(DateTime(dcfLastSyncUtcUnix)) + " UTC";
}

void resetDcfSyncQualification(const String &reason)
{
  dcfFramesQualifiedForSync = 0;

  if (reason.length() > 0)
    dcfLastSyncReason = reason;
}

void attemptDcfRtcSynchronization(const DcfDecodedTime &decoded)
{
  if (dcfFramesQualifiedForSync <
      DCF_FRAMES_REQUIRED_FOR_SYNC)
  {
    return;
  }

  dcfSyncAttemptCount++;

  if (!rtcReady)
  {
    dcfSyncRejectedCount++;
    dcfLastSyncStatus = "SYNCHRONIZACJA ODRZUCONA";
    dcfLastSyncReason = "Brak komunikacji z DS3231";
    resetDcfSyncQualification("");
    return;
  }

  uint32_t rtcUnix = rtc.now().unixtime();

  int64_t signedDifference64 =
      static_cast<int64_t>(decoded.utcUnix) -
      static_cast<int64_t>(rtcUnix);

  if (signedDifference64 > INT32_MAX)
    signedDifference64 = INT32_MAX;
  else if (signedDifference64 < INT32_MIN)
    signedDifference64 = INT32_MIN;

  dcfLastRtcDifferenceSeconds =
      static_cast<int32_t>(signedDifference64);

  int64_t absoluteDifference =
      signedDifference64 >= 0
          ? signedDifference64
          : -signedDifference64;

  if (absoluteDifference >
      DCF_MAX_SYNC_DIFFERENCE_SECONDS)
  {
    dcfSyncRejectedCount++;
    dcfLastSyncStatus = "SYNCHRONIZACJA ODRZUCONA";
    dcfLastSyncReason =
        "Różnica RTC/DCF77 wynosi " +
        signedSecondsText(dcfLastRtcDifferenceSeconds) +
        ", limit to ±600 s";

    Serial.print("[SYNC] ODRZUCENIE: ");
    Serial.println(dcfLastSyncReason);

    // Po odrzuceniu trzeba ponownie odebrać trzy kompletne,
    // kolejne i poprawne ramki.
    resetDcfSyncQualification("");
    return;
  }

  // Zapis RTC wykonujemy tylko wtedy, gdy różnica nie jest zerowa.
  // Sam poprawny test trzech ramek również ustanawia DCF77 jako
  // wiarygodne źródło referencyjne.
  if (dcfLastRtcDifferenceSeconds != 0)
  {
    rtc.adjust(DateTime(decoded.utcUnix));
    rtcLostPower = rtc.lostPower();

    resetClockAnchor(decoded.utcUnix);
    dcfRtcCorrectionCount++;
  }

  referenceUnix = decoded.utcUnix;
  dcfReferenceEstablished = true;
  dcfLastSyncUtcUnix = decoded.utcUnix;
  dcfLastSyncMillis = millis();
  dcfSyncSuccessCount++;

  if (storageConfigValid)
  {
    persistentConfig.totalDcfSyncCount++;
    persistentConfig.lastDcfSyncUtc = decoded.utcUnix;
    persistentConfig.lastRtcCorrectionSeconds =
        dcfLastRtcDifferenceSeconds;
    markStorageDirty();
  }

  dcfLastSyncStatus = "SYNCHRONIZACJA POPRAWNA";

  if (dcfLastRtcDifferenceSeconds == 0)
  {
    dcfLastSyncReason =
        "RTC był zgodny z DCF77 — zapis czasu nie był potrzebny";
  }
  else
  {
    dcfLastSyncReason =
        "Skorygowano RTC o " +
        signedSecondsText(dcfLastRtcDifferenceSeconds);
  }

  Serial.println("[SYNC] =================================");
  Serial.println("[SYNC] 3 kolejne pełne ramki poprawne");
  Serial.print("[SYNC] Różnica DCF77 - RTC: ");
  Serial.println(signedSecondsText(
      dcfLastRtcDifferenceSeconds));
  Serial.print("[SYNC] UTC referencyjne: ");
  Serial.println(formatDateTime(DateTime(decoded.utcUnix)));
  Serial.print("[SYNC] Wynik: ");
  Serial.println(dcfLastSyncReason);
  Serial.println("[SYNC] =================================");

  // Kolejna kontrola wymaga nowej serii trzech pełnych ramek.
  resetDcfSyncQualification("");
}

void evaluateCompletedDcfFrame()
{
  dcfFrameAttemptCount++;
  dcfLastFrameMillis = millis();

  dcfLastCompleteFrameBits = "";
  dcfLastCompleteFrameBits.reserve(60);

  for (uint8_t i = 0; i < dcfBitsInCurrentMinute && i < 59; i++)
    dcfLastCompleteFrameBits += dcfFrameBits[i] ? '1' : '0';

  if (dcfBitsInCurrentMinute != 59)
  {
    dcfInvalidFrameCount++;
    dcfConsecutiveValidFrames = 0;
    resetDcfSyncQualification(
        "Seria wyzerowana: niepełna ramka");
    dcfLastFrameStatus = "RAMKA NIEPEŁNA";
    dcfLastFrameError =
        "Odebrano " + String(dcfBitsInCurrentMinute) +
        " zamiast 59 bitów";

    Serial.print("[DCF77] Ramka niepełna: ");
    Serial.print(dcfBitsInCurrentMinute);
    Serial.println(" / 59");
    return;
  }

  DcfDecodedTime decoded;
  String error;

  if (!decodeDcfFrame(dcfFrameBits, decoded, error))
  {
    dcfInvalidFrameCount++;
    dcfConsecutiveValidFrames = 0;
    resetDcfSyncQualification(
        "Seria wyzerowana: błędna ramka");
    dcfLastFrameStatus = "RAMKA BŁĘDNA";
    dcfLastFrameError = error;
    dcfLastDecoded = decoded;

    Serial.print("[DCF77] Ramka odrzucona: ");
    Serial.println(error);
    return;
  }

  dcfValidFrameCount++;
  dcfLastFrameStatus = "RAMKA POPRAWNA";
  dcfLastFrameError = "---";

  bool continuesPreviousFrame =
      dcfPreviousValidUtcUnix != 0 &&
      decoded.utcUnix == dcfPreviousValidUtcUnix + 60UL;

  if (continuesPreviousFrame)
  {
    if (dcfConsecutiveValidFrames < 255)
      dcfConsecutiveValidFrames++;

    if (dcfFramesQualifiedForSync <
        DCF_FRAMES_REQUIRED_FOR_SYNC)
    {
      dcfFramesQualifiedForSync++;
    }
  }
  else
  {
    // Pierwsza poprawna ramka rozpoczyna nową serię.
    // Poprawna, ale niespójna czasowo ramka nie może być
    // kontynuacją poprzedniej serii.
    dcfConsecutiveValidFrames = 1;
    dcfFramesQualifiedForSync = 1;

    if (dcfPreviousValidUtcUnix != 0)
    {
      dcfLastSyncReason =
          "Rozpoczęto nową serię: brak ciągłości +60 s";
    }
  }

  dcfPreviousValidUtcUnix = decoded.utcUnix;
  dcfLastDecoded = decoded;

  DateTime localTime(decoded.localUnix);
  DateTime utcTime(decoded.utcUnix);

  Serial.println("[DCF77] =================================");
  Serial.print("[DCF77] Poprawna ramka nr ");
  Serial.println(dcfValidFrameCount);
  Serial.print("[DCF77] Czas lokalny: ");
  Serial.print(formatDateTime(localTime));
  Serial.print(" ");
  Serial.println(decoded.cest ? "CEST" : "CET");
  Serial.print("[DCF77] Czas UTC:     ");
  Serial.println(formatDateTime(utcTime));
  Serial.print("[DCF77] Kolejne poprawne ramki: ");
  Serial.println(dcfConsecutiveValidFrames);
  Serial.print("[DCF77] Ramki kwalifikujące do synchronizacji: ");
  Serial.print(dcfFramesQualifiedForSync);
  Serial.print(" / ");
  Serial.println(DCF_FRAMES_REQUIRED_FOR_SYNC);
  Serial.println("[DCF77] =================================");

  attemptDcfRtcSynchronization(decoded);
}

void resetDcfReceiverState(const String &reason,
                           bool resetFrame)
{
  dcfParserPrimed = false;
  dcfParserPreviousEdgeMicros = 0;
  dcfPolarityCandidateCount[LOW] = 0;
  dcfPolarityCandidateCount[HIGH] = 0;
  dcfActiveLevel = -1;
  dcfLastPulseStartMicros = 0;
  dcfSignalDetected = false;
  dcfParserResetCount++;

  if (resetFrame)
  {
    dcfMinuteAligned = false;
    resetDcfCurrentFrame();
    dcfConsecutiveValidFrames = 0;
    dcfPreviousValidUtcUnix = 0;
    resetDcfSyncQualification(
        "Seria wyzerowana: utrata ciągłości impulsów");
  }

  if (reason.length() > 0)
  {
    Serial.print("[DCF77] Reset odbiornika: ");
    Serial.println(reason);
  }
}

void acceptDcfPulse(uint32_t durationUs,
                    uint32_t pulseStartMicros,
                    uint8_t pulseLevel)
{
  const uint32_t durationMs = durationUs / 1000UL;

  if (dcfLastPulseStartMicros != 0)
  {
    const uint32_t startIntervalUs =
        pulseStartMicros - dcfLastPulseStartMicros;

    // Brak impulsu w 59. sekundzie daje odstęp około 2 s
    // pomiędzy początkiem ostatniego impulsu starej minuty
    // i pierwszego impulsu nowej minuty.
    if (startIntervalUs >= 1500000UL &&
        startIntervalUs <= 2600000UL)
    {
      dcfMinuteMarkerCount++;
      Serial.println("[DCF77] Znacznik nowej minuty");

      if (dcfMinuteAligned)
        evaluateCompletedDcfFrame();

      dcfMinuteAligned = true;
      resetDcfCurrentFrame();
    }
    else if (startIntervalUs > 2600000UL)
    {
      // Dłuższa przerwa oznacza utratę ciągłości. Bieżącej
      // ramki nie wolno kontynuować po brakujących impulsach.
      dcfMinuteAligned = false;
      resetDcfCurrentFrame();
      dcfConsecutiveValidFrames = 0;
      dcfPreviousValidUtcUnix = 0;
      resetDcfSyncQualification(
          "Seria wyzerowana: przerwa w sygnale DCF77");

      Serial.print("[DCF77] Przerwa w sygnale: ");
      Serial.print(startIntervalUs / 1000UL);
      Serial.println(" ms, oczekiwanie na nowy marker");
    }
  }

  dcfLastPulseStartMicros = pulseStartMicros;
  dcfLastPulseMs = static_cast<uint16_t>(durationMs);
  dcfLastValidPulseMillis = millis();
  dcfSignalDetected = true;
  dcfValidPulseCount++;

  uint8_t bitValue;

  if (durationMs < 150)
  {
    bitValue = 0;
    dcfZeroCount++;
  }
  else
  {
    bitValue = 1;
    dcfOneCount++;
  }

  dcfLastBit = bitValue;

  if (dcfMinuteAligned && dcfBitsInCurrentMinute < 59)
  {
    dcfFrameBits[dcfBitsInCurrentMinute] = bitValue;
    dcfBitsInCurrentMinute++;
  }

  dcfBitBuffer += bitValue ? '1' : '0';

  if (dcfBitBuffer.length() > 59)
    dcfBitBuffer.remove(0, dcfBitBuffer.length() - 59);

  Serial.print("[DCF77] impuls=");
  Serial.print(dcfLastPulseMs);
  Serial.print(" ms bit=");
  Serial.print(dcfLastBit);
  Serial.print(" poziom=");
  Serial.print(pulseLevel == HIGH ? "HIGH" : "LOW");
  Serial.print(" pozycja=");

  if (dcfMinuteAligned)
    Serial.println(dcfBitsInCurrentMinute - 1);
  else
    Serial.println("oczekiwanie na marker");
}

void processDcfEdge(const DcfEdgeEvent &event)
{
  dcfLastAnyEdgeMillis = millis();

  // Pierwsze zbocze po starcie lub resecie parsera tylko
  // kotwiczy pomiar. Dzięki temu nigdy nie uznajemy fragmentu
  // poziomu trwającego już podczas uruchamiania za pełny impuls.
  if (!dcfParserPrimed)
  {
    dcfParserPreviousEdgeMicros = event.timestampUs;
    dcfParserPreviousLevel = event.levelAfterEdge;
    dcfParserPrimed = true;
    return;
  }

  const uint32_t durationUs =
      event.timestampUs - dcfParserPreviousEdgeMicros;
  const uint8_t durationLevel = dcfParserPreviousLevel;

  dcfParserPreviousEdgeMicros = event.timestampUs;
  dcfParserPreviousLevel = event.levelAfterEdge;

  const uint32_t durationMs = durationUs / 1000UL;
  const bool pulseWidthValid =
      durationMs >= 60 && durationMs <= 260;

  if (dcfActiveLevel < 0)
  {
    if (!pulseWidthValid)
      return;

    // Polaryzację uznajemy dopiero po kilku pełnych impulsach
    // o prawidłowej długości na tym samym poziomie. Chroni to
    // przed błędnym rozpoznaniem poziomu po starcie lub zakłóceniu.
    uint8_t &candidate =
        dcfPolarityCandidateCount[durationLevel];

    if (candidate < 255)
      candidate++;

    dcfPolarityCandidateCount[durationLevel ^ 1U] = 0;

    if (candidate < DCF_POLARITY_CONFIRM_PULSES)
      return;

    dcfActiveLevel = static_cast<int8_t>(durationLevel);

    Serial.print("[DCF77] Rozpoznano polaryzację: aktywny ");
    Serial.println(dcfActiveLevel == HIGH ? "HIGH" : "LOW");

    const uint32_t pulseStartMicros =
        event.timestampUs - durationUs;

    acceptDcfPulse(
        durationUs,
        pulseStartMicros,
        durationLevel);

    return;
  }

  if (durationLevel != static_cast<uint8_t>(dcfActiveLevel))
    return;

  if (pulseWidthValid)
  {
    const uint32_t pulseStartMicros =
        event.timestampUs - durationUs;

    acceptDcfPulse(
        durationUs,
        pulseStartMicros,
        durationLevel);
  }
  else if (durationMs >= 20 && durationMs <= 500)
  {
    dcfInvalidPulseCount++;

    Serial.print("[DCF77] Impuls poza zakresem: ");
    Serial.print(durationMs);
    Serial.println(" ms");
  }
}

void processDcf77Signal()
{
  uint32_t overflowCount;

  noInterrupts();
  overflowCount = dcfEdgeQueueOverflowCount;
  interrupts();

  if (overflowCount != dcfLastHandledOverflowCount)
  {
    const uint32_t lost =
        overflowCount - dcfLastHandledOverflowCount;

    dcfLastHandledOverflowCount = overflowCount;

    Serial.print("[DCF77] Przepełnienie kolejki, utracono zdarzeń: ");
    Serial.println(lost);

    noInterrupts();
    dcfEdgeQueueTail = dcfEdgeQueueHead;
    interrupts();

    resetDcfReceiverState(
        "utrata zbocza w kolejce FIFO",
        true);
  }

  DcfEdgeEvent event;

  // Opróżniamy całą kolejkę. Nawet gdy Ethernet chwilowo zajmie
  // pętlę główną, każde zapamiętane zbocze zostanie przeliczone.
  while (popDcfEdgeEvent(event))
    processDcfEdge(event);

  // Samonaprawianie po utracie sygnału albo błędnym rozpoznaniu
  // polaryzacji. Próg jest większy od około 2-sekundowego markera.
  if (dcfParserPrimed &&
      dcfLastAnyEdgeMillis != 0 &&
      millis() - dcfLastAnyEdgeMillis > DCF_SIGNAL_TIMEOUT_MS)
  {
    resetDcfReceiverState(
        "brak zboczy przez ponad 3,5 s",
        true);
  }
  else if (dcfSignalDetected &&
           millis() - dcfLastValidPulseMillis >
               DCF_SIGNAL_TIMEOUT_MS)
  {
    resetDcfReceiverState(
        "brak poprawnych impulsów przez ponad 3,5 s",
        true);
  }
}

void initializeDcf77()
{
  dcfBitBuffer.reserve(64);
  dcfLastCompleteFrameBits.reserve(64);

  pinMode(DCF77_PIN, INPUT);

  noInterrupts();
  dcfEdgeQueueHead = 0;
  dcfEdgeQueueTail = 0;
  dcfEdgeQueueOverflowCount = 0;
  interrupts();

  dcfParserPreviousLevel =
      static_cast<uint8_t>(digitalRead(DCF77_PIN));
  dcfParserPreviousEdgeMicros = 0;
  dcfParserPrimed = false;
  dcfLastAnyEdgeMillis = millis();

  attachInterrupt(
      digitalPinToInterrupt(DCF77_PIN),
      onDcf77Change,
      CHANGE
  );

  Serial.println(
      "[DCF77] Dekoder FIFO aktywny na GPIO35 / IO35"
  );
  Serial.println(
      "[DCF77] Pierwsze zbocze zostanie użyte wyłącznie jako kotwica"
  );
}

// ============================================================
// HTML
// ============================================================

String htmlHeader(const String &title, const String &active)
{
  String page;
  page.reserve(5000);

  page += R"HTML(
<!DOCTYPE html>
<html lang="pl">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>)HTML";
  page += title;
  page += R"HTML(</title>
<style>
*{box-sizing:border-box}
body{margin:0;padding:22px;background:#eef2f6;font-family:Arial,sans-serif;color:#263238}
.container{max-width:900px;margin:auto}
.header{background:#263b50;color:#fff;padding:24px;border-radius:12px 12px 0 0;display:flex;justify-content:space-between;align-items:center;gap:16px}
.header h1{margin:0 0 7px}.header p{margin:0;color:#d7e1ea}.sync-badge{display:inline-block;padding:8px 12px;border-radius:999px;font-weight:bold;font-size:13px;white-space:nowrap}.sync-ok{background:#207a43}.sync-warn{background:#a66d00}.sync-error{background:#a52d2d}.grid2{display:grid;grid-template-columns:1fr 1fr;gap:16px}.radio-row{display:flex;gap:22px;margin-bottom:18px}.radio-row label{display:inline-flex;align-items:center;gap:7px}.radio-row input{width:auto;margin:0}.danger{background:#b23b3b}.muted{opacity:.58}.login-box{max-width:420px;margin:20px auto}.auth-note{padding:12px;border-radius:6px;background:#fff4d6;color:#775400;margin-top:14px}.nav-spacer{flex:1}
.nav{display:flex;gap:4px;flex-wrap:wrap;background:#34495e;padding:10px}
.nav a{color:#fff;text-decoration:none;padding:10px 15px;border-radius:6px}
.nav a:hover,.nav a.active{background:#1976a8}
.nav .disabled{color:#9eabb7;pointer-events:none}
.content{background:#fff;padding:24px;border-radius:0 0 12px 12px;box-shadow:0 5px 18px #0002}
.section{margin-bottom:28px}.section:last-child{margin-bottom:0}
.section h2{font-size:21px;border-bottom:1px solid #dbe2e8;padding-bottom:8px}
.clock{text-align:center;background:#f5f8fa;border:1px solid #dbe2e8;border-radius:8px;padding:20px}
.clock-date{font-size:22px}.clock-time{font:700 42px Consolas,monospace;color:#1c5d89}
.status{display:flex;align-items:center;margin:9px 0}
.dot{width:12px;height:12px;border-radius:50%;margin-right:10px;background:#c0392b}
.dot.ok{background:#27ae60}.dot.warn{background:#f39c12}
table{width:100%;border-collapse:collapse}td{padding:10px 8px;border-bottom:1px solid #edf0f2}
td:first-child{font-weight:bold;color:#455a64;width:45%}
td:last-child{font-family:Consolas,monospace}
.box{background:#f7f9fb;border:1px solid #dbe2e8;border-radius:8px;padding:20px}
label{display:block;font-weight:bold;margin:0 0 6px}
input{width:100%;padding:11px;border:1px solid #b8c5cf;border-radius:6px;font-size:16px;margin-bottom:16px}
button{border:0;border-radius:6px;padding:11px 18px;background:#1976a8;color:#fff;font-weight:bold;cursor:pointer}
button.green{background:#2e7d32}button:disabled{background:#9eabb7}
.message{padding:14px;border-radius:7px;margin-bottom:20px;font-weight:bold}
.message.success{background:#e7f7ec;color:#17672f}.message.error{background:#fbeaea;color:#982222}
.note{color:#607d8b;font-size:14px;line-height:1.5}
.footer{text-align:center;color:#78909c;font-size:13px;margin-top:18px}
@media(max-width:600px){body{padding:9px}.header,.content{padding:17px}.header{align-items:flex-start;flex-direction:column}.clock-time{font-size:33px}.grid2{grid-template-columns:1fr}}
</style>
</head>
<body><div class="container">
<div class="header"><div><h1>OpenDCF NTP Server</h1><p>WT32-ETH01 • DS3231 • DCF77 — firmware 1.0.0 DCF FIFO</p></div>
)HTML";
  page += synchronizationBadge();
  page += R"HTML(
</div>
<div class="nav">
)HTML";

  page += active == "status"
      ? "<a class='active' href='/'>Status</a>"
      : "<a href='/'>Status</a>";

  if (isAuthenticated())
  {
    page += active == "time"
        ? "<a class='active' href='/time'>Czas</a>"
        : "<a href='/time'>Czas</a>";

    page += active == "ntp"
        ? "<a class='active' href='/ntp'>NTP</a>"
        : "<a href='/ntp'>NTP</a>";

    page += active == "network"
        ? "<a class='active' href='/network'>Sieć</a>"
        : "<a href='/network'>Sieć</a>";

    page += active == "dcf"
        ? "<a class='active' href='/dcf'>DCF77</a>"
        : "<a href='/dcf'>DCF77</a>";

    page += active == "storage"
        ? "<a class='active' href='/storage'>Pamięć</a>"
        : "<a href='/storage'>Pamięć</a>";

    page += active == "security"
        ? "<a class='active' href='/security'>Hasło</a>"
        : "<a href='/security'>Hasło</a>";

    page += "<span class='nav-spacer'></span>";
    page += "<a href='/logout'>Wyloguj</a>";
  }
  else
  {
    page += "<span class='nav-spacer'></span>";

    page += active == "login"
        ? "<a class='active' href='/login'>Zaloguj</a>"
        : "<a href='/login'>Zaloguj</a>";
  }

  page += R"HTML(
</div><div class="content">
)HTML";

  return page;
}

String htmlFooter()
{
  String footer;
  footer.reserve(260);

  footer += "</div><div class='footer'>";
  footer += "OpenDCF NTP Server 1.0.0 DCF FIFO";
  footer += " &bull; build ";
  footer += __DATE__;
  footer += " ";
  footer += __TIME__;
  footer += " &bull; maintainer osnapus";
  footer += " &bull; MIT License";
  footer += "</div></div></body></html>";

  return footer;
}

String messageHtml()
{
  if (webMessage.isEmpty())
    return "";

  String result = "<div class='message ";
  result += webMessageIsError ? "error'>" : "success'>";
  result += webMessage;
  result += "</div>";
  return result;
}

void handleLoginPage()
{
  if (isAuthenticated())
  {
    server.sendHeader("Location", "/time");
    server.send(303);
    return;
  }

  String page = htmlHeader(
      "OpenDCF NTP Server — Logowanie",
      "login"
  );

  page += messageHtml();

  page += R"HTML(
<div class="section login-box">
<h2>Logowanie</h2>
<div class="box">
<form method="POST" action="/login">
<label for="password">Hasło administratora</label>
<input type="password" id="password" name="password"
 autocomplete="current-password" required autofocus>
<button type="submit">Zaloguj</button>
</form>
<div class="auth-note">
Domyślne hasło po przywróceniu ustawień fabrycznych: <b>admin</b>.
Po pierwszym zalogowaniu zmień je w zakładce „Hasło”.
</div>
<p class="note">
Panel korzysta z HTTP, dlatego hasło nie jest szyfrowane podczas
przesyłania w sieci. Dostęp administracyjny powinien być ograniczony
do zaufanej sieci lokalnej.
</p>
</div>
</div>
)HTML";

  page += htmlFooter();

  server.sendHeader("Cache-Control", "no-store");
  server.send(200, "text/html; charset=utf-8", page);
  webMessage = "";
}

void handleLoginSubmit()
{
  String password = server.arg("password");

  if (verifyStoredPassword(password))
  {
    authSessionToken = createSessionToken();
    authSessionLastActivityMillis = millis();

    server.sendHeader(
        "Set-Cookie",
        "ODCFSESSION=" + authSessionToken +
        "; Path=/; HttpOnly; SameSite=Strict"
    );

    String target = server.arg("next");

    if (target.isEmpty() ||
        !target.startsWith("/") ||
        target.startsWith("//"))
    {
      target = "/time";
    }

    Serial.println("[AUTH] Poprawne logowanie WWW");

    server.sendHeader("Location", target);
    server.send(303);
  }
  else
  {
    authFailedLoginCount++;
    Serial.println("[AUTH] Błędne hasło WWW");

    setWebMessage("Nieprawidłowe hasło.", true);
    server.sendHeader("Location", "/login");
    server.send(303);
  }
}

void handleLogout()
{
  authSessionToken = "";

  server.sendHeader(
      "Set-Cookie",
      "ODCFSESSION=; Path=/; Max-Age=0; HttpOnly; SameSite=Strict"
  );

  server.sendHeader("Location", "/");
  server.send(303);
}

void handleSecurityPage()
{
  String page = htmlHeader(
      "OpenDCF NTP Server — Hasło",
      "security"
  );

  page += messageHtml();

  page += R"HTML(
<div class="section"><h2>Zmiana hasła administratora</h2>
<div class="box">
<form method="POST" action="/security-password">
<label for="currentPassword">Aktualne hasło</label>
<input type="password" id="currentPassword"
 name="currentPassword" required>

<label for="newPassword">Nowe hasło</label>
<input type="password" id="newPassword"
 name="newPassword" minlength="8" maxlength="63" required>

<label for="confirmPassword">Powtórz nowe hasło</label>
<input type="password" id="confirmPassword"
 name="confirmPassword" minlength="8" maxlength="63" required>

<button type="submit">Zmień hasło</button>
</form>
<p class="note">
Nowe hasło musi mieć od 8 do 63 znaków. Po zmianie nastąpi
wylogowanie ze wszystkich aktywnych sesji.
</p>
</div>
</div>

<div class="section"><h2>Stan zabezpieczeń</h2><table>
<tr><td>Ochrona panelu</td><td>AKTYWNA</td></tr>
<tr><td>Sesja</td><td>30 minut bezczynności</td></tr>
<tr><td>Cookie</td><td>HttpOnly, SameSite=Strict</td></tr>
)HTML";

  page += "<tr><td>Nieudane logowania od startu</td><td>";
  page += String(authFailedLoginCount);
  page += "</td></tr></table></div>";

  page += R"HTML(
<div class="section"><h2>Ważne</h2>
<p class="note">
Połączenie WWW nie jest szyfrowane. Hasło chroni panel przed
przypadkową lub nieautoryzowaną zmianą konfiguracji w sieci LAN,
ale nie zastępuje HTTPS, VLAN-u ani reguł zapory sieciowej.
</p>
</div>
)HTML";

  page += htmlFooter();

  server.sendHeader("Cache-Control", "no-store");
  server.send(200, "text/html; charset=utf-8", page);
  webMessage = "";
}

void handlePasswordChange()
{
  String currentPassword = server.arg("currentPassword");
  String newPassword = server.arg("newPassword");
  String confirmPassword = server.arg("confirmPassword");

  if (!verifyStoredPassword(currentPassword))
  {
    setWebMessage("Aktualne hasło jest nieprawidłowe.", true);
    server.sendHeader("Location", "/security");
    server.send(303);
    return;
  }

  if (newPassword.length() < 8 ||
      newPassword.length() > 63)
  {
    setWebMessage(
        "Nowe hasło musi mieć od 8 do 63 znaków.",
        true
    );

    server.sendHeader("Location", "/security");
    server.send(303);
    return;
  }

  if (newPassword != confirmPassword)
  {
    setWebMessage("Nowe hasła nie są identyczne.", true);
    server.sendHeader("Location", "/security");
    server.send(303);
    return;
  }

  setStoredPassword(newPassword);

  if (!savePersistentConfig("zmiana hasła WWW"))
  {
    setWebMessage(
        "Nie udało się zapisać nowego hasła w 24C32.",
        true
    );

    server.sendHeader("Location", "/security");
    server.send(303);
    return;
  }

  authSessionToken = "";

  server.sendHeader(
      "Set-Cookie",
      "ODCFSESSION=; Path=/; Max-Age=0; HttpOnly; SameSite=Strict"
  );

  setWebMessage(
      "Hasło zmieniono. Zaloguj się ponownie.",
      false
  );

  server.sendHeader("Location", "/login");
  server.send(303);
}

void handleRoot()
{
  String page = htmlHeader("OpenDCF NTP Server — Status", "status");
  page += messageHtml();

  String date = "---";
  String time = "---";
  String temperature = "---";

  if (rtcReady)
  {
    DateTime now = rtc.now();
    date = formatDate(now);
    time = formatTime(now);
    temperature = String(rtc.getTemperature(), 2) + " &deg;C";
  }

  page += "<div class='section'><h2>Status urządzenia</h2>";

  page += "<div class='status'><span class='dot ";
  page += ethernetHasIP ? "ok'></span>Ethernet: OK" :
                          "'></span>Ethernet: BŁĄD";
  page += "</div>";

  page += "<div class='status'><span class='dot ";
  page += rtcReady ? "ok'></span>DS3231: OK" :
                     "'></span>DS3231: BŁĄD";
  page += "</div>";

  page += "<div class='status'><span class='dot ";
  page += timeIsValid()
      ? "ok'></span>Czas UTC: wiarygodny"
      : "warn'></span>Czas UTC: wymaga ustawienia";
  page += "</div>";

  page += "<div class='status'><span class='dot ";
  page += ntpSocketStarted
      ? "ok'></span>NTP UDP/123: uruchomiony"
      : "'></span>NTP UDP/123: zatrzymany";
  page += "</div>";

  page += "<div class='status'><span class='dot ";
  if (dcfConsecutiveValidFrames > 0)
    page += "ok'></span>DCF77: poprawne ramki, seria " +
            String(dcfConsecutiveValidFrames);
  else if (dcfSignalDetected)
    page += "warn'></span>DCF77: impulsy wykryte, brak poprawnej ramki";
  else
    page += "warn'></span>DCF77: oczekiwanie na sygnał";
  page += "</div></div>";

  page += "<div class='section'><h2>Czas UTC w DS3231</h2><div class='clock'>";
  page += "<div class='clock-date'>" + date + "</div>";
  page += "<div class='clock-time'>" + time + "</div>";
  page += "</div></div>";

  page += "<div class='section'><h2>Podsumowanie</h2><table>";
  page += "<tr><td>Temperatura DS3231</td><td>" + temperature + "</td></tr>";
  page += "<tr><td>Flaga utraty zasilania</td><td>";
  page += rtcReady ? (rtcLostPower ? "AKTYWNA" : "NIEAKTYWNA") : "---";
  page += "</td></tr>";
  page += "<tr><td>Adres IP</td><td>" + ETH.localIP().toString() + "</td></tr>";
  page += "<tr><td>Uptime</td><td>" + formatUptime() + "</td></tr>";
  page += "<tr><td>Źródło czasu NTP</td><td>" +
          currentTimeSourceText() + "</td></tr>";
  page += "<tr><td>Ramki DCF77 do synchronizacji</td><td>" +
          String(dcfFramesQualifiedForSync) + " / " +
          String(DCF_FRAMES_REQUIRED_FOR_SYNC) + "</td></tr>";
  page += "<tr><td>Pamięć 24C32</td><td>";
  page += storageDetected ? "WYKRYTA" : "BRAK";
  page += "</td></tr>";
  page += "<tr><td>CRC konfiguracji</td><td>" +
          storageCrcText() + "</td></tr>";
  page += "<tr><td>Zapytania NTP</td><td>" +
          String(ntpRequestCount) + "</td></tr>";
  page += "</table></div>";

  page += htmlFooter();
  server.sendHeader("Cache-Control", "no-store");
  server.send(200, "text/html; charset=utf-8", page);
  webMessage = "";
}

void handleTimePage()
{
  String page = htmlHeader("OpenDCF NTP Server — Czas", "time");
  page += messageHtml();

  String date = "---";
  String time = "---";

  if (rtcReady)
  {
    DateTime now = rtc.now();
    date = formatDate(now);
    time = formatTime(now);
  }

  page += "<div class='section'><h2>Aktualny czas UTC</h2><div class='clock'>";
  page += "<div class='clock-date'>" + date + "</div>";
  page += "<div class='clock-time'>" + time + "</div></div></div>";

  page += R"HTML(
<div class="section"><h2>Ustawienie ręczne UTC</h2>
<div class="box">
<form method="POST" action="/set-time-manual">
<label for="date">Data UTC</label>
<input type="date" id="date" name="date" min="2000-01-01" max="2099-12-31" required>
<label for="time">Godzina UTC</label>
<input type="time" id="time" name="time" step="1" required>
<button type="submit">Ustaw czas UTC</button>
</form></div></div>

<div class="section"><h2>Synchronizacja z komputerem</h2>
<div class="box">
<p>Przeglądarka prześle czas UTC obliczony z zegara komputera.</p>
<button class="green" id="syncButton" onclick="syncUtc()">Synchronizuj UTC z komputerem</button>
<p class="note" id="computerTime"></p>
</div></div>

<div class="section"><h2>Ważne</h2>
<p class="note">
DS3231 przechowuje UTC. Lokalna strefa czasowa i zmiana CET/CEST
nie są zapisywane w zegarze. Klienci NTP sami wyświetlają czas lokalny.
</p></div>

<script>
const pad=v=>String(v).padStart(2,"0");
function showUtc(){
 const d=new Date();
 document.getElementById("computerTime").textContent=
 "UTC komputera: "+d.getUTCFullYear()+"-"+pad(d.getUTCMonth()+1)+"-"+
 pad(d.getUTCDate())+" "+pad(d.getUTCHours())+":"+
 pad(d.getUTCMinutes())+":"+pad(d.getUTCSeconds());
}
async function syncUtc(){
 const b=document.getElementById("syncButton");
 const i=document.getElementById("computerTime");
 const d=new Date();
 const p=new URLSearchParams({
  year:d.getUTCFullYear(),month:d.getUTCMonth()+1,day:d.getUTCDate(),
  hour:d.getUTCHours(),minute:d.getUTCMinutes(),second:d.getUTCSeconds()
 });
 b.disabled=true;i.textContent="Zapisywanie UTC do DS3231...";
 try{
  const r=await fetch("/set-time-browser",{
   method:"POST",
   headers:{"Content-Type":"application/x-www-form-urlencoded"},
   body:p.toString()
  });
  const j=await r.json();
  if(!r.ok||!j.success)throw new Error(j.message||"Błąd urządzenia");
  i.textContent=j.message;
  setTimeout(()=>location.href="/time",600);
 }catch(e){i.textContent="Błąd: "+e.message;b.disabled=false}
}
showUtc();setInterval(showUtc,1000);
</script>
)HTML";

  page += htmlFooter();
  server.sendHeader("Cache-Control", "no-store");
  server.send(200, "text/html; charset=utf-8", page);
  webMessage = "";
}

void handleNtpPage()
{
  String page = htmlHeader("OpenDCF NTP Server — NTP", "ntp");

  page += "<div class='section'><h2>Stan serwera NTP</h2><table>";
  page += "<tr><td>Port</td><td>UDP 123</td></tr>";
  page += "<tr><td>Stan gniazda</td><td>";
  page += ntpSocketStarted ? "URUCHOMIONE" : "ZATRZYMANE";
  page += "</td></tr>";
  page += "<tr><td>Stan synchronizacji</td><td>";
  page += timeIsValid() ? "SYNCHRONIZOWANY" : "NIESYNCHRONIZOWANY";
  page += "</td></tr>";
  page += "<tr><td>Stratum</td><td>";
  page += String(currentNtpStratum());
  page += "</td></tr>";
  page += "<tr><td>Reference ID</td><td>";
  page += !timeIsValid() ? "INIT" :
          (dcfReferenceEstablished ? "DCF" : "LOCL");
  page += "</td></tr>";
  page += "<tr><td>Źródło czasu</td><td>" +
          currentTimeSourceText() + "</td></tr>";
  page += "<tr><td>Profil zgodności</td><td>RFC/SNTP + RouterOS</td></tr>";
  page += "<tr><td>Root Delay</td><td>0 s</td></tr>";
  page += "<tr><td>Root Dispersion</td><td>";
  page += dcfReferenceEstablished ? "0 s" : "0.015625 s";
  page += "</td></tr>";
  page += "<tr><td>Ostatnia synchronizacja DCF77</td><td>" +
          dcfLastSyncUtcText() + "</td></tr>";
  page += "<tr><td>Źródło kotwicy sekund</td><td>";
  page += sqwSignalValid ? "DS3231 SQW 1 Hz" : "I2C fallback";
  page += "</td></tr>";
  page += "<tr><td>Impulsy SQW</td><td>" + String(sqwPulseCount) + "</td></tr>";
  page += "<tr><td>Błąd ostatniego okresu SQW</td><td>" + String(lastSqwPeriodErrorUs) + " us</td></tr>";
  page += "<tr><td>Zapytania</td><td>" + String(ntpRequestCount) + "</td></tr>";
  page += "<tr><td>Odpowiedzi</td><td>" + String(ntpResponseCount) + "</td></tr>";
  page += "<tr><td>Pakiety odrzucone</td><td>" + String(ntpInvalidPacketCount) + "</td></tr>";
  page += "<tr><td>Ostatni klient</td><td>" + formatLastNtpClient() + "</td></tr>";
  page += "<tr><td>Ostatnie zapytanie</td><td>" + formatLastNtpAge() + "</td></tr>";
  page += "</table></div>";

  page += R"HTML(
<div class="section"><h2>Informacja</h2>
<p class="note">
Przed potwierdzoną synchronizacją DCF77 serwer zgłasza stratum 2,
jeżeli RTC ma wiarygodny czas. Po trzech kolejnych pełnych i poprawnych
ramkach DCF77 oraz zaakceptowaniu różnicy RTC/DCF77 zgłaszane jest
stratum 1 i Reference ID DCF. Przy nieważnym RTC odpowiedź ma
Leap Indicator 3 oraz stratum 0 (INIT).
</p></div>
)HTML";

  page += htmlFooter();
  server.sendHeader("Cache-Control", "no-store");
  server.send(200, "text/html; charset=utf-8", page);
}


void handleDcfPage()
{
  String page = htmlHeader("OpenDCF NTP Server — DCF77", "dcf");

  page += "<div class='section'><h2>Ostatnia ramka czasu</h2><table>";
  page += "<tr><td>Status</td><td>" + dcfLastFrameStatus + "</td></tr>";
  page += "<tr><td>Przyczyna błędu</td><td>" + dcfLastFrameError + "</td></tr>";
  page += "<tr><td>Wiek ostatniej ramki</td><td>" + dcfLastFrameAgeText() + "</td></tr>";
  page += "<tr><td>Poprawne ramki z rzędu</td><td>" +
          String(dcfConsecutiveValidFrames) + "</td></tr>";

  if (dcfLastDecoded.valid)
  {
    DateTime localTime(dcfLastDecoded.localUnix);
    DateTime utcTime(dcfLastDecoded.utcUnix);

    page += "<tr><td>Czas odebrany</td><td>" +
            formatDateTime(localTime) + " " +
            (dcfLastDecoded.cest ? "CEST" : "CET") +
            "</td></tr>";

    page += "<tr><td>Czas po konwersji</td><td>" +
            formatDateTime(utcTime) + " UTC</td></tr>";

    page += "<tr><td>Dzień tygodnia ISO</td><td>" +
            String(dcfLastDecoded.weekday) + "</td></tr>";

    page += "<tr><td>Zapowiedź zmiany CET/CEST</td><td>" +
            boolText(dcfLastDecoded.dstChangeAnnouncement) +
            "</td></tr>";

    page += "<tr><td>Zapowiedź sekundy przestępnej</td><td>" +
            boolText(dcfLastDecoded.leapSecondAnnouncement) +
            "</td></tr>";
  }
  else
  {
    page += "<tr><td>Czas odebrany</td><td>---</td></tr>";
    page += "<tr><td>Czas po konwersji</td><td>---</td></tr>";
  }

  page += "</table></div>";

  page += "<div class='section'><h2>Synchronizacja DCF77 → DS3231</h2><table>";
  page += "<tr><td>Wymagana seria</td><td>" +
          String(DCF_FRAMES_REQUIRED_FOR_SYNC) +
          " pełne poprawne ramki</td></tr>";
  page += "<tr><td>Aktualnie zakwalifikowane</td><td>" +
          String(dcfFramesQualifiedForSync) + " / " +
          String(DCF_FRAMES_REQUIRED_FOR_SYNC) + "</td></tr>";
  page += "<tr><td>Limit różnicy</td><td>±" +
          String(DCF_MAX_SYNC_DIFFERENCE_SECONDS) + " s</td></tr>";
  page += "<tr><td>Ostatni wynik</td><td>" +
          dcfLastSyncStatus + "</td></tr>";
  page += "<tr><td>Szczegóły</td><td>" +
          dcfLastSyncReason + "</td></tr>";
  page += "<tr><td>Ostatnia różnica DCF77 - RTC</td><td>" +
          signedSecondsText(dcfLastRtcDifferenceSeconds) + "</td></tr>";
  page += "<tr><td>Ostatnia synchronizacja UTC</td><td>" +
          dcfLastSyncUtcText() + "</td></tr>";
  page += "<tr><td>Wiek synchronizacji</td><td>" +
          dcfLastSyncAgeText() + "</td></tr>";
  page += "<tr><td>Źródło referencyjne aktywne</td><td>";
  page += dcfReferenceEstablished ? "DCF77" : "NIE";
  page += "</td></tr>";
  page += "</table></div>";

  page += "<div class='section'><h2>Kontrola ramki</h2><table>";
  page += "<tr><td>Parzystość minut P1</td><td>" +
          parityText(dcfLastDecoded.minuteParityOk) + "</td></tr>";
  page += "<tr><td>Parzystość godzin P2</td><td>" +
          parityText(dcfLastDecoded.hourParityOk) + "</td></tr>";
  page += "<tr><td>Parzystość daty P3</td><td>" +
          parityText(dcfLastDecoded.dateParityOk) + "</td></tr>";
  page += "<tr><td>Strefa</td><td>" + dcfZoneText() + "</td></tr>";
  page += "</table></div>";

  page += "<div class='section'><h2>Odbiór bieżącej minuty</h2><table>";
  page += "<tr><td>GPIO</td><td>GPIO35 / IO35</td></tr>";
  page += "<tr><td>Poziom wejścia</td><td>";
  page += digitalRead(DCF77_PIN) == HIGH ? "HIGH" : "LOW";
  page += "</td></tr>";
  page += "<tr><td>Polaryzacja</td><td>" + dcfPolarityText() + "</td></tr>";
  page += "<tr><td>Stan sygnału</td><td>";
  page += dcfSignalDetected ? "IMPULSY WYKRYTE" : "BRAK POPRAWNYCH IMPULSÓW";
  page += "</td></tr>";
  page += "<tr><td>Synchronizacja z początkiem minuty</td><td>";
  page += dcfMinuteAligned ? "TAK" : "NIE";
  page += "</td></tr>";
  page += "<tr><td>Ostatni impuls</td><td>" +
          String(dcfLastPulseMs) + " ms</td></tr>";
  page += "<tr><td>Ostatni bit</td><td>" +
          dcfLastBitText() + "</td></tr>";
  page += "<tr><td>Bity bieżącej ramki</td><td>" +
          String(dcfBitsInCurrentMinute) + " / 59</td></tr>";
  page += "</table></div>";

  page += "<div class='section'><h2>Statystyki</h2><table>";
  page += "<tr><td>Próby dekodowania</td><td>" +
          String(dcfFrameAttemptCount) + "</td></tr>";
  page += "<tr><td>Ramki poprawne</td><td>" +
          String(dcfValidFrameCount) + "</td></tr>";
  page += "<tr><td>Ramki błędne</td><td>" +
          String(dcfInvalidFrameCount) + "</td></tr>";
  page += "<tr><td>Próby synchronizacji RTC</td><td>" +
          String(dcfSyncAttemptCount) + "</td></tr>";
  page += "<tr><td>Synchronizacje zaakceptowane</td><td>" +
          String(dcfSyncSuccessCount) + "</td></tr>";
  page += "<tr><td>Synchronizacje odrzucone</td><td>" +
          String(dcfSyncRejectedCount) + "</td></tr>";
  page += "<tr><td>Faktyczne korekty RTC</td><td>" +
          String(dcfRtcCorrectionCount) + "</td></tr>";
  page += "<tr><td>Znaczniki minut</td><td>" +
          String(dcfMinuteMarkerCount) + "</td></tr>";
  page += "<tr><td>Poprawne impulsy</td><td>" +
          String(dcfValidPulseCount) + "</td></tr>";
  page += "<tr><td>Impulsy odrzucone</td><td>" +
          String(dcfInvalidPulseCount) + "</td></tr>";
  page += "</table></div>";

  page += "<div class='section'><h2>Ostatnia kompletna ramka</h2>";
  page += "<div class='box' style='font-family:Consolas,monospace;"
          "word-break:break-all;font-size:18px'>";
  page += dcfLastCompleteFrameBits.length()
      ? dcfLastCompleteFrameBits
      : "---";
  page += "</div></div>";

  page += R"HTML(
<div class="section"><h2>Informacja</h2>
<p class="note">
Odebrany czas urzędowy jest przeliczany na UTC. 
</p></div>
<script>setTimeout(()=>location.reload(),2000);</script>
)HTML";

  page += htmlFooter();
  server.sendHeader("Cache-Control", "no-store");
  server.send(200, "text/html; charset=utf-8", page);
}

void handleNetworkPage()
{
  String page = htmlHeader(
      "OpenDCF NTP Server — Sieć",
      "network"
  );

  page += messageHtml();

  page += R"HTML(
<div class="section"><h2>Konfiguracja sieci</h2>
<div class="box">
<form method="POST" action="/network-save" id="networkForm">

<div class="radio-row">
<label>
<input type="radio" name="mode" value="static" )HTML";

  page += persistentConfig.useDhcp ? "" : "checked";

  page += R"HTML( onchange="toggleStaticFields()">
Statyczny
</label>

<label>
<input type="radio" name="mode" value="dhcp" )HTML";

  page += persistentConfig.useDhcp ? "checked" : "";

  page += R"HTML( onchange="toggleStaticFields()">
DHCP
</label>
</div>

<label for="hostname">Hostname</label>
<input id="hostname" name="hostname" maxlength="31"
 pattern="[A-Za-z0-9_-]{1,31}" required value=")HTML";

  page += String(persistentConfig.hostname);

  page += R"HTML(">

<div id="staticFields">
<div class="grid2">

<div>
<label for="ip">Adres IP</label>
<input id="ip" name="ip" required value=")HTML";
  page += arrayToIp(persistentConfig.ip).toString();
  page += R"HTML(">
</div>

<div>
<label for="mask">Maska</label>
<input id="mask" name="mask" required value=")HTML";
  page += arrayToIp(persistentConfig.mask).toString();
  page += R"HTML(">
</div>

<div>
<label for="gateway">Brama</label>
<input id="gateway" name="gateway" required value=")HTML";
  page += arrayToIp(persistentConfig.gateway).toString();
  page += R"HTML(">
</div>

<div>
<label for="dns1">DNS 1</label>
<input id="dns1" name="dns1" required value=")HTML";
  page += arrayToIp(persistentConfig.dns1).toString();
  page += R"HTML(">
</div>

<div>
<label for="dns2">DNS 2</label>
<input id="dns2" name="dns2" required value=")HTML";
  page += arrayToIp(persistentConfig.dns2).toString();
  page += R"HTML(">
</div>

</div>
</div>

<button type="submit">Zapisz konfigurację</button>
</form>
</div>
</div>
)HTML";

  page += "<div class='section'><h2>Aktywna konfiguracja</h2><table>";

  page += "<tr><td>Hostname</td><td>";
  page += String(ETH.getHostname());
  page += "</td></tr>";

  page += "<tr><td>Adres IP</td><td>";
  page += ETH.localIP().toString();
  page += "</td></tr>";

  page += "<tr><td>Maska</td><td>";
  page += ETH.subnetMask().toString();
  page += "</td></tr>";

  page += "<tr><td>Brama</td><td>";
  page += ETH.gatewayIP().toString();
  page += "</td></tr>";

  page += "<tr><td>DNS</td><td>";
  page += ETH.dnsIP().toString();
  page += "</td></tr>";

  page += "<tr><td>MAC</td><td>";
  page += ETH.macAddress();
  page += "</td></tr>";

  page += "<tr><td>Link</td><td>";
  page += ethernetConnected ? "UP" : "DOWN";
  page += "</td></tr>";

  page += "<tr><td>Prędkość / duplex</td><td>";
  page += String(ETH.linkSpeed());
  page += " Mb/s ";
  page += ETH.fullDuplex() ? "FULL" : "HALF";
  page += "</td></tr>";

  page += "<tr><td>Ethernet PHY</td><td>LAN8720</td></tr>";
  page += "</table></div>";

  page += "<div class='section'><h2>Konfiguracja zapisana w 24C32</h2><table>";

  page += "<tr><td>Hostname</td><td>";
  page += String(persistentConfig.hostname);
  page += "</td></tr>";

  page += "<tr><td>Tryb</td><td>";
  page += persistentConfig.useDhcp ? "DHCP" : "STATYCZNY";
  page += "</td></tr>";

  page += "<tr><td>Adres IP</td><td>";
  page += arrayToIp(persistentConfig.ip).toString();
  page += "</td></tr>";

  page += "<tr><td>Maska</td><td>";
  page += arrayToIp(persistentConfig.mask).toString();
  page += "</td></tr>";

  page += "<tr><td>Brama</td><td>";
  page += arrayToIp(persistentConfig.gateway).toString();
  page += "</td></tr>";

  page += "<tr><td>DNS 1</td><td>";
  page += arrayToIp(persistentConfig.dns1).toString();
  page += "</td></tr>";

  page += "<tr><td>DNS 2</td><td>";
  page += arrayToIp(persistentConfig.dns2).toString();
  page += "</td></tr>";

  page += "<tr><td>Wymagany restart</td><td>";
  page += storedNetworkDiffersFromActive() ? "TAK" : "NIE";
  page += "</td></tr>";

  page += "</table></div>";

  page += R"HTML(
<div class="section"><h2>Restart urządzenia</h2>
<div class="box">
<form method="POST" action="/restart"
 onsubmit="return confirm('Uruchomić ponownie OpenDCF NTP Server?');">
<button class="danger" type="submit">
Restart urządzenia
</button>
</form>
<p class="note">
Restart stosuje konfigurację zapisaną w pamięci 24C32.
</p>
</div>
</div>
)HTML";

  page += "<div class='section'><h2>Informacje systemowe</h2><table>";

  page += "<tr><td>Firmware</td><td>0.9.0</td></tr>";

  page += "<tr><td>Build</td><td>";
  page += String(__DATE__);
  page += " ";
  page += String(__TIME__);
  page += "</td></tr>";

  page += "<tr><td>Płyta</td><td>WT32-ETH01</td></tr>";

  page += "<tr><td>CPU</td><td>";
  page += String(ESP.getCpuFreqMHz());
  page += " MHz</td></tr>";

  page += "<tr><td>Flash</td><td>";
  page += String(ESP.getFlashChipSize() / 1048576UL);
  page += " MB</td></tr>";

  page += "<tr><td>Wolna pamięć RAM</td><td>";
  page += String(ESP.getFreeHeap());
  page += " B</td></tr>";

  page += "<tr><td>ESP-IDF</td><td>";
  page += String(ESP.getSdkVersion());
  page += "</td></tr>";

  page += "</table></div>";

  page += R"HTML(
<script>
function toggleStaticFields()
{
  const dhcp =
    document.querySelector(
      'input[name="mode"][value="dhcp"]'
    ).checked;

  const box = document.getElementById("staticFields");

  box.classList.toggle("muted", dhcp);

  box.querySelectorAll("input").forEach(function(input)
  {
    input.disabled = dhcp;
  });
}

toggleStaticFields();
</script>
)HTML";

  page += htmlFooter();

  server.sendHeader("Cache-Control", "no-store");
  server.send(200, "text/html; charset=utf-8", page);

  webMessage = "";
}

void handleNetworkSave()
{
  if (!storageDetected || !storageConfigValid)
  {
    setWebMessage(
        "Pamięć 24C32 nie jest dostępna.",
        true
    );

    server.sendHeader("Location", "/network");
    server.send(303);
    return;
  }

  String mode = server.arg("mode");
  String hostname = server.arg("hostname");
  hostname.trim();

  if (!isValidHostname(hostname))
  {
    setWebMessage(
        "Nieprawidłowy hostname. Dozwolone są litery, "
        "cyfry, '-' oraz '_', maksymalnie 31 znaków.",
        true
    );

    server.sendHeader("Location", "/network");
    server.send(303);
    return;
  }

  bool useDhcp = mode == "dhcp";

  IPAddress newIp;
  IPAddress newMask;
  IPAddress newGateway;
  IPAddress newDns1;
  IPAddress newDns2;

  if (!useDhcp)
  {
    if (!parseIPv4(server.arg("ip"), newIp) ||
        !parseIPv4(server.arg("mask"), newMask) ||
        !parseIPv4(server.arg("gateway"), newGateway) ||
        !parseIPv4(server.arg("dns1"), newDns1) ||
        !parseIPv4(server.arg("dns2"), newDns2))
    {
      setWebMessage(
          "Co najmniej jeden adres IPv4 jest nieprawidłowy.",
          true
      );

      server.sendHeader("Location", "/network");
      server.send(303);
      return;
    }

    if (!isValidNetmask(newMask))
    {
      setWebMessage(
          "Maska podsieci jest nieprawidłowa.",
          true
      );

      server.sendHeader("Location", "/network");
      server.send(303);
      return;
    }
  }

  memset(
      persistentConfig.hostname,
      0,
      sizeof(persistentConfig.hostname)
  );

  hostname.toCharArray(
      persistentConfig.hostname,
      sizeof(persistentConfig.hostname)
  );

  persistentConfig.useDhcp = useDhcp ? 1 : 0;

  if (!useDhcp)
  {
    copyIpToArray(newIp, persistentConfig.ip);
    copyIpToArray(newMask, persistentConfig.mask);
    copyIpToArray(newGateway, persistentConfig.gateway);
    copyIpToArray(newDns1, persistentConfig.dns1);
    copyIpToArray(newDns2, persistentConfig.dns2);
  }

  if (rtcReady && !rtcLostPower)
  {
    persistentConfig.lastConfigWriteUtc =
        rtc.now().unixtime();
  }

  if (!savePersistentConfig(
          "konfiguracja sieci z WWW"))
  {
    setWebMessage(
        "Nie udało się zapisać konfiguracji w 24C32.",
        true
    );
  }
  else
  {
    String target = useDhcp
        ? "adres przydzielony przez DHCP"
        : arrayToIp(persistentConfig.ip).toString();

    setWebMessage(
        "Konfiguracja została zapisana i zweryfikowana. "
        "Zmiany zaczną obowiązywać po restarcie. "
        "Po restarcie urządzenie będzie dostępne pod: " +
        target,
        false
    );
  }

  server.sendHeader("Location", "/network");
  server.send(303);
}

void handleRestart()
{
  String page = htmlHeader(
      "OpenDCF NTP Server — Restart",
      "network"
  );

  page += R"HTML(
<div class="section"><h2>Restart urządzenia</h2>

<div class="message success">
Konfiguracja została zachowana.
Urządzenie uruchomi się ponownie za chwilę.
</div>

<p class="note">
Po zmianie statycznego IP otwórz w przeglądarce nowy adres.
W trybie DHCP sprawdź adres w routerze lub serwerze DHCP.
</p>
</div>
)HTML";

  page += htmlFooter();

  server.send(
      200,
      "text/html; charset=utf-8",
      page
  );

  restartRequested = true;
  restartAtMillis = millis() + 1500;
}

void handleStoragePage()
{
  String page = htmlHeader(
      "OpenDCF NTP Server — Pamięć 24C32",
      "storage"
  );

  page += messageHtml();

  page += "<div class='section'><h2>Pamięć 24C32</h2><table>";
  page += "<tr><td>Stan urządzenia</td><td>";
  page += storageDetected ? "WYKRYTE" : "NIE WYKRYTO";
  page += "</td></tr>";
  page += "<tr><td>Adres I2C</td><td>" +
          storageAddressText() + "</td></tr>";
  page += "<tr><td>Pojemność</td><td>4096 B</td></tr>";
  page += "<tr><td>Rozmiar rekordu</td><td>" +
          String(sizeof(OpenDcfPersistentConfig)) + " B</td></tr>";
  page += "<tr><td>Wersja formatu</td><td>" +
          String(persistentConfig.formatVersion) + "</td></tr>";
  page += "<tr><td>Magic</td><td>";
  page += storageConfigValid ? "ODCF" : "---";
  page += "</td></tr>";
  page += "<tr><td>CRC32</td><td>" +
          storageCrcText() + "</td></tr>";
  page += "<tr><td>Ostatni status</td><td>" +
          storageLastStatus + "</td></tr>";
  page += "<tr><td>Dane oczekują na zapis</td><td>";
  page += storageDirty ? "TAK" : "NIE";
  page += "</td></tr>";
  page += "</table></div>";

  page += "<div class='section'><h2>Trwała konfiguracja</h2><table>";
  page += "<tr><td>Hostname</td><td>" +
          String(persistentConfig.hostname) + "</td></tr>";
  page += "<tr><td>Tryb sieci</td><td>";
  page += persistentConfig.useDhcp ? "DHCP" : "STATYCZNY";
  page += "</td></tr>";
  page += "<tr><td>Adres IP</td><td>" +
          arrayToIp(persistentConfig.ip).toString() + "</td></tr>";
  page += "<tr><td>Maska</td><td>" +
          arrayToIp(persistentConfig.mask).toString() + "</td></tr>";
  page += "<tr><td>Brama</td><td>" +
          arrayToIp(persistentConfig.gateway).toString() + "</td></tr>";
  page += "<tr><td>DNS 1</td><td>" +
          arrayToIp(persistentConfig.dns1).toString() + "</td></tr>";
  page += "<tr><td>DNS 2</td><td>" +
          arrayToIp(persistentConfig.dns2).toString() + "</td></tr>";
  page += "</table></div>";

  page += "<div class='section'><h2>Trwałe statystyki</h2><table>";
  page += "<tr><td>Liczba uruchomień</td><td>" +
          String(persistentConfig.bootCount) + "</td></tr>";
  page += "<tr><td>Synchronizacje DCF77</td><td>" +
          String(persistentConfig.totalDcfSyncCount) + "</td></tr>";
  page += "<tr><td>Ostatnia synchronizacja UTC</td><td>";

  if (persistentConfig.lastDcfSyncUtc != 0)
  {
    page += formatDateTime(
        DateTime(persistentConfig.lastDcfSyncUtc)
    ) + " UTC";
  }
  else
  {
    page += "---";
  }

  page += "</td></tr>";
  page += "<tr><td>Ostatnia korekta RTC</td><td>" +
          signedSecondsText(
              persistentConfig.lastRtcCorrectionSeconds
          ) + "</td></tr>";
  page += "<tr><td>Poprawne zapisy pamięci</td><td>" +
          String(persistentConfig.successfulStorageWrites) +
          "</td></tr>";
  page += "<tr><td>Błędy odczytu</td><td>" +
          String(storageReadErrorCount) + "</td></tr>";
  page += "<tr><td>Błędy zapisu</td><td>" +
          String(storageWriteErrorCount) + "</td></tr>";
  page += "</table></div>";

  page += R"HTML(
<div class="section"><h2>Operacje serwisowe</h2>
<div class="box">
<form method="POST" action="/storage-save" style="margin-bottom:14px">
<button type="submit">Zapisz dane teraz</button>
</form>
<form method="POST" action="/storage-reset"
 onsubmit="return confirm('Przywrócić domyślne dane w 24C32?');">
<button type="submit" style="background:#b23b3b">
Przywróć rekord fabryczny
</button>
</form>
<p class="note">
Kasowanie rekordu przywraca domyślną konfigurację sieci:
192.168.200.150/16, brama 192.168.200.254.
Zmiana zacznie obowiązywać po ponownym uruchomieniu.
</p>
</div></div>
)HTML";

  page += htmlFooter();
  server.sendHeader("Cache-Control", "no-store");
  server.send(200, "text/html; charset=utf-8", page);
  webMessage = "";
}

void handleStorageSave()
{
  if (!storageDetected)
  {
    setWebMessage("Nie wykryto pamięci 24C32.", true);
  }
  else if (savePersistentConfig("zapis ręczny z WWW"))
  {
    setWebMessage("Dane zapisano i zweryfikowano.", false);
  }
  else
  {
    setWebMessage("Zapis pamięci nie powiódł się.", true);
  }

  server.sendHeader("Location", "/storage");
  server.send(303);
}

void handleStorageReset()
{
  if (!storageDetected)
  {
    setWebMessage("Nie wykryto pamięci 24C32.", true);
  }
  else
  {
    loadDefaultPersistentConfig();
    storageConfigValid = true;

    if (savePersistentConfig("rekord fabryczny"))
    {
      authSessionToken = "";

      server.sendHeader(
          "Set-Cookie",
          "ODCFSESSION=; Path=/; Max-Age=0; HttpOnly; SameSite=Strict"
      );

      setWebMessage(
          "Przywrócono ustawienia fabryczne. Hasło: admin.",
          false
      );

      server.sendHeader("Location", "/login");
      server.send(303);
      return;
    }
    else
    {
      setWebMessage(
          "Nie udało się zapisać rekordu fabrycznego.",
          true
      );
    }
  }

  server.sendHeader("Location", "/storage");
  server.send(303);
}

// ============================================================
// Ustawianie czasu
// ============================================================

void applyRtcTime(int year, int month, int day,
                  int hour, int minute, int second)
{
  DateTime newTime(year, month, day, hour, minute, second);
  rtc.adjust(newTime);

  rtcLostPower = rtc.lostPower();
  referenceUnix = newTime.unixtime();
  resetClockAnchor(referenceUnix);

  // Ręczne ustawienie czasu unieważnia wcześniejsze powiązanie
  // referencyjne z DCF77. Nowe potwierdzenie wymaga ponownie
  // trzech kolejnych pełnych poprawnych ramek.
  dcfReferenceEstablished = false;
  resetDcfSyncQualification(
      "Czas ustawiono ręcznie — oczekiwanie na 3 ramki DCF77");
  dcfLastSyncStatus = "OCZEKIWANIE NA DCF77";
}

void redirectToTime()
{
  server.sendHeader("Location", "/time");
  server.send(303);
}

void handleSetTimeManual()
{
  if (!rtcReady)
  {
    setWebMessage("Brak komunikacji z DS3231.", true);
    redirectToTime();
    return;
  }

  if (!server.hasArg("date") || !server.hasArg("time"))
  {
    setWebMessage("Nie przesłano daty lub godziny.", true);
    redirectToTime();
    return;
  }

  String d = server.arg("date");
  String t = server.arg("time");

  if (d.length() != 10 || (t.length() != 5 && t.length() != 8))
  {
    setWebMessage("Nieprawidłowy format danych.", true);
    redirectToTime();
    return;
  }

  int year = d.substring(0, 4).toInt();
  int month = d.substring(5, 7).toInt();
  int day = d.substring(8, 10).toInt();
  int hour = t.substring(0, 2).toInt();
  int minute = t.substring(3, 5).toInt();
  int second = t.length() == 8 ? t.substring(6, 8).toInt() : 0;

  if (!isValidDateTime(year, month, day, hour, minute, second))
  {
    setWebMessage("Podana data lub godzina UTC jest nieprawidłowa.", true);
    redirectToTime();
    return;
  }

  applyRtcTime(year, month, day, hour, minute, second);
  String value = formatDateTime(rtc.now());

  Serial.println("[RTC] Ustawiono ręcznie UTC: " + value);
  setWebMessage("Ustawiono czas UTC: " + value, false);
  redirectToTime();
}

void handleSetTimeBrowser()
{
  if (!rtcReady)
  {
    server.send(503, "application/json",
                "{\"success\":false,\"message\":\"Brak komunikacji z DS3231.\"}");
    return;
  }

  const char *args[] =
  {
    "year", "month", "day", "hour", "minute", "second"
  };

  for (const char *arg : args)
  {
    if (!server.hasArg(arg))
    {
      server.send(400, "application/json",
                  "{\"success\":false,\"message\":\"Brakuje danych czasu.\"}");
      return;
    }
  }

  int year = server.arg("year").toInt();
  int month = server.arg("month").toInt();
  int day = server.arg("day").toInt();
  int hour = server.arg("hour").toInt();
  int minute = server.arg("minute").toInt();
  int second = server.arg("second").toInt();

  if (!isValidDateTime(year, month, day, hour, minute, second))
  {
    server.send(400, "application/json",
                "{\"success\":false,\"message\":\"Nieprawidłowy czas UTC.\"}");
    return;
  }

  applyRtcTime(year, month, day, hour, minute, second);
  String value = formatDateTime(rtc.now());

  Serial.println("[RTC] Synchronizacja UTC z komputerem: " + value);

  String json =
      "{\"success\":true,\"message\":\"Zapisano UTC: " +
      value + "\"}";

  server.send(200, "application/json; charset=utf-8", json);
}

void handleNotFound()
{
  server.send(404, "text/plain; charset=utf-8",
              "Nie znaleziono strony: " + server.uri());
}

// ============================================================
// Ethernet / inicjalizacja
// ============================================================

void printNetworkInfo()
{
  Serial.println("========== ETHERNET ==========");
  Serial.println("IP:       " + ETH.localIP().toString());
  Serial.println("Maska:    " + ETH.subnetMask().toString());
  Serial.println("Brama:    " + ETH.gatewayIP().toString());
  Serial.println("MAC:      " + ETH.macAddress());
  Serial.printf("Predkosc: %u Mb/s\n", ETH.linkSpeed());
  Serial.println("==============================");
}

void networkEvent(arduino_event_id_t event)
{
  switch (event)
  {
    case ARDUINO_EVENT_ETH_START:
      ETH.setHostname(
          storageConfigValid
              ? persistentConfig.hostname
              : DEFAULT_HOSTNAME
      );
      Serial.println("[ETH] Interfejs uruchomiony");
      break;

    case ARDUINO_EVENT_ETH_CONNECTED:
      ethernetConnected = true;
      Serial.println("[ETH] Kabel podlaczony");
      break;

    case ARDUINO_EVENT_ETH_GOT_IP:
      ethernetHasIP = true;
      ntpStartRequested = true;
      Serial.println("[ETH] Adres IP aktywny");
      printNetworkInfo();
      break;

    case ARDUINO_EVENT_ETH_LOST_IP:
      ethernetHasIP = false;
      Serial.println("[ETH] Utracono IP");
      break;

    case ARDUINO_EVENT_ETH_DISCONNECTED:
      ethernetConnected = false;
      ethernetHasIP = false;
      Serial.println("[ETH] Kabel odlaczony");
      break;

    case ARDUINO_EVENT_ETH_STOP:
      ethernetConnected = false;
      ethernetHasIP = false;
      Serial.println("[ETH] Interfejs zatrzymany");
      break;

    default:
      break;
  }
}

void initializeRTC()
{
  Serial.println("[RTC] Start I2C");

  if (!Wire.begin(I2C_SDA_PIN, I2C_SCL_PIN, I2C_FREQUENCY))
  {
    Serial.println("[RTC] BLAD I2C");
    return;
  }

  if (!rtc.begin(&Wire))
  {
    Serial.println("[RTC] Nie znaleziono DS3231 pod 0x68");
    return;
  }

  rtcReady = true;
  rtcLostPower = rtc.lostPower();

  rtc.writeSqwPinMode(DS3231_SquareWave1Hz);
  pinMode(SQW_PIN, INPUT);
  attachInterrupt(digitalPinToInterrupt(SQW_PIN), onSqwFallingEdge, FALLING);
  Serial.println("[SQW] 1 Hz aktywne na GPIO36, zbocze FALLING");

  uint32_t currentUnix = rtc.now().unixtime();
  referenceUnix = currentUnix;
  resetClockAnchor(currentUnix);

  Serial.println("[RTC] DS3231 wykryty");
  Serial.println("[RTC] UTC: " + formatDateTime(rtc.now()));

  if (rtcLostPower)
    Serial.println("[RTC] UWAGA: czas wymaga ponownego ustawienia");
}

void initializeEthernet()
{
  Network.onEvent(networkEvent);

  if (!ETH.begin(
          ETH_PHY_TYPE,
          ETH_PHY_ADDR,
          ETH_PHY_MDC,
          ETH_PHY_MDIO,
          ETH_PHY_POWER,
          ETH_CLK_MODE))
  {
    Serial.println("[ETH] BLAD uruchomienia");
    return;
  }

  if (storageConfigValid &&
      persistentConfig.useDhcp)
  {
    Serial.println("[ETH] Tryb DHCP");
  }
  else
  {
    if (!ETH.config(
            localIP,
            gateway,
            subnet,
            primaryDNS,
            secondaryDNS))
    {
      Serial.println(
          "[ETH] BLAD konfiguracji statycznej"
      );
    }
    else
    {
      Serial.println(
          "[ETH] Statyczna konfiguracja IP aktywna"
      );
    }
  }
}

void initializeWebServer()
{
  const char *headerKeys[] = {"Cookie"};
  server.collectHeaders(headerKeys, 1);

  // Publiczne.
  server.on("/", HTTP_GET, handleRoot);
  server.on("/login", HTTP_GET, handleLoginPage);
  server.on("/login", HTTP_POST, handleLoginSubmit);
  server.on("/logout", HTTP_GET, handleLogout);

  // Chronione strony.
  server.on("/time", HTTP_GET, []()
  {
    if (requireAuthentication())
      handleTimePage();
  });

  server.on("/ntp", HTTP_GET, []()
  {
    if (requireAuthentication())
      handleNtpPage();
  });

  server.on("/dcf", HTTP_GET, []()
  {
    if (requireAuthentication())
      handleDcfPage();
  });

  server.on("/network", HTTP_GET, []()
  {
    if (requireAuthentication())
      handleNetworkPage();
  });

  server.on("/storage", HTTP_GET, []()
  {
    if (requireAuthentication())
      handleStoragePage();
  });

  server.on("/security", HTTP_GET, []()
  {
    if (requireAuthentication())
      handleSecurityPage();
  });

  // Chronione operacje.
  server.on("/network-save", HTTP_POST, []()
  {
    if (requireAuthentication())
      handleNetworkSave();
  });

  server.on("/restart", HTTP_POST, []()
  {
    if (requireAuthentication())
      handleRestart();
  });

  server.on("/storage-save", HTTP_POST, []()
  {
    if (requireAuthentication())
      handleStorageSave();
  });

  server.on("/storage-reset", HTTP_POST, []()
  {
    if (requireAuthentication())
      handleStorageReset();
  });

  server.on("/set-time-manual", HTTP_POST, []()
  {
    if (requireAuthentication())
      handleSetTimeManual();
  });

  server.on("/set-time-browser", HTTP_POST, []()
  {
    if (requireAuthenticationJson())
      handleSetTimeBrowser();
  });

  server.on("/security-password", HTTP_POST, []()
  {
    if (requireAuthentication())
      handlePasswordChange();
  });

  server.onNotFound(handleNotFound);
  server.begin();

  Serial.println("[HTTP] Serwer uruchomiony na TCP/80");
}

// ============================================================
// Arduino
// ============================================================

void setup()
{
  Serial.begin(115200);
  delay(1000);

  Serial.println();
  Serial.println("========================================");
  Serial.println(" OpenDCF NTP SERVER - WT32-ETH01");
  Serial.println(" Firmware 1.0.0 DCF FIFO");
  Serial.println(" DS3231 przechowuje UTC");
  Serial.println("========================================");

  initializeRTC();
  initializeStorage();
  initializeDcf77();
  initializeEthernet();
  initializeWebServer();
}

void loop()
{
  server.handleClient();
  pollRtcClock();
  processDcf77Signal();
  processStorage();

  if (restartRequested &&
      static_cast<int32_t>(
          millis() - restartAtMillis
      ) >= 0)
  {
    Serial.println("[SYSTEM] Restart...");
    delay(50);
    ESP.restart();
  }

  if (ntpStartRequested && ethernetHasIP)
    startNtpServer();

  if (!ethernetHasIP && ntpSocketStarted)
    stopNtpServer();

  handleNtpPackets();

  static uint32_t previousLog = 0;
  if (rtcReady && millis() - previousLog >= 10000)
  {
    previousLog = millis();

    Serial.print("[RTC] UTC ");
    Serial.print(formatDateTime(rtc.now()));
    Serial.print(" | DCF=");
    Serial.print(dcfSignalDetected ? "OK" : "---");
    Serial.print(" bit=");
    Serial.print(dcfLastBitText());
    Serial.print(" frames=");
    Serial.print(dcfValidFrameCount);
    Serial.print(" seq=");
    Serial.print(dcfConsecutiveValidFrames);
    Serial.print(" qualify=");
    Serial.print(dcfFramesQualifiedForSync);
    Serial.print("/");
    Serial.print(DCF_FRAMES_REQUIRED_FOR_SYNC);
    Serial.print(" source=");
    Serial.print(dcfReferenceEstablished ? "DCF" : "RTC");
    Serial.print(" | NTP req=");
    Serial.print(ntpRequestCount);
    Serial.print(" resp=");
    Serial.print(ntpResponseCount);
    Serial.print(" | SQW=");
    Serial.print(sqwSignalValid ? "OK" : "FALLBACK");
    Serial.print(" pulses=");
    Serial.print(sqwPulseCount);
    Serial.print(" periodErrUs=");
    Serial.print(lastSqwPeriodErrorUs);
    Serial.print(" | DCF edges=");
    Serial.print(dcfEdgeCount);
    Serial.print(" fifoLost=");
    Serial.print(dcfEdgeQueueOverflowCount);
    Serial.print(" resets=");
    Serial.println(dcfParserResetCount);
  }

  delay(1);
}