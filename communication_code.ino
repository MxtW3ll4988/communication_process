/**
 * @file    communication_code.ino
 * @brief   Enlace optico LED -> fototransistor con codigo Hamming(7,4),
 *          medicion de BER y prueba de integridad con cifrado XOR (Vernam).
 *
 * DESCRIPCION GENERAL
 * -------------------
 * Un LED transmite un mensaje de texto bit a bit y un fototransistor lo recibe
 * (ambos conectados a la misma placa Arduino). El programa corre UNA sola vez
 * dentro de setup() y compara tres escenarios:
 *
 *   FASE 1  Transmision SIN codigo: cada caracter se envia como 8 bits ASCII.
 *   FASE 2  Transmision CON Hamming(7,4): cada caracter se divide en 2 nibbles
 *           y cada nibble se envia como una palabra de 7 bits (14 bits/caracter,
 *           tasa de codigo 4/7). Corrige 1 bit erroneo por palabra y recupera
 *           hasta 2 bits "borrados" (anomalias del sensor).
 *   FASE 3  Test de integridad (opcional, ver ENABLE_INTEGRITY_TEST):
 *           - TEST A : un atacante inyecta una trama falsa codificada con
 *                      Hamming. Hamming NO detecta la falsificacion (solo
 *                      corrige errores de canal, no autentica).
 *           - TEST B1: trama legitima cifrada con XOR (clave de un solo uso)
 *                      + Hamming. Se recupera intacta.
 *           - TEST B2: la trama falsa llega a un receptor que descifra con XOR;
 *                      el atacante no tiene la clave, asi que el resultado es
 *                      basura.
 *   FINAL   Se muestra en el LCD y por Serial la comparacion de BER
 *           (Bit Error Rate) sin codigo vs. con Hamming.
 *
 * HARDWARE
 * --------
 *   - LED emisor ............. pin digital 9
 *   - Fototransistor ......... pin analogico A0 (receptor)
 *   - LCD 16x2 (HD44780) ..... RS=2, E=3, D4=4, D5=5, D6=6, D7=7
 *   - Pin A2 SIN conectar .... fuente de ruido para generar la clave XOR
 *   - Serial ................. 9600 baudios (log detallado de todo el proceso)
 *
 * PROTOCOLO DE BITS
 * -----------------
 *   - Duracion de cada bit: BIT_DURATION_US (1000 us -> 1000 bps).
 *   - El receptor muestrea SENSOR_SETTLE_US (300 us) despues de encender/apagar
 *     el LED para dar tiempo a que el fototransistor se estabilice.
 *   - La lectura analogica se clasifica en '0', '1' o ANOMALIA segun los rangos
 *     ZERO_MIN..ZERO_MAX y ONE_MIN..ONE_MAX (calibrar segun el montaje).
 *
 * DISTRIBUCION DE LA PALABRA HAMMING(7,4)
 * ---------------------------------------
 *   posicion:  1   2   3   4   5   6   7
 *   bit:       p1  p2  d1  p3  d2  d3  d4
 *
 *   p1 = d1 ^ d2 ^ d4      (cubre posiciones 1,3,5,7)
 *   p2 = d1 ^ d3 ^ d4      (cubre posiciones 2,3,6,7)
 *   p3 = d2 ^ d3 ^ d4      (cubre posiciones 4,5,6,7)
 *
 *   El sindrome (s3 s2 s1) en binario indica la posicion del bit erroneo
 *   (0 = sin error).
 *
 * NOTAS IMPORTANTES
 *   - Usa memoria dinamica (realloc/free) para los buffers de recepcion; en
 *     placas con poca RAM (Uno/Nano) conviene vigilar el tamano del mensaje.
 *   - La clave XOR se muestra por Serial SOLO con fines didacticos.
 */

#include <string.h>
#include <stdlib.h>
#include <LiquidCrystal.h>

// CONFIGURATION
const int LED = 9;  // Pin digital del LED emisor
const int SENSOR = A0;  // Pin analogico del fototransistor receptor

const unsigned long BIT_DURATION_US = 1000;  // Duracion de cada bit (us) -> 1000 bps
const unsigned int SENSOR_SETTLE_US = 300;  // Espera antes de leer el sensor (us)

const int ZERO_MIN = 0;  // Rango de lectura ADC que se interpreta como bit 0
const int ZERO_MAX = 1;

const int ONE_MIN = 15;  // Rango de lectura ADC que se interpreta como bit 1
const int ONE_MAX = 30;

// ERROR INJECTION (controlled)
// Se invierte 1 bit cada ERROR_PERIOD bits transmitidos, empezando en ERROR_OFFSET.
// Con ERROR_PERIOD >= 7 nunca caen 2 errores en la misma palabra Hamming (7,4),
// por lo que todos se pueden corregir. Si se baja de 7, apareceran errores
// no corregibles (util para mostrar el limite del codigo).
const unsigned int ERROR_PERIOD = 20;  // Un error cada 20 bits
const unsigned int ERROR_OFFSET = 9;  // Posicion (dentro del periodo) del bit que se invierte

// INTEGRITY TEST (trama falsa + cifrado XOR/Vernam)
// true  -> corre el test de integridad despues de las fases 1 y 2
// false -> se omite por completo
const bool ENABLE_INTEGRITY_TEST = true;  // Activa/desactiva la fase 3

// Pin analogico LIBRE (sin conectar) usado como fuente de ruido para la clave
const int KEY_NOISE_PIN = A2;  // Debe quedar sin conectar

// Mensaje que inyecta el atacante (se rellena con espacios / se recorta a arrSize)
const char forgedMessage[] PROGMEM = "estas hackeado";  // Guardado en flash para ahorrar RAM

LiquidCrystal lcd(2, 3, 4, 5, 6, 7);  // RS, E, D4, D5, D6, D7

// INPUT
char message[] = "proyecto senales de transmisioon";  // Mensaje legitimo a transmitir

const size_t arrSize = sizeof(message) - 1;  // Longitud del mensaje (sin el '\0')

int codes[arrSize];  // Codigos ASCII del mensaje original
char bits[arrSize][9];  // Representacion binaria (8 bits + '\0') de cada caracter

// SIGNAL STATE
enum SignalState {
  SIGNAL_ZERO,
  SIGNAL_ONE,
  SIGNAL_ANOMALY
};

// RECEIVED DATA
char* receivedBits = nullptr;  // Registro de todos los bits validos recibidos
size_t receivedBitCount = 0;  // Cantidad de bits en receivedBits

char binary[9] = "";  // Byte parcial en construccion (modo sin codigo)
int bitCount = 0;  // Bits acumulados en binary

bool memoryError = false;  // true si fallo una asignacion de memoria

int codeASCII = 0;  // Ultimo caracter decodificado

int* receivedMessage = nullptr;  // Caracteres recibidos (memoria dinamica)
size_t receivedCount = 0;  // Cantidad de caracteres en receivedMessage

// HAMMING / BER STATE
bool hammingMode = false;            // false: sin codigo | true: Hamming(7,4)

char hammingWord[8] = "";            // palabra de 7 bits recibida (+ '\0')
int hammingBitCount = 0;
int pendingNibble = -1;              // primer nibble recibido (-1 = ninguno)

unsigned long channelBitIndex = 0;   // contador de bits que pasan por el canal
unsigned long injectedErrors = 0;    // errores inyectados
unsigned long correctedErrors = 0;   // errores corregidos por Hamming
unsigned long erasuresRecovered = 0; // palabras con bits perdidos (anomalia) recuperadas
unsigned long wordsLost = 0;         // palabras no recuperables

float berNoCode = 0.0;
float berHamming = 0.0;

// INTEGRITY / CIPHER STATE
uint8_t key[arrSize];                // clave de un solo uso (tan larga como el mensaje)
bool keyReady = false;               // true = clave valida y aun sin usar
uint8_t wire[arrSize];               // bytes que realmente viajan por el enlace

// FUNCTION PROTOTYPES
// Encoding
void textToAsciiCodes(const char* message, int* codes);
bool integerToBinaryAscii(const int* codes, char bits[][9]);
void hammingEncodeNibble(uint8_t nibble, char cw[8]);

// Transmission
void transmitBinaryData(const char* bits, int nBits = 8);
void processTransmission();
void processHammingTransmission();
void sendHammingPayload(const uint8_t* payload);

// Phototransistor
int readSignal();
SignalState classifySignal(int reading);
char appendBit(SignalState state);
bool storeBit(char sbit);

// Error injection / BER
char injectError(char sbit);
void resetChannelState();
unsigned long countBitErrors(const int* rx, size_t rxCount);

// Decoding
int binaryToIntegerAscii(const char binary[9]);
void receiveBit(char bitt);
int hammingDecodeWord(const char cw[8], uint8_t* nibble);
uint8_t hammingSyndrome(const uint8_t b[8]);
void receiveHammingBit(char bitt);
bool storeReceivedCode(int code);
void processReceivedMessage();
void displayReceivedCharacter(int* receivedMessage);
void displayBER();

// Integrity / XOR (Vernam)
void generateKey();
void eraseKey();
bool xorEncrypt(const int* plain, uint8_t* out);
bool xorDecrypt(int* data, size_t count);
uint8_t forgedByte(size_t i);
unsigned long countFrameErrors(const int* rx, size_t rxCount, bool againstForged, size_t* matched);
void printFrameText(const int* rx, size_t rxCount);
void printHexBuffer(const uint8_t* data, size_t n);
void clearReceivedData();
void showLcd(const __FlashStringHelper* line1, const __FlashStringHelper* line2);
void processIntegrityTest();

// Auxiliary
bool checkMemoryAllocation(void* ptr);
bool isValidBit(char vbit);

// SETUP AND LOOP
/**
 * @brief Inicializa el hardware y ejecuta todas las fases del experimento.
 *
 * Orden de ejecucion:
 *   1) Transmision sin codigo        -> processTransmission + processReceivedMessage
 *   2) Transmision con Hamming(7,4)  -> processHammingTransmission + processReceivedMessage
 *   3) Test de integridad (si ENABLE_INTEGRITY_TEST) -> processIntegrityTest
 *   4) Comparacion final de BER      -> displayBER
 */
void setup() {
  pinMode(LED, OUTPUT);
  pinMode(SENSOR, INPUT);

  digitalWrite(LED, LOW);

  Serial.begin(9600);

  lcd.begin(16, 2);
  lcd.clear();
  lcd.print(F("En Proceso"));

  delay(1000);

  // 1) Transmision SIN codigo (con errores inyectados)
  processTransmission();
  processReceivedMessage();

  // 2) Transmision CON Hamming(7,4) (mismos errores inyectados)
  processHammingTransmission();
  processReceivedMessage();

  // 3) Test de integridad: trama falsa + cifrado XOR/Vernam (activable)
  if (ENABLE_INTEGRITY_TEST) {
    processIntegrityTest();
  }

  // 4) Comparacion de BER en el LCD
  delay(3000);
  displayBER();
}

/**
 * @brief No se usa: todo el experimento corre una sola vez en setup().
 */
void loop() {}

// ENCODING
/**
 * @brief Convierte una cadena de texto en su arreglo de codigos ASCII.
 * @param message Cadena terminada en '\0' a convertir.
 * @param codes   Arreglo de salida (debe tener al menos strlen(message) elementos).
 */
void textToAsciiCodes(const char* message, int* codes) {
  for (size_t i = 0; message[i] != '\0'; i++) {
    codes[i] = (unsigned char)message[i];
  }
}

/**
 * @brief Convierte cada codigo ASCII a una cadena de 8 caracteres '0'/'1' (MSB primero).
 * @param codes Codigos ASCII de entrada (arrSize elementos).
 * @param bits  Salida: bits[i] es la cadena binaria (8 bits + '\0') del caracter i.
 * @return true si todos los codigos estan en 0..255; false si alguno esta fuera de rango.
 */
bool integerToBinaryAscii(const int* codes, char bits[][9]) {
  for (size_t j = 0; j < arrSize; j++) {
    if (codes[j] < 0 || codes[j] > 255) {
      return false;
    }
  }

  for (size_t y = 0; y < arrSize; y++) {
    for (int x = 7; x >= 0; x--) {
      bits[y][7 - x] =
        (codes[y] & (1 << x)) ? '1' : '0';
    }

    bits[y][8] = '\0';
  }

  return true;
}

// Hamming(7,4): palabra = p1 p2 d1 p3 d2 d3 d4
/**
 * @brief Codifica un nibble (4 bits) como palabra Hamming(7,4).
 *
 * Formato de salida (posiciones 1..7): p1 p2 d1 p3 d2 d3 d4, donde d1 es el
 * bit mas significativo del nibble.
 *
 * @param nibble Valor de 4 bits (0..15) a codificar.
 * @param cw     Salida: 7 caracteres '0'/'1' mas '\0' (8 bytes en total).
 */
void hammingEncodeNibble(uint8_t nibble, char cw[8]) {
  uint8_t d1 = (nibble >> 3) & 1;
  uint8_t d2 = (nibble >> 2) & 1;
  uint8_t d3 = (nibble >> 1) & 1;
  uint8_t d4 = nibble & 1;

  uint8_t p1 = d1 ^ d2 ^ d4;
  uint8_t p2 = d1 ^ d3 ^ d4;
  uint8_t p3 = d2 ^ d3 ^ d4;

  cw[0] = '0' + p1;
  cw[1] = '0' + p2;
  cw[2] = '0' + d1;
  cw[3] = '0' + p3;
  cw[4] = '0' + d2;
  cw[5] = '0' + d3;
  cw[6] = '0' + d4;
  cw[7] = '\0';
}

// TRANSMISSION
// nBits = 8 para ASCII sin codigo, 7 para una palabra Hamming(7,4)
/**
 * @brief Transmite bits por el LED y los recibe con el fototransistor (bit a bit).
 *
 * Por cada bit: enciende/apaga el LED, espera SENSOR_SETTLE_US, lee el sensor,
 * lo clasifica ('0', '1' o anomalia) y lo entrega al decodificador segun el
 * modo activo:
 *   - Modo normal: receiveBit(). Una anomalia se DESCARTA.
 *   - Modo Hamming: receiveHammingBit(). Una anomalia se marca como '?'
 *     (borrado) para conservar la posicion dentro de la palabra.
 * Cada bit dura exactamente BIT_DURATION_US microsegundos.
 *
 * Nota: la inyeccion de error esta comentada (ver notas en el encabezado).
 *
 * @param bits  Cadena de '0'/'1' a transmitir.
 * @param nBits Cantidad de bits a enviar: 8 (ASCII sin codigo) o 7 (palabra Hamming).
 *              Si ocurre un error de memoria la transmision se aborta.
 */
void transmitBinaryData(const char* bits, int nBits) {
  for (int i = 0; i < nBits; i++) {
    unsigned long startBit = micros();

    digitalWrite(LED, bits[i] == '1' ? HIGH : LOW);

    delayMicroseconds(SENSOR_SETTLE_US);

    int reading = readSignal();
    SignalState state = classifySignal(reading);
    char sbit = appendBit(state);

    // Inyeccion controlada de error sobre el bit detectado
    char cleanBit = sbit;
    //sbit = injectError(sbit);

    Serial.print(F("Sent: "));
    Serial.print(bits[i]);

    Serial.print(F(" | Reading: "));
    Serial.print(reading);

    Serial.print(F(" | Detected: "));

    if (sbit != '\0') {
      Serial.print(sbit);

      if (sbit != cleanBit) {
        Serial.print(F(" [ERROR INJECTED]"));
      }

      Serial.println();

      if (storeBit(sbit)) {
        if (hammingMode) {
          receiveHammingBit(sbit);
        } else {
          receiveBit(sbit);
        }
      } else {
        Serial.println(F("ERROR: Could not store bit."));
        memoryError = true;
      }
    } else {
      Serial.println(F("ANOMALY"));

      if (hammingMode) {
        // No se descarta el bit: se marca como borrado ('?') para conservar
        // la posicion dentro de la palabra y mantener la alineacion.
        Serial.println(F("WARNING: Bit marked as erasure (alignment kept)."));
        receiveHammingBit('?');
      } else {
        Serial.println(F("WARNING: Bit discarded."));
      }
    }

    while (micros() - startBit < BIT_DURATION_US) { }

    if (memoryError) {
      digitalWrite(LED, LOW);
      return;
    }
  }

  digitalWrite(LED, LOW);
}

// PHOTOTRANSISTOR
/**
 * @brief Lee el valor analogico crudo del fototransistor (0..1023).
 * @return Lectura del ADC en el pin SENSOR (A0).
 */
int readSignal() {
  return analogRead(SENSOR);
}

/**
 * @brief Clasifica una lectura analogica segun los umbrales configurados.
 * @param reading Lectura del ADC.
 * @return SIGNAL_ZERO si esta en [ZERO_MIN, ZERO_MAX],
 *         SIGNAL_ONE  si esta en [ONE_MIN, ONE_MAX],
 *         SIGNAL_ANOMALY en cualquier otro caso (zona intermedia / ruido).
 */
SignalState classifySignal(int reading) {
  if (reading >= ZERO_MIN && reading <= ZERO_MAX) {
    return SIGNAL_ZERO;
  }

  if (reading >= ONE_MIN && reading <= ONE_MAX) {
    return SIGNAL_ONE;
  }

  return SIGNAL_ANOMALY;
}

/**
 * @brief Convierte el estado de la senal en el caracter de bit correspondiente.
 * @param state Estado devuelto por classifySignal().
 * @return '1', '0', o '\0' si la senal fue una anomalia.
 */
char appendBit(SignalState state) {
  if (state == SIGNAL_ANOMALY) {
    return '\0';
  }

  return (state == SIGNAL_ONE) ? '1' : '0';
}

/**
 * @brief Agrega un bit valido al buffer dinamico receivedBits (registro de todo lo recibido).
 *
 * Usa realloc para crecer el buffer y lo mantiene terminado en '\0'.
 *
 * @param sbit Bit recibido ('0' o '1').
 * @return true si se almaceno; false si el bit no es valido o falta memoria
 *         (en ese caso se activa memoryError).
 */
bool storeBit(char sbit) {
  if (!isValidBit(sbit)) {
    return false;
  }

  char* temp = static_cast<char*>(
    realloc(receivedBits, receivedBitCount + 2)
  );

  if (!checkMemoryAllocation(temp)) {
    memoryError = true;
    return false;
  }

  receivedBits = temp;

  receivedBits[receivedBitCount] = sbit;
  receivedBitCount++;

  receivedBits[receivedBitCount] = '\0';

  return true;
}

// ERROR INJECTION / BER
// Invierte un bit cada ERROR_PERIOD bits (patron determinista y repetible)
/**
 * @brief Inyecta errores de canal de forma determinista y repetible.
 *
 * Invierte un bit cada ERROR_PERIOD bits que pasan por el canal, empezando en
 * ERROR_OFFSET. Incrementa channelBitIndex en cada llamada e injectedErrors
 * cada vez que invierte un bit.
 *
 * @param sbit Bit detectado ('0' o '1'; las anomalias no se alteran).
 * @return El bit original, o su complemento si le toca error.
 */
char injectError(char sbit) {
  bool flip = (channelBitIndex % ERROR_PERIOD) == ERROR_OFFSET;
  channelBitIndex++;

  if (flip && isValidBit(sbit)) {
    injectedErrors++;
    return (sbit == '1') ? '0' : '1';
  }

  return sbit;
}

// Reinicia contadores para que ambas fases vean el mismo patron de errores
/**
 * @brief Reinicia contadores y buffers de estado del canal y del decodificador.
 *
 * Se llama antes de cada fase para que todas vean el mismo patron de errores
 * y empiecen con las palabras/bytes parciales vacios.
 */
void resetChannelState() {
  channelBitIndex = 0;
  injectedErrors = 0;
  correctedErrors = 0;
  erasuresRecovered = 0;
  wordsLost = 0;

  bitCount = 0;
  binary[0] = '\0';

  hammingBitCount = 0;
  hammingWord[0] = '\0';
  pendingNibble = -1;
}

// Bits distintos entre el mensaje original (codes) y el recibido.
// Los caracteres que no llegaron cuentan como 8 bits erroneos.
/**
 * @brief Cuenta los bits distintos entre el mensaje original (codes) y el recibido.
 * @param rx      Caracteres recibidos (codigos ASCII).
 * @param rxCount Cantidad de caracteres recibidos.
 * @return Total de bits erroneos. Cada caracter que no llego cuenta como 8 errores.
 */
unsigned long countBitErrors(const int* rx, size_t rxCount) {
  unsigned long errors = 0;

  for (size_t i = 0; i < arrSize; i++) {
    if (i < rxCount) {
      uint8_t diff = (uint8_t)(codes[i] ^ rx[i]);

      while (diff) {
        errors += diff & 1;
        diff >>= 1;
      }
    } else {
      errors += 8;
    }
  }

  return errors;
}

// DECODING
/**
 * @brief Receptor SIN codigo: acumula bits y forma un caracter cada 8.
 *
 * Al completar 8 bits convierte a ASCII, lo agrega a receivedMessage
 * (memoria dinamica) y lo imprime por Serial.
 *
 * @param bitt Bit recibido ('0' o '1'). Cualquier otro valor se ignora.
 */
void receiveBit(char bitt) {
  if (!isValidBit(bitt) || memoryError) {
    return;
  }

  binary[bitCount] = bitt;
  bitCount++;

  if (bitCount == 8) {
    binary[8] = '\0';

    codeASCII = binaryToIntegerAscii(binary);

    int* temp = static_cast<int*>(
      realloc(
        receivedMessage,
        (receivedCount + 1) * sizeof(int)
      )
    );

    if (!checkMemoryAllocation(temp)) {
      memoryError = true;
      return;
    }

    receivedMessage = temp;
    receivedMessage[receivedCount] = codeASCII;
    receivedCount++;

    Serial.print(F("Received byte: "));
    Serial.print(binary);
    Serial.print(F(" | ASCII: "));
    Serial.print(codeASCII);

    if (codeASCII >= 32 && codeASCII <= 126) {
      Serial.print(F(" | Character: "));
      Serial.write((char)codeASCII);
    }

    Serial.println();

    bitCount = 0;
  }
}

/**
 * @brief Convierte una cadena de 8 caracteres '0'/'1' (MSB primero) a entero.
 * @param binary Cadena binaria de 8 bits.
 * @return Valor numerico (0..255).
 */
int binaryToIntegerAscii(const char binary[9]) {
  int code = 0;

  for (int i = 0; i < 8; i++) {
    code <<= 1;

    if (binary[i] == '1') {
      code |= 1;
    }
  }

  return code;
}

// Sindrome de una palabra de 7 bits (b[1..7]). 0 = palabra valida.
/**
 * @brief Calcula el sindrome de una palabra Hamming(7,4).
 * @param b Bits de la palabra indexados de 1 a 7 (b[0] no se usa).
 * @return 0 si la palabra es valida; en otro caso, la posicion (1..7) del bit erroneo.
 */
uint8_t hammingSyndrome(const uint8_t b[8]) {
  uint8_t s1 = b[1] ^ b[3] ^ b[5] ^ b[7];
  uint8_t s2 = b[2] ^ b[3] ^ b[6] ^ b[7];
  uint8_t s3 = b[4] ^ b[5] ^ b[6] ^ b[7];

  return s1 + (s2 << 1) + (s3 << 2);
}

// Decodifica una palabra Hamming(7,4). Los bits perdidos por anomalia llegan
// como '?' (borrados). Como la distancia minima es 3, se pueden recuperar
// hasta 2 borrados probando sus combinaciones y quedandose con la unica que
// da sindrome 0.
// Retorna: 0  -> sin errores (o borrados recuperados)
//          >0 -> posicion (1..7) del bit corregido
//          -1 -> palabra no recuperable (mejor esfuerzo)
/**
 * @brief Decodifica una palabra Hamming(7,4) y obtiene el nibble de datos.
 *
 * Maneja dos tipos de problema:
 *  - Error: un bit invertido. Se corrige con el sindrome.
 *  - Borrado: un bit perdido por anomalia, que llega como '?'. Como la
 *    distancia minima del codigo es 3, se pueden recuperar hasta 2 borrados
 *    probando todas sus combinaciones y quedandose con la que da sindrome 0.
 *
 * @param cw     Palabra recibida: 7 caracteres '0'/'1'/'?'.
 * @param nibble Salida: nibble de datos (d1 d2 d3 d4) decodificado.
 * @return 0  sin errores (o borrados recuperados),
 *         >0 posicion (1..7) del bit corregido,
 *         -1 palabra no recuperable (se devuelve el mejor esfuerzo).
 */
int hammingDecodeWord(const char cw[8], uint8_t* nibble) {
  uint8_t b[8];
  int erasePos[7];
  int eraseCount = 0;

  for (int i = 1; i <= 7; i++) {
    if (cw[i - 1] == '?') {
      b[i] = 0;
      erasePos[eraseCount] = i;
      eraseCount++;
    } else {
      b[i] = (cw[i - 1] == '1') ? 1 : 0;
    }
  }

  int result = 0;

  if (eraseCount > 0) {
    bool recovered = false;

    if (eraseCount <= 2) {
      for (int mask = 0; mask < (1 << eraseCount) && !recovered; mask++) {
        for (int k = 0; k < eraseCount; k++) {
          b[erasePos[k]] = (mask >> k) & 1;
        }

        if (hammingSyndrome(b) == 0) {
          recovered = true;
        }
      }
    }

    if (!recovered) {
      // Borrado + error extra (o mas de 2 borrados): no hay solucion unica.
      for (int k = 0; k < eraseCount; k++) {
        b[erasePos[k]] = 0;
      }

      result = -1;
    }
  }

  if (result == 0) {
    int syndrome = hammingSyndrome(b);

    if (syndrome != 0) {
      b[syndrome] ^= 1;
      result = syndrome;
    }
  } else {
    int syndrome = hammingSyndrome(b);

    if (syndrome != 0) {
      b[syndrome] ^= 1;
    }
  }

  *nibble = (b[3] << 3) | (b[5] << 2) | (b[6] << 1) | b[7];

  return result;
}

// Agrupa bits en palabras de 7, decodifica y junta 2 nibbles en 1 caracter
/**
 * @brief Receptor CON Hamming: agrupa bits en palabras de 7, las decodifica y
 *        une 2 nibbles para formar un caracter.
 *
 * Actualiza los contadores correctedErrors, erasuresRecovered y wordsLost, e
 * imprime un registro por Serial de cada correccion.
 *
 * @param bitt '0' o '1' (bit valido) o '?' (bit perdido que conserva su posicion).
 */
void receiveHammingBit(char bitt) {
  // '?' = bit perdido (anomalia) que conserva su posicion en la palabra
  if ((!isValidBit(bitt) && bitt != '?') || memoryError) {
    return;
  }

  hammingWord[hammingBitCount] = bitt;
  hammingBitCount++;

  if (hammingBitCount == 7) {
    hammingWord[7] = '\0';

    int erasures = 0;
    for (int i = 0; i < 7; i++) {
      if (hammingWord[i] == '?') {
        erasures++;
      }
    }

    uint8_t nibble = 0;
    int syndrome = hammingDecodeWord(hammingWord, &nibble);

    if (syndrome > 0) {
      correctedErrors++;
      Serial.print(F("Hamming: word "));
      Serial.print(hammingWord);
      Serial.print(F(" | error corrected at position "));
      Serial.println(syndrome);
    } else if (syndrome == 0 && erasures > 0) {
      erasuresRecovered++;
      Serial.print(F("Hamming: word "));
      Serial.print(hammingWord);
      Serial.println(F(" | erasure(s) recovered"));
    } else if (syndrome < 0) {
      wordsLost++;
      Serial.print(F("Hamming: word "));
      Serial.print(hammingWord);
      Serial.println(F(" | WARNING: word not recoverable"));
    }

    hammingBitCount = 0;

    if (pendingNibble < 0) {
      pendingNibble = nibble;
    } else {
      codeASCII = (pendingNibble << 4) | nibble;
      pendingNibble = -1;

      if (!storeReceivedCode(codeASCII)) {
        memoryError = true;
        return;
      }

      Serial.print(F("Received byte (Hamming) | ASCII: "));
      Serial.print(codeASCII);

      if (codeASCII >= 32 && codeASCII <= 126) {
        Serial.print(F(" | Character: "));
        Serial.write((char)codeASCII);
      }

      Serial.println();
    }
  }
}

/**
 * @brief Agrega un caracter decodificado al arreglo dinamico receivedMessage.
 * @param code Codigo ASCII a guardar.
 * @return true si se guardo; false si no hay memoria suficiente.
 */
bool storeReceivedCode(int code) {
  int* temp = static_cast<int*>(
    realloc(
      receivedMessage,
      (receivedCount + 1) * sizeof(int)
    )
  );

  if (!checkMemoryAllocation(temp)) {
    return false;
  }

  receivedMessage = temp;
  receivedMessage[receivedCount] = code;
  receivedCount++;

  return true;
}

// MESSAGE PROCESSING
/**
 * @brief FASE 1: transmite el mensaje completo SIN codigo (8 bits por caracter).
 *
 * Prepara el estado (hammingMode = false), convierte el mensaje a binario y lo
 * envia caracter por caracter con transmitBinaryData(). Se detiene si hay
 * error de memoria.
 */
void processTransmission() {
  Serial.println();
  Serial.println(F("================================"));
  Serial.println(F("PHASE 1: WITHOUT CODE"));
  Serial.print(F("Original message: "));
  Serial.println(message);

  Serial.print(F("Characters to transmit: "));
  Serial.println(arrSize);

  Serial.println(F("================================"));

  hammingMode = false;
  resetChannelState();

  textToAsciiCodes(message, codes);

  if (!integerToBinaryAscii(codes, bits)) {
    Serial.println(F("ERROR: ASCII code out of range."));
    return;
  }

  for (size_t i = 0; i < arrSize; i++) {
    Serial.println();

    Serial.print(F("Character "));
    Serial.print(i);
    Serial.print(F(": "));
    Serial.write(message[i]);

    Serial.print(F(" | ASCII: "));
    Serial.print(codes[i]);

    Serial.print(F(" | Binary sent: "));
    Serial.println(bits[i]);

    transmitBinaryData(bits[i]);

    if (memoryError) {
      Serial.println(F("Transmission stopped due to memory error."));
      return;
    }
  }

  digitalWrite(LED, LOW);
}

// Cada caracter (8 bits) se divide en 2 nibbles; cada nibble se codifica
// en una palabra Hamming(7,4) -> 14 bits transmitidos por caracter.
/**
 * @brief FASE 2: transmite el mensaje completo CON Hamming(7,4).
 *
 * Cada caracter (8 bits) se divide en 2 nibbles y cada nibble se codifica como
 * una palabra de 7 bits: 14 bits transmitidos por caracter.
 */
void processHammingTransmission() {
  Serial.println();
  Serial.println(F("================================"));
  Serial.println(F("PHASE 2: WITH HAMMING(7,4)"));
  Serial.print(F("Original message: "));
  Serial.println(message);

  Serial.print(F("Characters to transmit: "));
  Serial.println(arrSize);

  Serial.print(F("Bits per character: 14 (code rate 4/7)"));
  Serial.println();

  Serial.println(F("================================"));

  hammingMode = true;
  resetChannelState();

  textToAsciiCodes(message, codes);

  for (size_t i = 0; i < arrSize; i++) {
    wire[i] = (uint8_t)codes[i];
  }

  sendHammingPayload(wire);
}

// Transmite arrSize bytes; cada byte se envia como 2 palabras Hamming(7,4)
/**
 * @brief Transmite arrSize bytes codificados con Hamming(7,4).
 *
 * Cada byte se envia como 2 palabras: primero el nibble alto y luego el bajo.
 * Se reutiliza en la fase 2 y en los tests de integridad (payload en claro,
 * cifrado o trama falsa).
 *
 * @param payload Arreglo de arrSize bytes a enviar.
 */
void sendHammingPayload(const uint8_t* payload) {
  char cw[2][8];

  for (size_t i = 0; i < arrSize; i++) {
    hammingEncodeNibble((payload[i] >> 4) & 0x0F, cw[0]);
    hammingEncodeNibble(payload[i] & 0x0F, cw[1]);

    Serial.println();

    Serial.print(F("Character "));
    Serial.print(i);
    Serial.print(F(": "));
    char shown = (payload[i] >= 32 && payload[i] <= 126) ? (char)payload[i] : '.';
    Serial.write(shown);

    Serial.print(F(" | ASCII: "));
    Serial.print(payload[i]);

    Serial.print(F(" | Hamming sent: "));
    Serial.print(cw[0]);
    Serial.print(F(" "));
    Serial.println(cw[1]);

    transmitBinaryData(cw[0], 7);

    if (memoryError) {
      Serial.println(F("Transmission stopped due to memory error."));
      return;
    }

    transmitBinaryData(cw[1], 7);

    if (memoryError) {
      Serial.println(F("Transmission stopped due to memory error."));
      return;
    }
  }

  digitalWrite(LED, LOW);
}

/**
 * @brief Muestra el resultado de la recepcion, calcula el BER y libera memoria.
 *
 * Imprime estadisticas (bits validos, caracteres decodificados, errores
 * corregidos, etc.), muestra el mensaje reconstruido y guarda el BER en
 * berHamming o berNoCode segun el modo activo. Al final libera los buffers
 * dinamicos de recepcion.
 *
 * BER = bits erroneos / (arrSize * 8)
 */
void processReceivedMessage() {
  Serial.println();
  Serial.println(F("RECEPTION RESULTS"));

  Serial.print(F("Valid bits received: "));
  Serial.println(receivedBitCount);

  Serial.print(F("Incomplete bits at end: "));
  Serial.println(hammingMode ? hammingBitCount : bitCount);

  Serial.print(F("Characters decoded: "));
  Serial.println(receivedCount);

  Serial.print(F("Received bit sequence: "));
  if (receivedBits != nullptr) {
    Serial.println(receivedBits);
  } else {
    Serial.println(F("(empty)"));
  }

  displayReceivedCharacter(receivedMessage);

  // BER respecto al mensaje original (8 bits por caracter)
  unsigned long totalBits = (unsigned long)arrSize * 8;
  unsigned long errors = countBitErrors(receivedMessage, receivedCount);
  float ber = (float)errors / (float)totalBits;

  Serial.print(F("Injected channel errors: "));
  Serial.println(injectedErrors);

  if (hammingMode) {
    berHamming = ber;

    Serial.print(F("Errors corrected by Hamming: "));
    Serial.println(correctedErrors);

    Serial.print(F("Erasures (anomalies) recovered: "));
    Serial.println(erasuresRecovered);

    Serial.print(F("Words not recoverable: "));
    Serial.println(wordsLost);

    Serial.print(F("Residual bit errors: "));
    Serial.print(errors);
    Serial.print(F(" / "));
    Serial.println(totalBits);

    Serial.print(F("BER WITH Hamming(7,4): "));
    Serial.println(berHamming, 6);
  } else {
    berNoCode = ber;

    Serial.print(F("Bit errors: "));
    Serial.print(errors);
    Serial.print(F(" / "));
    Serial.println(totalBits);

    Serial.print(F("BER WITHOUT code: "));
    Serial.println(berNoCode, 6);
  }

  if (memoryError) {
    Serial.println(F("WARNING: Memory allocation failed."));
  }

  // Liberar la memoria dinamica ya utilizada
  free(receivedBits);
  receivedBits = nullptr;
  receivedBitCount = 0;

  free(receivedMessage);
  receivedMessage = nullptr;
  receivedCount = 0;
}

// DISPLAY
/**
 * @brief Muestra el mensaje reconstruido por Serial y en el LCD 16x2.
 *
 * En el LCD se escriben hasta 32 caracteres: los primeros 16 en la fila 0 y
 * el resto en la fila 1.
 *
 * @param receivedMessage Caracteres recibidos (usa receivedCount como longitud).
 */
void displayReceivedCharacter(int* receivedMessage) {
  lcd.clear();

  if (receivedMessage == nullptr || receivedCount == 0) {
    Serial.println(F("No complete characters received."));
    lcd.setCursor(0, 0);
    lcd.print(F("No message"));
    return;
  }

  Serial.print(F("Reconstructed message: "));

  for (size_t i = 0; i < receivedCount; i++) {
    Serial.write((char)receivedMessage[i]);
  }
  Serial.println();

  // Mostrar hasta 32 caracteres en un LCD 16x2
  for (size_t i = 0; i < receivedCount && i < 32; i++) {
    if (i < 16) {
      lcd.setCursor(i, 0);
    } else {
      lcd.setCursor(i - 16, 1);
    }

    lcd.write((char)receivedMessage[i]);
  }
}

// Muestra la comparacion final de BER (en porcentaje)
/**
 * @brief Muestra la comparacion final de BER (en porcentaje) en el LCD y por Serial.
 *
 * Fila 0: BER sin codigo. Fila 1: BER con Hamming(7,4).
 */
void displayBER() {
  lcd.clear();

  lcd.setCursor(0, 0);
  lcd.print(F("BER sin: "));
  lcd.print(berNoCode * 100.0, 2);
  lcd.print('%');

  lcd.setCursor(0, 1);
  lcd.print(F("BER con: "));
  lcd.print(berHamming * 100.0, 2);
  lcd.print('%');

  Serial.println();
  Serial.println(F("================================"));
  Serial.println(F("BER COMPARISON"));
  Serial.print(F("Without code:  "));
  Serial.println(berNoCode, 6);
  Serial.print(F("With Hamming:  "));
  Serial.println(berHamming, 6);
  Serial.println(F("================================"));
}

// INTEGRITY TEST (trama falsa + cifrado XOR/Vernam)
// Clave de un solo uso, tan larga como el mensaje, generada con ruido analogico.
// (Para la demo basta; en un sistema real se usaria un TRNG o pads pre-compartidos.)
/**
 * @brief Genera una clave de un solo uso (tan larga como el mensaje).
 *
 * Cada bit sale del LSB de (lectura analogica del pin A2 flotante XOR micros()),
 * con una pausa de 150 us entre bits. Es suficiente para la demo; en un sistema
 * real se usaria un TRNG o pads pre-compartidos.
 */
void generateKey() {
  for (size_t i = 0; i < arrSize; i++) {
    uint8_t k = 0;

    for (int b = 0; b < 8; b++) {
      k = (k << 1) | ((analogRead(KEY_NOISE_PIN) ^ micros()) & 1);
      delayMicroseconds(150);
    }

    key[i] = k;
  }

  keyReady = true;
}

/**
 * @brief Borra la clave (la pone en ceros) y la marca como no valida.
 */
void eraseKey() {
  for (size_t i = 0; i < arrSize; i++) {
    key[i] = 0;
  }

  keyReady = false;
}

// out[i] = plain[i] XOR key[i]
/**
 * @brief Cifra con XOR (Vernam): out[i] = plain[i] ^ key[i].
 * @param plain Texto en claro (arrSize elementos).
 * @param out   Salida: bytes cifrados (arrSize elementos).
 * @return true si se cifro; false si no hay una clave valida.
 */
bool xorEncrypt(const int* plain, uint8_t* out) {
  if (!keyReady) {
    Serial.println(F("ERROR: no valid one-time key."));
    return false;
  }

  for (size_t i = 0; i < arrSize; i++) {
    out[i] = (uint8_t)plain[i] ^ key[i];
  }

  return true;
}

// Descifra en el lugar y DESTRUYE la clave (un solo uso)
/**
 * @brief Descifra en el lugar con XOR y DESTRUYE la clave (un solo uso).
 * @param data  Datos recibidos; se sobrescriben con el texto descifrado.
 * @param count Cantidad de elementos a descifrar.
 * @return true si se descifro; false si no hay una clave valida.
 */
bool xorDecrypt(int* data, size_t count) {
  if (!keyReady) {
    Serial.println(F("ERROR: no valid one-time key."));
    return false;
  }

  for (size_t i = 0; i < count && i < arrSize; i++) {
    data[i] = (uint8_t)data[i] ^ key[i];
  }

  eraseKey();

  return true;
}

// Byte i del mensaje falso (se rellena con espacios si es mas corto que arrSize)
/**
 * @brief Devuelve el byte i del mensaje falso del atacante (forgedMessage).
 * @param i Indice del caracter.
 * @return Caracter del mensaje falso, o ' ' (espacio) si i excede su longitud.
 */
uint8_t forgedByte(size_t i) {
  if (i < strlen_P(forgedMessage)) {
    return pgm_read_byte(&forgedMessage[i]);
  }

  return ' ';
}

// Bits distintos contra el mensaje original (codes) o contra el falso.
// Los caracteres que no llegaron cuentan como 8 bits erroneos.
/**
 * @brief Cuenta bits distintos contra el mensaje original o contra el falso.
 * @param rx            Caracteres recibidos.
 * @param rxCount       Cantidad de caracteres recibidos.
 * @param againstForged true: comparar con el mensaje falso; false: con el original.
 * @param matched       Salida: cantidad de caracteres identicos a la referencia.
 * @return Total de bits erroneos (cada caracter faltante cuenta como 8).
 */
unsigned long countFrameErrors(const int* rx, size_t rxCount, bool againstForged, size_t* matched) {
  unsigned long errors = 0;
  *matched = 0;

  for (size_t i = 0; i < arrSize; i++) {
    uint8_t ref = againstForged ? forgedByte(i) : (uint8_t)codes[i];

    if (i < rxCount) {
      uint8_t diff = (uint8_t)rx[i] ^ ref;

      if (diff == 0) {
        (*matched)++;
      }

      while (diff) {
        errors += diff & 1;
        diff >>= 1;
      }
    } else {
      errors += 8;
    }
  }

  return errors;
}

/**
 * @brief Imprime por Serial los caracteres recibidos; los no imprimibles salen como '.'.
 * @param rx      Caracteres recibidos.
 * @param rxCount Cantidad de caracteres.
 */
void printFrameText(const int* rx, size_t rxCount) {
  for (size_t i = 0; i < rxCount; i++) {
    char c = (char)rx[i];
    Serial.write((c >= 32 && c <= 126) ? c : '.');
  }

  Serial.println();
}

/**
 * @brief Imprime un buffer en hexadecimal (2 digitos por byte, separados por espacio).
 * @param data Bytes a imprimir.
 * @param n    Cantidad de bytes.
 */
void printHexBuffer(const uint8_t* data, size_t n) {
  for (size_t i = 0; i < n; i++) {
    if (data[i] < 16) {
      Serial.print('0');
    }

    Serial.print(data[i], HEX);
    Serial.print(' ');
  }

  Serial.println();
}

/**
 * @brief Libera y reinicia los buffers dinamicos de recepcion (bits y mensaje).
 */
void clearReceivedData() {
  free(receivedBits);
  receivedBits = nullptr;
  receivedBitCount = 0;

  free(receivedMessage);
  receivedMessage = nullptr;
  receivedCount = 0;
}

/**
 * @brief Muestra dos lineas de texto (guardadas en flash) en el LCD durante 2.5 s.
 * @param line1 Texto de la fila 0.
 * @param line2 Texto de la fila 1.
 */
void showLcd(const __FlashStringHelper* line1, const __FlashStringHelper* line2) {
  lcd.clear();
  lcd.setCursor(0, 0);
  lcd.print(line1);
  lcd.setCursor(0, 1);
  lcd.print(line2);

  delay(2500);
}

/**
 * @brief FASE 3: prueba de integridad frente a una trama falsa.
 *
 *  TEST A : trama falsa + Hamming sin cifrado. Hamming solo corrige errores
 *           de canal, no autentica, por lo que la trama falsa se ACEPTA.
 *  TEST B1: trama legitima cifrada con XOR (Vernam) + Hamming. Debe recuperarse
 *           intacta tras descifrar.
 *  TEST B2: trama falsa recibida por un receptor que usa XOR. Como el atacante
 *           no conoce la clave, el resultado es basura y su texto no se entrega.
 */
void processIntegrityTest() {
  const unsigned long totalBits = (unsigned long)arrSize * 8;
  size_t matched = 0;
  unsigned long errors = 0;

  textToAsciiCodes(message, codes);   // referencia: mensaje legitimo

  Serial.println();
  Serial.println(F("================================"));
  Serial.println(F("INTEGRITY TEST: FORGED FRAME"));
  Serial.print(F("Legitimate message: "));
  Serial.println(message);
  Serial.println(F("================================"));

  // TEST A: trama falsa con Hamming(7,4) solamente
  // El atacante codifica SU texto con Hamming: todas las palabras son validas,
  // el sindrome da 0 y el receptor no tiene como saber que es falsa.
  Serial.println();
  Serial.println(F("TEST A: forged frame, Hamming(7,4) only (no cipher)"));

  for (size_t i = 0; i < arrSize; i++) {
    wire[i] = forgedByte(i);
  }

  hammingMode = true;
  resetChannelState();
  sendHammingPayload(wire);

  errors = countFrameErrors(receivedMessage, receivedCount, true, &matched);

  Serial.println();
  Serial.print(F("Receiver output: "));
  printFrameText(receivedMessage, receivedCount);
  Serial.print(F("Channel errors corrected by Hamming: "));
  Serial.println(correctedErrors);
  Serial.print(F("Words flagged as invalid: "));
  Serial.println(wordsLost);
  Serial.print(F("Characters equal to forged text: "));
  Serial.print(matched);
  Serial.print(F(" / "));
  Serial.println(arrSize);
  Serial.print(F("Bit errors vs forged text: "));
  Serial.print(errors);
  Serial.print(F(" / "));
  Serial.println(totalBits);

  if (matched == arrSize && wordsLost == 0) {
    Serial.println(F("RESULT: forged frame ACCEPTED as valid (Hamming cannot detect it)."));
    showLcd(F("Sin XOR: FALSA"), F("ACEPTADA"));
  } else {
    Serial.println(F("RESULT: inconclusive (channel altered the forged frame)."));
    showLcd(F("Sin XOR: FALSA"), F("inconcluso"));
  }

  clearReceivedData();

  // TEST B1: trama legitima con XOR (Vernam) + Hamming
  Serial.println();
  Serial.println(F("TEST B1: legitimate frame, XOR (Vernam) + Hamming(7,4)"));

  generateKey();
  Serial.print(F("One-time key (shown for the demo only): "));
  printHexBuffer(key, arrSize);

  xorEncrypt(codes, wire);
  Serial.print(F("Ciphertext on the wire: "));
  printHexBuffer(wire, arrSize);

  hammingMode = true;
  resetChannelState();
  sendHammingPayload(wire);

  xorDecrypt(receivedMessage, receivedCount);
  errors = countFrameErrors(receivedMessage, receivedCount, false, &matched);

  Serial.println();
  Serial.print(F("Decrypted output: "));
  printFrameText(receivedMessage, receivedCount);
  Serial.print(F("Channel errors corrected by Hamming: "));
  Serial.println(correctedErrors);
  Serial.print(F("Bit errors vs original: "));
  Serial.print(errors);
  Serial.print(F(" / "));
  Serial.println(totalBits);
  Serial.print(F("Key still valid after use: "));
  Serial.println(keyReady ? F("YES") : F("NO (erased)"));

  if (errors == 0) {
    Serial.println(F("RESULT: legitimate frame recovered intact."));
    showLcd(F("Con XOR: legit"), F("descifrada OK"));
  } else {
    Serial.println(F("RESULT: legitimate frame has residual errors."));
    showLcd(F("Con XOR: legit"), F("descifrada ERR"));
  }

  clearReceivedData();

  // TEST B2: trama falsa con XOR activo en el receptor
  // El atacante NO conoce la clave: su texto se descifra a bytes sin sentido.
  Serial.println();
  Serial.println(F("TEST B2: forged frame, receiver uses XOR (Vernam)"));

  generateKey();   // clave de un solo uso del siguiente mensaje (el atacante no la tiene)

  for (size_t i = 0; i < arrSize; i++) {
    wire[i] = forgedByte(i);
  }

  hammingMode = true;
  resetChannelState();
  sendHammingPayload(wire);

  xorDecrypt(receivedMessage, receivedCount);
  errors = countFrameErrors(receivedMessage, receivedCount, true, &matched);

  Serial.println();
  Serial.print(F("Receiver output after decrypting: "));
  printFrameText(receivedMessage, receivedCount);
  Serial.print(F("Characters equal to forged text: "));
  Serial.print(matched);
  Serial.print(F(" / "));
  Serial.println(arrSize);
  Serial.print(F("Bit errors vs forged text: "));
  Serial.print(errors);
  Serial.print(F(" / "));
  Serial.print(totalBits);
  Serial.print(F(" (BER "));
  Serial.print((float)errors / (float)totalBits, 4);
  Serial.println(F(")"));

  if (matched < arrSize) {
    Serial.println(F("RESULT: attacker's text NOT delivered; receiver gets random bytes."));
    showLcd(F("Con XOR: FALSA"), F("= BASURA"));
  } else {
    Serial.println(F("RESULT: forged text got through (unexpected)."));
    showLcd(F("Con XOR: FALSA"), F("paso (!)"));
  }

  clearReceivedData();
  eraseKey();
}

// AUXILIARY
/**
 * @brief Verifica el resultado de una asignacion de memoria.
 * @param ptr Puntero devuelto por malloc/realloc.
 * @return true si es valido; false (e imprime error) si es nullptr.
 */
bool checkMemoryAllocation(void* ptr) {
  if (ptr == nullptr) {
    Serial.println(F("ERROR: Insufficient memory."));
    return false;
  }

  return true;
}

/**
 * @brief Indica si un caracter es un bit valido.
 * @param vbit Caracter a evaluar.
 * @return true si es '0' o '1'.
 */
bool isValidBit(char vbit) {
  return vbit == '0' || vbit == '1';
}