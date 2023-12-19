#include <cstdio>
#include <cstring>
#include <iostream>

#include "PcAPIL.h"

#define MAX_LENGTH 10240
#define MAX_FIELD_LENGTH 50
#define MAX_TEXT_LENGTH 10240

FILE* getFile(const char* filePath, const char* mode) {
#ifdef _WIN32
  FILE* file;
  int err = fopen_s(&file, filePath, mode);
  if (err != 0) {
    perror("Error opening file");
    return NULL;
  }
#else
  FILE* file = fopen(filePath, mode);
  if (file == NULL) {
    perror("Error opening file");
    return NULL;
  }
#endif
  return file;
}

class CryptConfig {
 public:
  char* algorithm;
  char* keySize;
  char* operationMode;
  char* ivType;
  char* ntnType;
  char* dataType;
  char* keyName;
  char* text;

  unsigned int textLen;

  void parse(char* line) {
    char* context = NULL;
#ifdef _WIN32
    algorithm = strtok_s(line, ",", &context);
    keySize = strtok_s(NULL, ",", &context);
    operationMode = strtok_s(NULL, ",", &context);
    ivType = strtok_s(NULL, ",", &context);
    ntnType = strtok_s(NULL, ",", &context);
    dataType = strtok_s(NULL, ",", &context);
    keyName = strtok_s(NULL, ",", &context);
    text = strtok_s(NULL, "", &context);
#else
    algorithm = strtok(line, ",");
    keySize = strtok(NULL, ",");
    operationMode = strtok(NULL, ",");
    ivType = strtok(NULL, ",");
    ntnType = strtok(NULL, ",");
    dataType = strtok(NULL, ",");
    keyName = strtok(NULL, ",");
    text = strtok(NULL, "");
#endif
    textLen = strlen(text);
    if (textLen > 0 && text[textLen - 1] == '\n') {
      text[textLen - 1] = '\0';  // 개행 문자 제거
      textLen--;
    }
  };

  void drawString() {
    printf(
        "CryptConfig [algorithm=%s, keySize=%s, operationMode=%s, ivType=%s, "
        "ntnType=%s, dataType=%s, keyName=%s]\n",
        algorithm, keySize, operationMode, ivType, ntnType, dataType, keyName);
  };
};

void hashTest(CryptConfig config, int sid, FILE* resultFile) {
  unsigned char hashString[MAX_TEXT_LENGTH];
  unsigned int hashStringLen = MAX_TEXT_LENGTH;
  memset(hashString, 0, hashStringLen);

  int errorCode = 0;
  int hashEncryptPass = 1;

  int rtn = PcAPI_encrypt_name(sid, config.keyName, (unsigned char*)config.text,
                               config.textLen, hashString, &hashStringLen);
  if (rtn < 0) {
    errorCode = rtn;
    hashEncryptPass = -1;
  }

  fprintf(resultFile, "%s,hash,passcode,%d,errcode,%d,%s[%d]\n", config.keyName,
          hashEncryptPass, errorCode, hashString, hashStringLen);
}

void SymmetricKeyEncryptionTest(CryptConfig config, int sid, FILE* resultFile) {
  unsigned char encryptString[MAX_TEXT_LENGTH];
  unsigned int encryptStringLen = MAX_TEXT_LENGTH;
  memset(encryptString, 0, encryptStringLen);

  unsigned char decryptString[MAX_TEXT_LENGTH];
  unsigned int decryptStringLen = MAX_TEXT_LENGTH;
  memset(decryptString, 0, decryptStringLen);

  int encryptErrorCode = 0;
  int decryptErrorCode = 0;

  int encryptPass = 1;
  int decryptPass = 1;

  int rtn =
      PcAPI_encrypt_name(sid, config.keyName, (unsigned char*)config.text,
                         config.textLen, encryptString, &encryptStringLen);

  if (rtn < 0) {
    encryptErrorCode = rtn;
    encryptPass = -1;
  }

  rtn = PcAPI_decrypt_name(sid, config.keyName, encryptString, encryptStringLen,
                           decryptString, &decryptStringLen);
  if (rtn < 0) {
    decryptErrorCode = rtn;
    decryptPass = -1;
  } else {
    decryptString[decryptStringLen] = '\0';
  }

  if (strcmp(config.text, (const char*)decryptString) != 0) {
    decryptPass = -1;
  }

  fprintf(resultFile, "%s,encrypt,passcode,%d,errcode,%d,%s[%d]\n",
          config.keyName, encryptPass, encryptErrorCode, encryptString,
          encryptStringLen);
  fprintf(resultFile, "%s,decrypt,passcode,%d,errcode,%d,%s[%d]\n",
          config.keyName, decryptPass, decryptErrorCode, decryptString,
          decryptStringLen);
}

void randomInitialVectorTest(CryptConfig config, int sid, FILE* resultFile) {
  unsigned char encryptString[MAX_TEXT_LENGTH];
  unsigned int encryptStringLen = MAX_TEXT_LENGTH;
  memset(encryptString, 0, encryptStringLen);
  unsigned char decryptString[MAX_TEXT_LENGTH];
  unsigned int decryptStringLen = MAX_TEXT_LENGTH;
  memset(decryptString, 0, decryptStringLen);

  unsigned char secondEcnryptString[MAX_TEXT_LENGTH];
  unsigned int secondEncryptStringLen = MAX_TEXT_LENGTH;
  memset(secondEcnryptString, 0, secondEncryptStringLen);
  unsigned char secondDecryptString[MAX_TEXT_LENGTH];
  unsigned int secondDecryptStringLen = MAX_TEXT_LENGTH;
  memset(secondDecryptString, 0, secondDecryptStringLen);

  int encryptErrorCode = 0;
  int decryptErrorCode = 0;

  int secondEncryptErrorCode = 0;
  int secondDecryptErrorCode = 0;

  int encryptPass = 1;
  int decryptPass = 1;

  int secondEncryptPass = 1;
  int secondDecryptPass = 1;

  int differentEncryptPass = 1;

  int rtn =
      PcAPI_encrypt_name(sid, config.keyName, (unsigned char*)config.text,
                         config.textLen, encryptString, &encryptStringLen);

  if (rtn < 0) {
    encryptErrorCode = rtn;
    encryptPass = -1;
  }

  rtn = PcAPI_decrypt_name(sid, config.keyName, encryptString, encryptStringLen,
                           decryptString, &decryptStringLen);
  if (rtn < 0) {
    decryptErrorCode = rtn;
    decryptPass = -1;
  } else {
    decryptString[decryptStringLen] = '\0';
  }

  if (strcmp(config.text, (const char*)decryptString) != 0) {
    decryptPass = 0;
  }

  rtn = PcAPI_encrypt_name(sid, config.keyName, (unsigned char*)config.text,
                           config.textLen, secondEcnryptString,
                           &secondEncryptStringLen);
  if (rtn < 0) {
    secondEncryptErrorCode = rtn;
    secondEncryptPass = -1;
  }

  rtn = PcAPI_decrypt_name(sid, config.keyName, secondEcnryptString,
                           secondEncryptStringLen, secondDecryptString,
                           &secondDecryptStringLen);
  if (rtn < 0) {
    secondDecryptErrorCode = rtn;
    secondDecryptPass = -1;
  } else {
    secondDecryptString[secondDecryptStringLen] = '\0';
  }

  if (strcmp(config.text, (const char*)secondDecryptString) != 0) {
    secondDecryptPass = 0;
  }

  if (strcmp(config.ntnType, "N2N") != 0 &&
      strcmp((const char*)encryptString, (const char*)secondEcnryptString) ==
          0) {
    differentEncryptPass = 0;
  }

  fprintf(resultFile, "%s,encrypt,passcode,%d,errcode,%d,_[%d]\n",
          config.keyName, encryptPass, encryptErrorCode, encryptStringLen);
  fprintf(resultFile, "%s,decrypt,passcode,%d,errcode,%d,%s[%d]\n",
          config.keyName, decryptPass, decryptErrorCode, decryptString,
          decryptStringLen);
  fprintf(resultFile, "%s,second_encrypt,passcode,%d,errcode,%d,_[%d]\n",
          config.keyName, secondEncryptPass, secondEncryptErrorCode,
          secondEncryptStringLen);
  fprintf(resultFile, "%s,second_decrypt,passcode,%d,errcode,%d,%s[%d]\n",
          config.keyName, secondDecryptPass, secondDecryptErrorCode,
          secondDecryptString, secondDecryptStringLen);
  fprintf(resultFile, "%s,different_encrypt,passcode,%d\n", config.keyName,
          differentEncryptPass);
}

int main(int argc, char const* argv[]) {
  if (argc < 3) {
    printf("Usage: %s <csvFilePath> <resultFilePath>\n", argv[0]);
    return -1;
  }
  const char* csvFilePath = argv[1];
  FILE* csvFile = getFile(csvFilePath, "r");
  if (csvFile == NULL) {
    return -1;
  }

  const char* resultFilePath = argv[2];
  FILE* resultFile = getFile(resultFilePath, "w");
  if (resultFile == NULL) {
    return -1;
  }

  int sid = PcAPI_getSession("");
  if (sid < 0) {
    printf("PcAPI_getSession error\n");
    return -1;
  }

  char line[MAX_LENGTH];

  while (fgets(line, MAX_LENGTH, csvFile)) {
    CryptConfig config;
    config.parse(line);
    config.drawString();

    if (strcmp(config.algorithm, "SHA") == 0 ||
        strcmp(config.algorithm, "HMAC") == 0) {
      hashTest(config, sid, resultFile);
    } else {
      if (strcmp(config.ivType, "RIV") == 0 &&
          strcmp(config.operationMode, "ECB") != 0) {
        randomInitialVectorTest(config, sid, resultFile);
      } else {
        SymmetricKeyEncryptionTest(config, sid, resultFile);
      }
    }
  }

  return 0;
}
