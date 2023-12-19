import java.io.BufferedReader;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import sinsiway.*;

class CryptConfig {

  String algorithm;
  String keySize;
  String operationMode;
  String ivType;
  String ntnType;
  String dataType;
  String keyName;
  String text;

  public CryptConfig() {}

  public void parse(String line) {
    String[] fields = line.split(",");
    this.algorithm = fields[0];
    this.keySize = fields[1];
    this.operationMode = fields[2];
    this.ivType = fields[3];
    this.ntnType = fields[4];
    this.dataType = fields[5];
    this.keyName = fields[6];
    this.text = (fields.length > 7) ? fields[7] : "";
    text = text.replaceAll("\n", "");
  }

  public String toString() {
    return (
      "CryptConfig [algorithm=" +
      algorithm +
      ", keySize=" +
      keySize +
      ", operationMode=" +
      operationMode +
      ", ivType=" +
      ivType +
      ", ntnType=" +
      ntnType +
      ", dataType=" +
      dataType +
      ", keyName=" +
      keyName +
      ", text=" +
      text +
      "]"
    );
  }
}

public class CipherAlgorithmTest {

  private static final int MAX_TEXT_LENGTH = 10240;

  static void hashTest(
    CryptConfig config,
    sinsiway.PcaSession session,
    FileWriter resultWriter
  ) {
    String hashString = "";
    int hashEncryptPass = 1;
    int errorCode = 0;
    try {
      hashString = session.encrypt(config.keyName, config.text);
    } catch (PcaException e) {
      hashEncryptPass = -1;
      errorCode = e.getErrCode();
    }
    hashString = hashString == null ? "" : hashString;

    try {
      int hashStringLen = hashString != null ? hashString.length() : 0;
      resultWriter.write(
        config.keyName +
        ",hash,passcode," +
        hashEncryptPass +
        ",errcode," +
        errorCode +
        "," +
        hashString +
        "[" +
        hashStringLen +
        "]\n"
      );
    } catch (IOException e) {
      System.err.println("I/O error: " + e.getMessage());
    }
  }

  static void SymmetricKeyEncryptionTest(
    CryptConfig config,
    sinsiway.PcaSession session,
    FileWriter resultWriter
  ) {
    String encryptString = "";
    String decryptString = "";

    int encryptPass = 1;
    int decryptPass = 1;

    int encryptErrorCode = 0;
    int decryptErrorCode = 0;

    try {
      encryptString = session.encrypt(config.keyName, config.text);
    } catch (PcaException e) {
      encryptPass = -1;
      encryptErrorCode = e.getErrCode();
    }
    encryptString = encryptString == null ? "" : encryptString;

    try {
      decryptString = session.decrypt(config.keyName, encryptString);
    } catch (PcaException e) {
      decryptPass = -1;
      decryptErrorCode = e.getErrCode();
    }
    decryptString = decryptString == null ? "" : decryptString;

    if (!config.text.equals(decryptString)) {
      decryptPass = 0;
    }

    try {
      int encryptStringLen = encryptString != null ? encryptString.length() : 0;
      resultWriter.write(
        config.keyName +
        ",encrypt,passcode," +
        encryptPass +
        ",errcode," +
        encryptErrorCode +
        "," +
        encryptString +
        "[" +
        encryptStringLen +
        "]\n"
      );

      int decryptStringLen = decryptString != null ? decryptString.length() : 0;
      resultWriter.write(
        config.keyName +
        ",decrypt,passcode," +
        decryptPass +
        ",errcode," +
        decryptErrorCode +
        "," +
        decryptString +
        "[" +
        decryptStringLen +
        "]\n"
      );
    } catch (IOException e) {
      System.err.println("I/O error: " + e.getMessage());
    }
  }

  static void randomInitialVectorTest(
    CryptConfig config,
    sinsiway.PcaSession session,
    FileWriter resultWriter
  ) {
    String encryptString = "";
    String decryptString = "";
    String secondEcnryptString = "";
    String secondDecryptString = "";

    int encryptPass = 1;
    int decryptPass = 1;
    int secondEcnryptPass = 1;
    int secondDecryptPass = 1;

    int differentEncryptPass = 1;

    int encryptErrorCode = 0;
    int decryptErrorCode = 0;
    int secondEcnryptErrorCode = 0;
    int secondDecryptErrorCode = 0;

    try {
      encryptString = session.encrypt(config.keyName, config.text);
    } catch (PcaException e) {
      encryptPass = -1;
      encryptErrorCode = e.getErrCode();
    }
    encryptString = encryptString == null ? "" : encryptString;

    try {
      decryptString = session.decrypt(config.keyName, encryptString);
    } catch (PcaException e) {
      decryptPass = -1;
      decryptErrorCode = e.getErrCode();
    }
    decryptString = decryptString == null ? "" : decryptString;

    if (!config.text.equals(decryptString)) {
      decryptPass = 0;
    }

    try {
      secondEcnryptString = session.encrypt(config.keyName, config.text);
    } catch (PcaException e) {
      secondEcnryptPass = -1;
      secondEcnryptErrorCode = e.getErrCode();
    }
    secondEcnryptString =
      secondEcnryptString == null ? "" : secondEcnryptString;

    try {
      secondDecryptString =
        session.decrypt(config.keyName, secondEcnryptString);
    } catch (PcaException e) {
      secondDecryptPass = -1;
      secondDecryptErrorCode = e.getErrCode();
    }
    secondDecryptString =
      secondDecryptString == null ? "" : secondDecryptString;

    if (!config.text.equals(secondDecryptString)) {
      secondDecryptPass = 0;
    }

    if (
      !config.ntnType.equals("N2N") &&
      encryptString != null &&
      encryptString.equals(secondEcnryptString)
    ) {
      differentEncryptPass = 0;
    }

    try {
      int encryptStringLen = encryptString != null ? encryptString.length() : 0;
      resultWriter.write(
        config.keyName +
        ",encrypt,passcode," +
        encryptPass +
        ",errcode," +
        encryptErrorCode +
        "," +
        "_[" +
        encryptStringLen +
        "]\n"
      );

      int decryptStringLen = decryptString != null ? decryptString.length() : 0;
      resultWriter.write(
        config.keyName +
        ",decrypt,passcode," +
        decryptPass +
        ",errcode," +
        decryptErrorCode +
        "," +
        decryptString +
        "[" +
        decryptStringLen +
        "]\n"
      );

      int secondEcnryptStringLen = secondEcnryptString != null
        ? secondEcnryptString.length()
        : 0;
      resultWriter.write(
        config.keyName +
        ",second_encrypt,passcode," +
        secondEcnryptPass +
        ",errcode," +
        secondEcnryptErrorCode +
        "," +
        "_[" +
        secondEcnryptStringLen +
        "]\n"
      );

      int secondDecryptStringLen = secondDecryptString != null
        ? secondDecryptString.length()
        : 0;
      resultWriter.write(
        config.keyName +
        ",second_decrypt,passcode," +
        secondDecryptPass +
        ",errcode," +
        secondDecryptErrorCode +
        "," +
        secondDecryptString +
        "[" +
        secondDecryptStringLen +
        "]\n"
      );

      resultWriter.write(
        config.keyName +
        ",different_encrypt,passcode," +
        differentEncryptPass +
        "\n"
      );
    } catch (IOException e) {
      System.err.println("I/O error: " + e.getMessage());
    }
  }

  public static void main(String[] args) {
    if (args.length < 2) {
      System.out.println(
        "Usage: java CipherAlgorithmTest <csvFilePath> <resultFilePath>"
      );
      return;
    }

    String csvFilePath = args[0];
    String resultFilePath = args[1];

    try (
      BufferedReader csvReader = new BufferedReader(
        new FileReader(csvFilePath)
      );
      FileWriter resultWriter = new FileWriter(resultFilePath)
    ) {
      String line;

      while ((line = csvReader.readLine()) != null) {
        CryptConfig config = new CryptConfig();
        config.parse(line);

        try {
          sinsiway.PcaSession session = sinsiway.PcaSessionPool.getSession();
          if (
            config.algorithm.equals("SHA") || config.algorithm.equals("HMAC")
          ) {
            hashTest(config, session, resultWriter);
          } else {
            if (
              config.ivType.equals("RIV") && !config.operationMode.equals("ECB")
            ) {
              randomInitialVectorTest(config, session, resultWriter);
            } else {
              SymmetricKeyEncryptionTest(config, session, resultWriter);
            }
          }
        } catch (PcaException e) {
          e.printStackTrace();
        }
      }
    } catch (IOException e) {
      System.err.println("I/O error: " + e.getMessage());
    }
  }
}
