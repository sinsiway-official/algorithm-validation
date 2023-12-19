import 'dart:io';

class EncryptionConfig {
  int? algorithmId;
  String? algorithm;
  List<String>? keySize;
  List<String>? operationMode;
  List<String>? initialVectorType;
  List<String>? nullToNull;
  List<String>? formatSpecification;

  List<String>? testcaseList = List.empty(growable: true);

  EncryptionConfig({
    this.algorithmId,
    this.algorithm,
    this.keySize,
    this.operationMode,
    this.initialVectorType,
    this.nullToNull,
    this.formatSpecification,
  });

  factory EncryptionConfig.fromMap(Map<String, dynamic> map) {
    return EncryptionConfig(
      algorithmId: int.parse(map['algorithmId']),
      algorithm: map['algorithm'] ?? '',
      keySize: List<String>.from(map['keySize'] ?? []),
      operationMode: List<String>.from(map['operationMode'] ?? []),
      initialVectorType: List<String>.from(map['initialVectorType'] ?? []),
      nullToNull: List<String>.from(map['nullToNull'] ?? []),
      formatSpecification: List<String>.from(map['formatSpecification'] ?? []),
    );
  }

  Map<String, dynamic> toMap() {
    return {
      'algorithm': algorithm,
      'keySize': keySize,
      'operationMode': operationMode,
      'initialVectorType': initialVectorType,
      'nullToNull': nullToNull,
      'formatSpecification': formatSpecification,
    };
  }

  List<String> getTestcaseList() {
    return testcaseList!;
  }

  // 속성 조합 생성 함수
  List<String> generateCombinations(List<List<String>> lists) {
    List<String> combinations = [];

    void generate(int depth, String current) {
      if (depth == lists.length) {
        combinations.add(current);
        return;
      }
      for (String item in lists[depth]) {
        generate(depth + 1, current + (depth > 0 ? '_' : '') + item);
      }
    }

    generate(0, '');
    return combinations;
  }

  // 쿼리를 생성하는 별도의 함수
  void generateQuery(
      File file,
      int keyId,
      String keySize,
      CipherType cipherType,
      OperationMode operationMode,
      InitialVectorType initialVectorType,
      NullToNull nullToNull,
      FormatSpecification formatSpecification) {
    String keyName = "${cipherType.symbol}_${keySize}_${operationMode.symbol}_"
        "${initialVectorType.symbol}_${nullToNull.symbol}_"
        "${formatSpecification.symbol}";

    file.writeAsStringSync(
        "insert into pct_encrypt_key(key_id, key_no, key_size, cipher_type, enc_mode, iv_type, n2n_flag, b64_txt_enc_flag, enc_start_pos, key_name) values('$keyId', '0', '$keySize', '${cipherType.value}', '${operationMode.value}', '${initialVectorType.value}', '${nullToNull.value}', '${formatSpecification.value}', '1', '$keyName');\n",
        mode: FileMode.append);
    file.writeAsStringSync(
        "insert into pct_enc_column(enc_col_id, enc_tab_id, key_id, data_length, column_name) values('$keyId', '10', '$keyId', '2000', '$keyName');\n",
        mode: FileMode.append);

    testcaseList?.add(
        "${cipherType.symbol},$keySize,${operationMode.symbol},${initialVectorType.symbol},${nullToNull.symbol},${formatSpecification.symbol},$keyName");
  }

// 주 함수 개선
  void makeQuery(File file) async {
    // 속성 조합 생성
    List<String> combinations = generateCombinations([
      keySize!,
      operationMode!,
      initialVectorType!,
      nullToNull!,
      formatSpecification!
    ]);

    for (String combination in combinations) {
      List<String> parts = combination.split('_');

      String keySize = parts[0];
      CipherType cipherType =
          CipherType.values.firstWhere((c) => c.name == algorithm!);
      OperationMode operationMode =
          OperationMode.values.firstWhere((o) => o.name == parts[1]);
      InitialVectorType initialVectorType =
          InitialVectorType.values.firstWhere((iv) => iv.name == parts[2]);
      NullToNull nullToNull =
          NullToNull.values.firstWhere((f) => f.name == parts[3]);
      FormatSpecification formatSpecification =
          FormatSpecification.values.firstWhere((f) => f.name == parts[4]);

      generateQuery(file, algorithmId!, keySize, cipherType, operationMode,
          initialVectorType, nullToNull, formatSpecification);

      algorithmId = (algorithmId ?? 0) + 1;
    }
  }

  getAlgorithmSymbol() {
    return CipherType.values.firstWhere((c) => c.name == algorithm!).symbol;
  }
}

enum CipherType {
  aes,
  seed,
  aria,
  sha,
  tdes,
  rsa,
  des,
  hmac,
  hight;

  int get value {
    switch (this) {
      case CipherType.aes:
        return 1;
      case CipherType.seed:
        return 2;
      case CipherType.aria:
        return 3;
      case CipherType.sha:
        return 4;
      case CipherType.tdes:
        return 5;
      case CipherType.rsa:
        return 7;
      case CipherType.des:
        return 8;
      case CipherType.hmac:
        return 9;
      case CipherType.hight:
        return 10;
      default:
        return 0;
    }
  }

  String get symbol {
    switch (this) {
      case CipherType.aes:
        return "AES";
      case CipherType.seed:
        return "SEED";
      case CipherType.aria:
        return "ARIA";
      case CipherType.sha:
        return "SHA";
      case CipherType.tdes:
        return "TDES";
      case CipherType.rsa:
        return "RSA";
      case CipherType.des:
        return "DES";
      case CipherType.hmac:
        return "HMAC";
      case CipherType.hight:
        return "HIGHT";
      default:
        return "ERR";
    }
  }

  CipherType? parseCipherType(String cipherName) {
    return CipherType.values.firstWhere(
        (c) => c.name == cipherName.toLowerCase(),
        orElse: () => CipherType.aes);
  }
}

enum OperationMode {
  ecb,
  cbc,
  cfb,
  ofb;

  int get value {
    switch (this) {
      case OperationMode.ecb:
        return 1;
      case OperationMode.cbc:
        return 2;
      case OperationMode.cfb:
        return 3;
      case OperationMode.ofb:
        return 4;
      default:
        return 0;
    }
  }

  String get symbol {
    switch (this) {
      case OperationMode.ecb:
        return "ECB";
      case OperationMode.cbc:
        return "CBC";
      case OperationMode.cfb:
        return "CFB";
      case OperationMode.ofb:
        return "OFB";
      default:
        return "ERR";
    }
  }

  OperationMode? parseOperationMode(String modeName) {
    return OperationMode.values.firstWhere(
        (m) => m.name == modeName.toLowerCase(),
        orElse: () => OperationMode.ecb);
  }
}

enum InitialVectorType {
  zero,
  fixed,
  random;

  int get value {
    switch (this) {
      case InitialVectorType.zero:
        return 0;
      case InitialVectorType.fixed:
        return 3;
      case InitialVectorType.random:
        return 2;
      default:
        return 0;
    }
  }

  String get symbol {
    switch (this) {
      case InitialVectorType.zero:
        return "ZIV";
      case InitialVectorType.fixed:
        return "PIV";
      case InitialVectorType.random:
        return "RIV";
      default:
        return "ERR";
    }
  }

  InitialVectorType? parseInitialVectorType(String ivName) {
    return InitialVectorType.values.firstWhere(
        (iv) => iv.name == ivName.toLowerCase(),
        orElse: () => InitialVectorType.zero);
  }
}

enum NullToNull {
  no,
  yes;

  int get value {
    switch (this) {
      case NullToNull.no:
        return 0;
      case NullToNull.yes:
        return 1;
      default:
        return 0;
    }
  }

  String get symbol {
    switch (this) {
      case NullToNull.no:
        return "N2E";
      case NullToNull.yes:
        return "N2N";
      default:
        return "ERR";
    }
  }

  NullToNull? parseNullToNull(String n2nName) {
    return NullToNull.values.firstWhere(
        (n2n) => n2n.name == n2nName.toLowerCase(),
        orElse: () => NullToNull.no);
  }
}

enum FormatSpecification {
  zeroRaw,
  zeroB64,
  pkcs7B64,
  pkcs7B64Trailer,
  pkcs7Raw,
  pkcs7Hex;

  int get value {
    switch (this) {
      case FormatSpecification.zeroRaw:
        return 0;
      case FormatSpecification.zeroB64:
        return 1;
      case FormatSpecification.pkcs7B64:
        return 2;
      case FormatSpecification.pkcs7B64Trailer:
        return 3;
      case FormatSpecification.pkcs7Raw:
        return 4;
      case FormatSpecification.pkcs7Hex:
        return 5;
      default:
        return 0;
    }
  }

  String get symbol {
    switch (this) {
      case FormatSpecification.zeroRaw:
        return "ZPNE";
      case FormatSpecification.zeroB64:
        return "ZPB64";
      case FormatSpecification.pkcs7B64:
        return "P7B64";
      case FormatSpecification.pkcs7B64Trailer:
        return "P7B64T";
      case FormatSpecification.pkcs7Raw:
        return "PKRAW";
      case FormatSpecification.pkcs7Hex:
        return "PKHEX";
      default:
        return "ERR";
    }
  }

  FormatSpecification? parseFormatSpecification(String formatName) {
    return FormatSpecification.values.firstWhere(
        (f) => f.name == formatName.toLowerCase(),
        orElse: () => FormatSpecification.zeroRaw);
  }
}
