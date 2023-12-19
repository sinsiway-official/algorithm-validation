import 'dart:convert';
import 'dart:io';

import 'package:petra_cipher_algorithm/models/encryption_config_list.dart';

Future<void> main() async {
  // 파일 경로 지정 (JSON 파일의 실제 경로로 수정하세요)
  const filePath = 'lib/data/algorithm_meta.json';
  String resultSqlPath = './result/init.sql';
  File resultSqlFile = File(resultSqlPath);
  String csvPath = './result/testcase.csv';
  File csvFile = File(csvPath);

  List<String> testcaseString = [
    "",
    "0123456789abcde",
    "0123456789abcdef",
    "0123456789abcdef0",
    "0123456789abcdef0123456789abcdef",
    "Lorem ipsum dolor sit amet. consectetur adipiscing elit. Morbi non scelerisque nunc. Nulla ut dapibus libero. Praesent viverra libero a erat posuere. in rutrum nibh sollicitudin. Integer et ultrices felis. id bibendum urna. Pellentesque habitant morbi tristique senectus et netus et malesuada fames ac turpis egestas. Vestibulum feugiat. sem et luctus maximus. arcu metus accumsan metus. quis luctus dui libero in nisl. Lorem ipsum dolor sit amet. consectetur adipiscing elit. Nulla mollis dignissim aliquet. Phasellus tincidunt semper lorem. sed tristique risus bibendum sed. Etiam bibendum dui vel diam fringilla. ac sodales tortor laoreet. Curabitur nec sollicitudin ex. Integer a feugiat tellus. Nulla at vehicula eros. quis condimentum est. Nullam vehicula et dolor at consequat. Nulla volutpat nunc sit amet interdum malesuada. Maecenas semper eros eu metus vestibulum pharetra. Nam elementum vel dolor ut mollis. Nullam non mi sit amet augue tempus tristique. Pellentesque laoreet ullamcorper arcu ac laoreet. Etiam est lacus. tincidunt vel justo at. suscipit egestas nisl. Donec non sem nec lorem volutpat venenatis. Vivamus at convallis lectus. et maximus ex. Nulla eget neque eget est vehicula euismod suscipit sed arcu. Cras tincidunt lacus ut nibh hendrerit. a porta sapien porta. In molestie dolor vel ipsum interdum. et tempus nulla ornare. Integer sodales sapien nec purus cursus consectetur. Etiam vel metus ut ligula convallis semper. Aliquam lobortis. est eget hendrerit dictum morbi."
  ];

  // 파일 읽기
  final file = File(filePath);
  final contents = await file.readAsString();

  // JSON 파싱 및 EncryptionConfigList 객체 생성
  final encryptionConfigList =
      EncryptionConfigList.fromMap(json.decode(contents));

  resultSqlFile.writeAsStringSync(
      "delete pct_encrypt_key where key_id >= 1000;\n",
      mode: FileMode.write);
  resultSqlFile.writeAsStringSync(
      "delete pct_enc_column where enc_col_id >= 1000;\n",
      mode: FileMode.append);
  csvFile.writeAsStringSync("", mode: FileMode.write);

  // 결과 출력 (여기서는 첫 번째 구성을 출력)
  if (encryptionConfigList.meta != null &&
      encryptionConfigList.meta!.isNotEmpty) {
    for (var i = 0; i < encryptionConfigList.meta!.length; i++) {
      final config = encryptionConfigList.meta![i];
      print("make query: ${config.getAlgorithmSymbol()}");
      config.makeQuery(resultSqlFile);

      print("make testcase: ${config.getAlgorithmSymbol()}");
      List<String> testcaseList = config.getTestcaseList();
      for (var j = 0; j < testcaseList.length; j++) {
        for (var k = 0; k < testcaseString.length; k++) {
          csvFile.writeAsStringSync('${testcaseList[j]},${testcaseString[k]}\n',
              mode: FileMode.append);
        }
      }
    }
  } else {
    print('No configuration data found.');
  }
}
