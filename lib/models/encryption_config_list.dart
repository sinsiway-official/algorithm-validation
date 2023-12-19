import 'encryption_config_model.dart';

class EncryptionConfigList {
  List<EncryptionConfig>? meta;

  EncryptionConfigList({this.meta});

  factory EncryptionConfigList.fromMap(Map<String, dynamic> map) {
    return EncryptionConfigList(
      meta: map['meta'] != null
          ? List<EncryptionConfig>.from(
              map['meta'].map((x) => EncryptionConfig.fromMap(x)))
          : null,
    );
  }

  Map<String, dynamic> toMap() {
    return {
      'meta': meta?.map((x) => x.toMap()).toList(),
    };
  }
}
