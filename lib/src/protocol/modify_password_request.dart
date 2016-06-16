part of ldap.protocol;

class ModifyPasswordRequest extends RequestOp {
  String _dn;
  String _oldPassword;
  String _newPassword;

  ModifyPasswordRequest(this._dn, this._oldPassword, this._newPassword) :
      super(EXTENDED_REQUEST);

  @override
  ASN1Object toASN1() {
    var seq = _startSequence();

    seq.add(new ASN1OctetString("1.3.6.1.4.1.4203.1.11.1", tag: 0x80));

    if (_dn != null) {
      seq.add(new ASN1OctetString(_dn));
    }

    var rs = new ASN1Sequence();

    if (_oldPassword != null) {
      rs.add(new ASN1OctetString(_oldPassword));
    }

    if (_newPassword != null) {
      rs.add(new ASN1OctetString(_newPassword));
    }

    seq.add(rs);

    return seq;
  }
}
