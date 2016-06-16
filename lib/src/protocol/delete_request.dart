part of ldap.protocol;

class DeleteRequest extends RequestOp {
  String _dn;

  // dn of entry we are deleting

  DeleteRequest(this._dn) : super(DELETE_REQUEST);

  /*
   * Encode the add request to BER
   *
        DelRequest ::= [APPLICATION 10] LDAPDN

  */

  ASN1Object toASN1() => new ASN1OctetString(_dn, tag: DELETE_REQUEST);
}
