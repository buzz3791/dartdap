library ldap.filter;

import 'ldap_exception.dart';
import 'package:asn1lib/asn1lib.dart';
import 'ldap_util.dart';

/// Represents an LDAP search filter.
///
/// An LDAP search filter can be a single filter created using either of these
/// factory methods:
///
/// * [present] - matches if the entry contains the attribute
/// * [equals] - matches if an attribute has a given value
/// * [substring] - matches wildcard
/// * [approx] - matches if an attribute approximately has the value
/// * [greaterOrEquals] - matches if the value is greater than or equal
/// * [lessOrEquals] - matches if the entry has the attribute with a value that is less than or equal to the supplied value
///
/// Or it can be a compound filter that composes other filters created using
/// these factory methods:
///
/// * [not] - matches if its member filter does not match
/// * [and] - matches if all of its member filters match
/// * [or] - matches if at least one of its member filters match

class Filter {
  int _filterType;

  int get filterType => _filterType;

  // The assertion value for this filter.
  String _assertionValue;

  String get assertionValue => _assertionValue;
  String _attributeName;

  String get attributeName => _attributeName;

  // nested filters
  List<Filter> _subFilters = new List<Filter>();

  List<Filter> get subFilters => _subFilters;

  /**
   * BER types
   */
  static const int TYPE_AND = 0xA0;
  static const int TYPE_OR = 0xA1;
  static const int TYPE_NOT = 0xA2;
  static const int TYPE_EQUALITY = 0xA3;
  static const int TYPE_SUBSTRING = 0xA4;
  static const int TYPE_GREATER_OR_EQUAL = 0xA5;
  static const int TYPE_LESS_OR_EQUAL = 0xA6;

  static const int TYPE_PRESENCE = 0x87;
  static const int TYPE_APPROXIMATE_MATCH = 0xA8;
  static const int TYPE_EXTENSIBLE_MATCH = 0xA9;

  static const int EXTENSIBLE_TYPE_MATCHING_RULE_ID = 0x81;
  static const int EXTENSIBLE_TYPE_ATTRIBUTE_NAME = 0x82;
  static const int EXTENSIBLE_TYPE_MATCH_VALUE = 0x83;
  static const int EXTENSIBLE_TYPE_DN_ATTRIBUTES = 0x84;

  /// Constructor
  ///
  /// It is preferable to use one of the convenience methods ([present],
  /// [equals], [substring], [approx], [greaterOrEquals], [lessOrEquals])
  /// instead of directly using this constructor.

  Filter(this._filterType,
      [this._attributeName, this._assertionValue, this._subFilters]);

  /// Creates a [Filter] that matches an entry that has an attribute with the given value.
  static Filter equals(String attributeName, String attrValue) =>
      new Filter(TYPE_EQUALITY, attributeName, attrValue);

  /// Creates a [Filter] that matches entries that matches all of the [filters].
  static Filter and(List<Filter> filters) =>
      new Filter(TYPE_AND, null, null, filters);

  /// Creates a [Filter] that matches entries that matches at least one of the [filters].
  static Filter or(List<Filter> filters) =>
      new Filter(TYPE_OR, null, null, filters);

  /// Creates a [Filter] that matches entries that don't match on [f].
  static Filter not(Filter f) => new Filter(TYPE_NOT, null, null, [f]);

  /// Creates a [Filter] that matches an entry contains an attribute.
  static Filter present(String attrName) => new Filter(TYPE_PRESENCE, attrName);

  /// Creates a [Filter] that matches on a substring.
  ///
  /// The [pattern] must be a [String] of the form "attr=match", where _attr_ is
  /// the attribute name and _match_ is a value that has at least one `*`
  /// character. There can be wildcard `*` chararcters at the beginning, middle
  /// or end of _match_.

  static Filter substring(String pattern) => new SubstringFilter(pattern);

  /// Creates a [Filter] that matches an entry that contains the [attributeName]
  /// with a value that is greater than or equal to [attrValue].
  static Filter greaterOrEquals(String attributeName, String attrValue) =>
      new Filter(TYPE_GREATER_OR_EQUAL, attributeName, attrValue);

  /// Creates a [Filter] that matches an entry that contains the [attributeName]
  /// with a value that is less than or equal to [attrValue].
  static Filter lessOrEquals(String attributeName, String attrValue) =>
      new Filter(TYPE_LESS_OR_EQUAL, attributeName, attrValue);

  /// Creates a [Filter] that matches an entry that contains the [attributeName]
  /// that approximately matches [attrValue].
  static Filter approx(String attributeName, String attrValue) =>
      new Filter(TYPE_APPROXIMATE_MATCH, attributeName, attrValue);

  /// Operator version of the [and] filter factory method.
  Filter operator &(Filter other) => Filter.and([this, other]);

  /// Operator version of the [or] filter factory method.
  Filter operator |(Filter other) => Filter.or([this, other]);

  String toString() =>
      "Filter(type=$_filterType attrName=$_attributeName val=$_assertionValue, subFilters=$_subFilters)";

  /**
   * Convert a Filter expression to an ASN1 Object
   *
   * This may be called recursively
   */
  ASN1Object toASN1() {
    switch (filterType) {
      case Filter.TYPE_EQUALITY:
      case Filter.TYPE_GREATER_OR_EQUAL:
      case Filter.TYPE_LESS_OR_EQUAL:
      case Filter.TYPE_APPROXIMATE_MATCH:
        var seq = new ASN1Sequence(tag: filterType);
        seq.add(new ASN1OctetString(attributeName));
        seq.add(new ASN1OctetString(LDAPUtil.escapeString(assertionValue)));
        return seq;

      case Filter.TYPE_AND:
      case Filter.TYPE_OR:
        var aset = new ASN1Set(tag: filterType);
        subFilters.forEach((Filter subf) {
          aset.add(subf.toASN1());
        });
        return aset;

      case Filter.TYPE_PRESENCE:
        return new ASN1OctetString(attributeName, tag: filterType);

      case Filter.TYPE_NOT:
        // like AND/OR but with only one subFilter.
        assert(subFilters != null);
        var notObj = new ASN1Set(tag: filterType);
        notObj.add(subFilters[0].toASN1());
        return notObj;

      case Filter.TYPE_EXTENSIBLE_MATCH:
        throw "Not Done yet. Fix me!!";

      default:
        throw new LDAPException(
            "Unexpected filter type = $filterType. This should never happen");
    }
  }
}

/**
 * A Substring filter
 * Clients should not need to invoke this directly. Use [Filter.substring()]
 */
class SubstringFilter extends Filter {
  /// BER type for initial part of string filter
  static const int TYPE_SUBINITIAL = 0x80;

  /// BER type for any part of string filter
  static const int TYPE_SUBANY = 0x81;

  /// BER type for final part of string filter
  static const int TYPE_SUBFINAL = 0x82;

  String _initial;
  List<String> _any = [];
  String _final;

  /** The initial substring filter component. Zero or one */
  String get initial => _initial;

  /** The list of "any" components. Zero or more */
  List<String> get any => _any;

  /** The final component. Zero or more */
  String get finalString => _final;

  SubstringFilter(String pattern) : super(Filter.TYPE_SUBSTRING) {
    // todo: We probaby need to properly escape special chars = and *
    var l = pattern.split("=");
    if (l.length != 2 || l[0] == "" || l[1] == "") {
      throw new LDAPException("Invalid substring search pattern '$pattern'");
    }

    _attributeName = l[0];
    var matchString = l[1];

    // now parse initial, any, final

    var x = matchString.split("*");
    // must be at least one * -giving a split of at least two strings
    assert(x.length > 1);

    /*
     *  foo*
     *  *foo
     *
     *  foo*bar
     *  foo*bar*baz*boo
     */

    if (x[0] != "") {
      _initial = x[0];
    }
    if (x.last != "") {
      _final = x.last;
    }
    for (int i = 1; i < x.length - 1; ++i) {
      _any.add(x[i]);
    }
  }

  ASN1Object toASN1() {
    var seq = new ASN1Sequence(tag: filterType);
    seq.add(new ASN1OctetString(attributeName));
    // sub sequence embeds init,any,final
    var sSeq = new ASN1Sequence();

    if (initial != null) {
      sSeq.add(
          new ASN1OctetString(initial, tag: SubstringFilter.TYPE_SUBINITIAL));
    }
    any.forEach((String o) =>
        sSeq.add(new ASN1OctetString(o, tag: SubstringFilter.TYPE_SUBANY)));
    if (finalString != null) {
      sSeq.add(
          new ASN1OctetString(finalString, tag: SubstringFilter.TYPE_SUBFINAL));
    }
    seq.add(sSeq);
    return seq;
  }

  String toString() =>
      "SubstringFilter(_init=$_initial, any=$_any, fin=$_final)";
}
