library ldap.configuration;

import 'dart:async';

import 'package:dartdap/common.dart';

import 'ldap_connection.dart';
import 'ldap_exception.dart';

/// A LDAP configuration settings and a LDAP connection created from it.
///
/// Use an instance of this class to represent the LDAP server
/// settings (host, port, bind distinguished name, password, and
/// whether the connection uses TLS/SSL).
///
/// It is also used to obtain an [LDAPConnection] using those settings.
///
/// There are two ways to create an LDAP configuration:
///
/// * Providing the settings as parameters using the default constructor.
/// * Loading the settings from a YAML file using the fromFile constructor.

class LDAPConfiguration {
  // Constants

  static const String _DEFAULT_HOST = "localhost";
  static const int _STANDARD_LDAP_PORT = 389;
  static const int _STANDARD_LDAPS_PORT = 636;

  // Configuration settings

  /// The LDAP server hostname or IP address
  String host;

  /// The LDAP server port number
  int port;

  /// Whether the connection to the LDAP server uses TLS/SSL
  bool ssl;

  /// The distinguished name of the entry for the bind operation
  String bindDN;

  /// The password used for the bind operation
  String password;

  // File details (only set if object created by the fromFile constructor)

  bool _file_load;

  // true if settings need to be loaded from file
  String _file_name;

  // file containing settings
  String _file_entry;

  // name of map in the YAML settings file

  // Cached connection

  LDAPConnection _connection;

  // null if not created

  // Set values
  //
  // This internal method is used by the default constructor and to
  // process settings loaded from a file. It applies all the default rules
  // for when values are not provided.

  void _setAll(
      String hostname, int port, bool ssl, String bindDN, String password) {
    this.host = (hostname != null) ? hostname : _DEFAULT_HOST;
    this.ssl = (ssl != null) ? ssl : false;
    this.port = (port != null)
        ? port
        : ((this.ssl) ? _STANDARD_LDAPS_PORT : _STANDARD_LDAP_PORT);
    this.bindDN = (bindDN != null) ? bindDN : "";
    this.password = (password != null) ? password : "";
  }

  /// Constructor for a new LDAP configuration.
  ///
  /// The [hostname] is the hostname of the LDAP server.
  ///
  /// The [port] is the port number of the LDAP server. It defaults to the
  /// standard LDAP port numbers: 389 when TLS is not used or 636 when TLS is
  /// used.
  ///
  /// Set [ssl] to true to connect over TLS, otherwise TLS is not used. It
  /// defaults to false.
  ///
  /// Set [bindDN] to the distinguish name for the bind. An empty string
  /// means to perform an anonymous bind.  It defaults to an empty string.
  ///
  /// Set [password] to the password for bind. It defaults to an empty string.
  ///
  /// To perform an anonymous bind, omit the [bindDN] and [password].
  ///
  /// Examples:
  ///
  ///      // Anonymous bind
  ///      LDAPConfiguration.settings("localhost");
  ///      LDAPConfiguration.settings("ldap.example.com", ssl: true);
  ///
  ///      // Authenticated bind
  ///      LDAPConfiguration.settings("ldap.example.com", ssl: true, bindDN: "cn=admin,dc=example,dc=com", password: "p@ssw0rd");

  LDAPConfiguration(String hostname,
      {int port, bool ssl: false, String bindDN, String password}) {
    _setAll(hostname, port, ssl, bindDN, password);
    _file_load = false;
  }

  /// Constructor for a new LDAP configuration from a YAML file.
  ///
  /// The [fileName] is the name of a YAML file
  /// containing the LDAP connection settings.
  ///
  /// The [configName] is the name of a Map in the YAML file.
  ///
  /// # Example
  ///
  ///     var ldapConfig = new LDAPConfiguration("ldap.yaml", "default");
  ///
  /// This example loads the LDAP configuration from a Map named "default" from
  /// the YAML file "ldap.yaml" in the current directory. That YAML file could
  /// contain:
  ///
  ///     default:
  ///       host: "ldap.example.com"
  ///       port: 389
  ///       ssl: false
  ///       bindDN: "cn=admin,dc=example,dc=com"
  ///       password: "p@ssw0rd"
  ///
  ///  The only mandatory attribute is "host". See the default constructor
  ///  for a description of the other attributes, and their values if they are not specified.

  LDAPConfiguration.fromFile(String fileName, String configName) {
    assert(fileName != null && fileName.isNotEmpty);
    assert(configName != null && configName.isNotEmpty);

    this._file_name = fileName;
    this._file_entry = configName;
    this._file_load = true;
  }

  /// Loads the settings from the YAML file, if needed.
  ///
  /// If the LDAPConfiguration was not created using the fromFile constructor, this method
  /// does nothign and returns immediately.

  Future _load_values() async {
    if (_file_load == false) {
      // File does not need to be loaded: settings are already set
      // This occurs if the fromFile constructor was not used, or the settings
      // were loaded in a previous invocation of _load_values.
    } else {}
  }

  /// Return a Future<[LDAPConnection]> using this configuration.
  ///
  /// The connection is cached so that subsequent calls will return
  /// the same connection (unless it has been closed, in which case
  /// a new one will be created).
  ///
  /// If the optional parameter [doBind] is true (the default),
  /// the returned connection will also be bound using the configured DN and password.
  ///
  /// The LDAP connection can be closed by invoking the `close` method on the
  /// [LDAPConfiguration] or by invoking the [LDAPConnection.close] method on the
  /// connection object.  Either approach will cause subsequent calls to
  /// this [getConnection] method to open a new LDAP connection.

  Future<LDAPConnection> getConnection([bool doBind = true]) async {
    if (_connection != null && !_connection.isClosed()) {
      // Use cached connection
      return _connection;
    }

    // Get settings (loading them from the YAML file if necessary)

    await _load_values();

    // Connect

    ldapLogger.info(this.toString());

    _connection = new LDAPConnection(host, port, ssl, bindDN, password);
    await _connection.connect();

    // Bind

    if (doBind) {
      var r = await _connection.bind();
      if (r.resultCode != 0) throw new LDAPException("BIND Failed", r);
    }

    return _connection;
  }

  /// Closes the [LDAPconnection] that was opened with [getConnection].

  Future close([bool immediate = false]) {
    if (_connection != null) {
      var f = _connection.close(immediate);
      _connection = null;
      return f;
    } else {
      assert(_connection != null);
      return null;
    }
  }

  /// Returns a string representation of this object.

  String toString() {
    return "${ssl ? "ldaps://" : "ldap://"}${host}:${port}${(bindDN != null)
      ? "/${bindDN}"
      : ""}";
  }
}
