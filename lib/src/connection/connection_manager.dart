library ldap.connection_manager;

import 'dart:io';
import 'dart:async';
import 'dart:collection';

import 'package:dartdap/common.dart';

import '../protocol/ldap_protocol.dart';

import '../ldap_exception.dart';
import '../ldap_result.dart';
import '../control/control.dart';
import '../search_result.dart';
import 'ldap_transformer.dart';

/**
 * Holds a pending LDAP operation that we have issued to the server. We
 * expect to get a response back from the server for this op. We match
 * the response against the message Id. example: We send request with id = 1234,
 * we expect a response with id = 1234
 *
 * todo: Implement timeouts?
 */
abstract class _PendingOp {
  Stopwatch _stopwatch = new Stopwatch()..start();

  // the message we are waiting for a response from
  LDAPMessage message;

  _PendingOp(this.message);

  String toString() => "PendingOp m=${message}";

  // Process an LDAP result. Return true if this operation is now complete
  bool processResult(ResponseOp op);

  done() {
    var ms = _stopwatch.elapsedMilliseconds;
    ldapLogger.fine("Request $message serviced in $ms ms");
  }
}

// A pending operation that has multiple values returned via a
// Stream. Used for SearchResults.
class _StreamPendingOp extends _PendingOp {
  StreamController<SearchEntry> _controller =
      new StreamController<SearchEntry>();
  SearchResult _searchResult;

  SearchResult get searchResult => _searchResult;

  _StreamPendingOp(LDAPMessage m) : super(m) {
    _searchResult = new SearchResult(_controller.stream);
  }

  // process the stream op - return false if we expect more data to come
  // or true if the search is complete
  bool processResult(ResponseOp op) {
    // op is Search Entry. Add it to our stream and keep
    if (op is SearchResultEntry) {
      _controller.add(op.searchEntry);
      return false;
    } else {
      // we should be done now
      // if this is not a done message we are in trouble...
      var x = (op as SearchResultDone);

      if (x.ldapResult.resultCode != 0) _controller.addError(x.ldapResult);

      _searchResult.controls = x.controls;
      _searchResult.ldapResult = x.ldapResult;
      _controller.close();
      done();
    }
    return true; // op complete
  }
}

// A pending opertion that expects a single return response message
// returned via a future. For all LDAP ops except search results
class _FuturePendingOp extends _PendingOp {
  Completer completer = new Completer();

  _FuturePendingOp(LDAPMessage m) : super(m);

  bool processResult(ResponseOp op) {
    var ldapResult = op.ldapResult;
    if (_isError(ldapResult.resultCode)) {
      completer.completeError(ldapResult);
    } else {
      completer.complete(ldapResult);
    }
    done();
    return true;
  }

  // return true if the result code is an error
  // any result code that you want to generate a [Future] error
  // should return true here. If the caller is normally
  // expecting to get a result code back this should return false.
  // example: for LDAP compare the caller wants to know the result
  // so we dont generate an error -but let the result code propagate back
  bool _isError(int resultCode) {
    switch (resultCode) {
      case 0:
      case ResultCode.COMPARE_TRUE:
      case ResultCode.COMPARE_FALSE:
        return false;
    }
    return true;
  }
}

/**
 * Manages the state of the LDAP connection.
 *
 * Queues LDAP operations and sends them to the LDAP server.
 */

class ConnectionManager {
  // Queue for all outbound messages.
  Queue<_PendingOp> _outgoingMessageQueue = new Queue<_PendingOp>();

  // Messages that we are expecting a response back from the LDAP server
  Map<int, _PendingOp> _pendingResponseMessages = new Map();

  // TIMEOUT when waiting for a pending op to come back from the server.
  static const PENDING_OP_TIMEOUT = const Duration(seconds: 3);

  bool _bindPending = false;

  // true if a BIND is pending
  Socket _socket;

  // true if this connection is closed
  // (if the socket is null, we consider it closed)
  bool isClosed() => _socket == null;

  int _nextMessageId = 1;

  // message counter for this connection

  int _port;
  String _host;
  bool _ssl;

  ConnectionManager(this._host, this._port, this._ssl);

  Future<ConnectionManager> connect() async {
    ldapLogger.finest("Creating socket to ${_host}:${_port} ssl=$_ssl");
    _socket = await (_ssl
        ? SecureSocket.connect(_host, _port, onBadCertificate: _badCertHandler)
        : Socket.connect(_host, _port));

    ldapLogger.fine("Connected to $_host:$_port");
    _socket.transform(createTransformer()).listen((m) => _handleLDAPMessage(m),
        onError: (error, stacktrace) {
      ldapLogger.severe("Socket error = $error  stacktrace=${stacktrace}");
      throw new LDAPException("Socket error = $error stacktrace=${stacktrace}");
    });
    return this;
  }

  // Called when the SSL cert is not valid
  // Return true to carry on anyways. TODO: Make it configurable
  bool _badCertHandler(X509Certificate cert) {
    ldapLogger.warning(
        "Invalid Certificate issuer= ${cert.issuer} subject=${cert.subject}");
    ldapLogger.warning("SSL Connection will proceed. Please fix the certificate");
    return true; // carry on
  }

  // process an LDAP Search Request
  SearchResult processSearch(SearchRequest rop, List<Control> controls) {
    var m = new LDAPMessage(++_nextMessageId, rop, controls);
    var op = new _StreamPendingOp(m);
    _queueOp(op);
    return op.searchResult;
  }

  // Process a generic LDAP operation.
  Future<LDAPResult> process(RequestOp rop) async {
    var m = new LDAPMessage(++_nextMessageId, rop);
    var op = new _FuturePendingOp(m);
    _queueOp(op);
    return await op.completer.future;
  }

  _queueOp(_PendingOp op) {
    _outgoingMessageQueue.add(op);
    _sendPendingMessage();
  }

  _sendPendingMessage() {
    while (_messagesToSend()) {
      var op = _outgoingMessageQueue.removeFirst();
      _sendMessage(op);
    }
  }

  /**
   * Return TRUE if there are messages waiting to be sent.
   *
   * Note that BIND is synchronous (as per LDAP spec) - so if there is a pending BIND
   * we must wait to send more messages until the BIND response comes back from the
   * server
   */
  bool _messagesToSend() =>
      (!_outgoingMessageQueue.isEmpty) && (_bindPending == false);

  // Send a single message to the server
  _sendMessage(_PendingOp op) async {
    if (_socket == null) {
      await connect();
    }

    ldapLogger.fine("Sending message ${op.message}");
    var l = op.message.toBytes();
    _socket.add(l);
    _pendingResponseMessages[op.message.messageId] = op;
    if (op.message.protocolTag == BIND_REQUEST) _bindPending = true;
  }

  /**
   *
   *
   * Close the LDAP connection.
   *
   * Pending operations will be allowed to finish, unless immediate = true
   *
   * Returns a Future that is called when the connection is closed
   */

  Future close(bool immediate) {
    if (immediate || _canClose()) {
      return _doClose();
    } else {
      var c = new Completer();
      new Timer.periodic(PENDING_OP_TIMEOUT, (Timer t) {
        if (_canClose()) {
          t.cancel();
          _doClose().then((_) => c.complete());
        }
      });
      return c.future;
    }
  }

  /**
   * Return true if there are no more pending messages.
   */
  bool _canClose() {
    if (_pendingResponseMessages.isEmpty && _outgoingMessageQueue.isEmpty) {
      return true;
    }
    ldapLogger.finest(
        "close() waiting for queue to drain pendingResponse=$_pendingResponseMessages");
    _sendPendingMessage();
    return false;
  }

  Future _doClose() {
    ldapLogger.info("Closing ldap connection");
    var f = _socket.done;
    new Future(() {
      if (_socket != null) {
        _socket.destroy();
        _socket = null;
      }
    });
    return f;
  }

  /// called for each LDAP message recevied from the server
  void _handleLDAPMessage(LDAPMessage m) {
    // call response handler to figure out what kind of resposnse
    // the message contains.
    var rop = ResponseHandler.handleResponse(m);
    // match it to a pending operation based on message id
    // todo: AN extended protocol op may not match an outstanding request
    // hanndle this case

    if (rop is ExtendedResponse) {
      var o = rop as ExtendedResponse;
      ldapLogger
          .severe("Got extended response ${o.responseName} code=${rop.ldapResult
          .resultCode}");
    }

    var pending_op = _pendingResponseMessages[m.messageId];

    // If this is not true, the server sent us possibly
    // malformed LDAP. What should we do?? Not clear if
    // we should throw an exception or try to ignore the error bytes
    // and carry on....
    if (pending_op == null)
      throw new LDAPException(
          "Server sent us an unknown message id = ${m.messageId}"
            " opCode=${m.protocolTag}");

    if (pending_op.processResult(rop)) {
      // op is now complete. Remove it from pending q
      _pendingResponseMessages.remove(m.messageId);
    }

    if (m.protocolTag == BIND_RESPONSE) _bindPending = false;
  }
}
