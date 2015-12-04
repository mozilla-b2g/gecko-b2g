/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this file,
 * You can obtain one at http://mozilla.org/MPL/2.0/. */

/*
 * RemoteControlService.jsm is the entry point of remote control function.
 * The service initializes a TLS socket server to receives events from user.
 *
 *               RemoteControlService <-- Gecko Preference
 *
 *     user -->  nsITLSSocketServer --> script (gecko)
 *
 * Events from user are in JSON format. After parsed to control command,
 * these events are passed to script (js), runs in sandbox,
 * and dispatch corresponding events to Gecko.
 *
 * Here is related component location:
 * gecko/b2g/components/RemoteControlService.jsm
 *
 * For more details, please visit: https://wiki.mozilla.org/Firefox_OS/Remote_Control
 */

"use strict";

this.EXPORTED_SYMBOLS = ["RemoteControlService"];

const { classes: Cc, interfaces: Ci, results: Cr, utils: Cu, Constructor: CC } = Components;

Cu.import("resource://gre/modules/Services.jsm");
Cu.import("resource://gre/modules/XPCOMUtils.jsm");
Cu.import("resource://gre/modules/debug.js");

XPCOMUtils.defineLazyServiceGetter(this, "certService", "@mozilla.org/security/local-cert-service;1",
                                   "nsILocalCertService");

// static functions
function debug(aStr) {
  dump("RemoteControlService: " + aStr + "\n");
}

const DEBUG = false;

const REMOTE_CONTROL_EVENT = 'mozChromeRemoteControlEvent';
const RC_PREF_DEVICES = "remotecontrol.authorized_devices";
const MAX_CLIENT_CONNECTIONS = 5; // Allow max 5 clients to use remote control TV

const SERVER_STATUS = {
  STOPPED: 0,
  STARTED: 1
};

this.RemoteControlService = {
  // Remote Control status
  _serverStatus: SERVER_STATUS.STOPPED,

  // TLS socket server
  _port: -1, // The port on which this service listens
  _socket: null, // The socket associated with this
  _doQuit: false, // Indicates when the service is to be shut down at the end of the request.
  _socketClosed: true, // True if the socket in this is closed, false otherwise.
  _connectionGen: 0, // Used for tracking existing connections
  _connections: new Map(), // Hash of all open connections, indexed by connection number
  _mDNSCancelableHandler: null, // Handle mDNS cancel

  init: function() {
    DEBUG && debug("init");
  },

  // PUBLIC API
  // Start TLS socket server.
  // Return a promise for start() resolves/reject to
  start: function() {
    if (this._serverStatus == SERVER_STATUS.STARTED) {
      return Promise.reject("AlreadyStarted");
    }

    let promise = new Promise((aResolve, aReject) => {
      this._doStart(aResolve, aReject);
    });
    return promise;
  },

  // Stop TLS socket server, remove registered observer
  // Cancel mDNS registration
  // Return false if server not started, stop failed.
  stop: function() {
    if (this._serverStatus == SERVER_STATUS.STOPPED) {
      return false;
    }

    if (!this._socket) {
      return false;
    }

    DEBUG && debug("Stop listening on port " + this._socket.port);

    Services.obs.removeObserver(this, "xpcom-shutdown");

    if (this._mDNSCancelableHandler) {
      this._mDNSCancelableHandler.Cancel(Cr.NS_OK);
      this._mDNSCancelableHandler = null;
    }

    this._socket.close();
    this._socket = null;
    this._doQuit = false;
    this._serverStatus = SERVER_STATUS.STOPPED;

    return true;
  },

  // Observers and Listeners
  // nsIObserver
  observe: function(subject, topic, data) {
    switch (topic) {
      case "xpcom-shutdown": {
        // Stop service when xpcom-shutdown
        this.stop();
        break;
      }
    }
  },

  // nsIServerSocketListener
  onSocketAccepted: function(socket, trans) {
    DEBUG && debug("onSocketAccepted(socket=" + socket + ", trans=" + trans + ")");
    DEBUG && debug("New connection on " + trans.host + ":" + trans.port);

    const SEGMENT_SIZE = 8192;
    const SEGMENT_COUNT = 1024;

    try {
      var input = trans.openInputStream(0, SEGMENT_SIZE, SEGMENT_COUNT)
                       .QueryInterface(Ci.nsIAsyncInputStream);
      var output = trans.openOutputStream(0, 0, 0);
    } catch (e) {
      DEBUG && debug("Error opening transport streams: " + e);
      trans.close(Cr.NS_BINDING_ABORTED);
      return;
    }

    let connectionNumber = ++this._connectionGen;

    try {
      // Create a connection for each user connection
      // EventHandler implements nsIInputStreamCallback for incoming message from user
      var conn = new Connection(input, output, this, socket.port, trans.port, connectionNumber);
      let handler = new EventHandler(conn);

      input.asyncWait(handler, 0, 0, Services.tm.mainThread);
    } catch (e) {
      DEBUG && debug("Error in initial connection: " + e);
      trans.close(Cr.NS_BINDING_ABORTED);
      return;
    }

    this._connections.set(connectionNumber, conn);
    DEBUG && debug("Start connection " + connectionNumber);
  },

  // Close all connection when socket closed
  onStopListening: function(socket, status) {
    DEbug && debug("Shut down server on port " + socket.port);

    this._connections.forEach(function(value, key){
      let connection = value;
      connection.close();
    });

    this._socketClosed = true;
  },

  // PRIVATE FUNCTIONS
  _doStart: function(aResolve, aReject) {
    DEBUG && debug("doStart");

    if (this._socket) {
      aReject("SocketAlreadyInit");
      return;
    }

    this._doQuit = this._socketClosed = false;

    // Monitor xpcom-shutdown to stop service and clean up
    Services.obs.addObserver(this, "xpcom-shutdown", false);

    // Start TLSSocketServer with self-signed certification
    Cc["@mozilla.org/psm;1"].getService(Ci.nsISupports);
    certService.getOrCreateCert("RemoteControlService", {
      handleCert: function(cert, result) {
        if(result) {
          aReject("getOrCreateCert " + result);
        } else {
          let self = RemoteControlService;

          try {
            // Try to get random port
            let ios = Cc["@mozilla.org/network/io-service;1"].getService(Ci.nsIIOService);
            let socket;
            for (let i = 100; i; i--) {
              let temp = Cc["@mozilla.org/network/tls-server-socket;1"].createInstance(Ci.nsITLSServerSocket);
              temp.init(self._port, false, MAX_CLIENT_CONNECTIONS);
              temp.serverCert = cert;

              let allowed = ios.allowPort(temp.port, "tls");
              if (!allowed) {
                DEBUG && debug("Warning: obtained TLSServerSocket listens on a blocked port: " + temp.port);
              }

              if (!allowed && self._port == -1) {
                DEBUG && debug("Throw away TLSServerSocket with bad port.");
                temp.close();
                continue;
              }

              socket = temp;
              break;
            }

            if (!socket) {
              throw new Error("No socket server available. Are there no available ports?");
            }

            DEBUG && debug("Listen on port " + socket.port + ", " + MAX_CLIENT_CONNECTIONS + " pending connections");

            socket.serverCert = cert;
            socket.setSessionCache(false);
            socket.setSessionTickets(false);
            socket.setRequestClientCertificate(Ci.nsITLSServerSocket.REQUEST_NEVER);

            socket.asyncListen(self);
            self._port = socket.port;
            self._socket = socket;
          } catch (e) {
            DEBUG && debug("Could not start server on port " + self._port + ": " + e);
            aReject("Start TLSSocketServer fail");
          }

          // Register mDNS remote control service with this._port
          if (("@mozilla.org/toolkit/components/mdnsresponder/dns-sd;1" in Cc)) {
            let serviceInfo = Cc["@mozilla.org/toolkit/components/mdnsresponder/dns-info;1"].createInstance(Ci.nsIDNSServiceInfo);
            serviceInfo.serviceType = "_remotecontrol._tcp";
            serviceInfo.serviceName = Services.prefs.getCharPref("dom.presentation.device.name");
            serviceInfo.port = self._port;

            let mdns = Cc["@mozilla.org/toolkit/components/mdnsresponder/dns-sd;1"].getService(Ci.nsIDNSServiceDiscovery);
            self._mDNSCancelableHandler = mdns.registerService(serviceInfo, null);
          }

          aResolve();
          self._serverStatus = SERVER_STATUS.STARTED;
        }
      }
    });
  },

  // Notifies this server that the given connection has been closed.
  _connectionClosed: function(connection) {
    NS_ASSERT(connection.number in this._connections,
              "closing a connection " + this + " that we never added to the " +
              "set of open connections?");
    NS_ASSERT(this._connections.get(connection.number) === connection,
              "connection number mismatch?  " +
              this._connections.get(connection.number));
    delete this._connections.get(connection.number);
  },
};

// Represents a connection to the server
function Connection(input, output, server, port, outgoingPort, number) {
  DEBUG && debug("Open a new connection " + number + " on port " + outgoingPort);

  // Stream of incoming data
  this.input = input;

  // Stream for outgoing data
  this.output = output;

  // Server associated with this connection
  this.server = server;

  // Port on which the server is running
  this.port = port;

  // Outgoing poort used by this connection
  this._outgoingPort = outgoingPort;

  // The serial number of this connection
  this.number = number;

  // This allows a connection to disambiguate between a peer initiating a
  // close and the socket being forced closed on shutdown.
  this._closed = false;
}
Connection.prototype = {
  // Closes this connection's input/output streams
  close: function() {
    if (this._closed) {
      return;
    }

    DEBUG && debug("Close connection " + this.number + " on port " + this._outgoingPort);

    this.input.close();
    this.output.close();
    this._closed = true;

    let server = this.server;
    server._connectionClosed(this);

    // If an error triggered a server shutdown, act on it now
    if (server._doQuit) {
      server.stop();
    }
  },
};

function streamClosed(e) {
  return e === Cr.NS_BASE_STREAM_CLOSED ||
         (typeof e === "object" && e.result === Cr.NS_BASE_STREAM_CLOSED);
}

// Parse and dispatch incoming events from client
function EventHandler(connection) {
  this._connection = connection;

  this._output = Cc["@mozilla.org/intl/converter-output-stream;1"]
                   .createInstance(Ci.nsIConverterOutputStream);
  this._output.init(this._connection.output, "UTF-8", 0, 0x0000);

  this._input = Cc["@mozilla.org/intl/converter-input-stream;1"]
                  .createInstance(Ci.nsIConverterInputStream);
  this._input.init(this._connection.input, "UTF-8", 0,
                   Ci.nsIConverterInputStream.DEFAULT_REPLACEMENT_CHARACTER);
}
EventHandler.prototype = {
  // nsIInputStreamCallback
  onInputStreamReady: function(input) {
    DEBUG && debug("onInputStreamReady(input=" + input + ") on thread " +
                   Services.tm.currentThread + " (main is " +
                   Services.tm.mainThread + ")");

    try {
      let available = 0, numChars = 0, fullMessage = "";

      // Read and concat messages from input stream buffer
      do {
        let partialMessage = {};

        available = input.available();
        numChars = this._input.readString(available, partialMessage);

        fullMessage += partialMessage.value;
      } while(numChars < available);

      if (numChars != 0 && fullMessage.length > 0) { // While last readString contains something
        // Handle concatenated JSON string
        fullMessage = '[' + fullMessage.replace(/}{/g, '},{') + ']';

        try {
          // Parse JSON string to event objects
          let events = JSON.parse(fullMessage);

          events.forEach((event) => {
            this._handleEvent(event);
          });
        } catch (e) {
          DEBUG && debug ("Parse event error, drop this message");
        }
      }
    } catch (e) {
      if (streamClosed(e)) {
        DEBUG && debug("WARNING: unexpected error when reading from socket; will " +
                       "be treated as if the input stream had been closed");
        DEBUG && debug("WARNING: actual error was: " + e);
      }

      // Input has been closed, but we're still expecting to read more data.
      // available() will throw in this case, destroy the connection.
      DEBUG && debug("onInputStreamReady called on a closed input, destroying connection");
      this._connection.close();
      return;
    }

    // Wait next message
    input.asyncWait(this, 0, 0, Services.tm.currentThread);
  },

  // PRIVATE FUNCTIONS
  _handleEvent: function(event) {
    // TODO: Implement JPAKE pairing and control command dispatch here
  },
};

RemoteControlService.init();
