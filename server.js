"use strict";

const net = require('net');
const dns = require('dns');
const util = require('util');
const extend = require('extend');
const crypto = require('crypto');
const ipcheck = require('ipcheck').match;
const inherits = util.inherits;
const EventEmitter = require('events').EventEmitter;
const Parser = require('./server.parser');
const ipbytes = require('./utils').ipbytes;
const ATYP = require('./constants').ATYP;
const REP = require('./constants').REP;
const BUF_AUTH_NO_ACCEPT = new Buffer([0x05, 0xFF]);
const BUF_REP_INTR_SUCCESS = new Buffer([0x05, REP.SUCCESS, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
const BUF_REP_DISALLOW = new Buffer([0x05, REP.DISALLOW]);
const BUF_REP_CMDUNSUPP = new Buffer([0x05, REP.CMDUNSUPP]);
const BLACKLIST_DEFAULT = [
        '10.0.0.0/8',     // IPv4 local addresses
        '172.16.0.0/12',  // ...
        '192.168.0.0/16', // ...
        'fc00::/7',       // IPv6 local addresses
    ];
const DEFAULTS = {
        limits: {
            connections: Infinity,  // Max number of connections
        },
        server: {
            port: 1080
        },
        socket: {

        },
        blacklist: [],
        auth: false
    };
module.exports = class Server extends EventEmitter {
    constructor(options) {
        super();

        var self = this;

        options = extend(true, {}, DEFAULTS, options);

        // Setup the blacklist to block local addresses by default
        if (typeof options.blacklist !== "object")
            options.blacklist = [];
        options.blacklist = options.blacklist.concat(BLACKLIST_DEFAULT);

        self.options = options;
        self.sockets = {};

        EventEmitter.call(self);

        if (!options.auth) {
            self.auth = require("./auth/None.js")();
        } else {
            self.auth = require("./auth/UserPassword.js")(self.options.auth);
        }

        self._connections = 0;

        self.server = new net.Server(function(socket) {
                if (self._connections >= self.options.limits.connections) {
                    socket.destroy();
                    return;
                }
                ++self._connections;
                socket.once('close', function(had_err) {
                    --self._connections;
                });
                self.handleConnection(socket);
            }).on('error', function(err) {
                self.emit('error', err);
            }).on('listening', function() {
                self.emit('listening');
            }).on('close', function() {
                self.emit('close');
            });
    }

    listen() {
        var self = this;
        self.server.listen(self.options.server.port, self.options.server.address);
        self.emit('ready');
    }

    handleConnection(socket) {
        var self = this,
            parser = new Parser(socket),
            ow = socket.write;

        socket.write = function (data) {
            ow.apply(socket, arguments)
        }

        parser.on('error', function(err) {
            if (socket.writable)
                socket.end();
            console.log("Error: ", err);
        }).on('methods', function(methods) {
            socket.write(new Buffer([0x05, self.auth.METHOD]));
            socket.resume();

            self.auth.server(self, socket, function(result) {
                if (result) {
                    parser.authed = true;
                    parser.start();
                } else {
                    if (util.isError(result))
                        console.log('Error: ' + result.message);
                    socket.end();
                }
            });
        }).on('request', function(req) {
            if (req.cmd !== 'connect')
                return socket.end(BUF_REP_CMDUNSUPP);

            var uid = 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function(c) {
                var r = crypto.randomBytes(1)[0]%16|0, v = c == 'x' ? r : (r&0x3|0x8);
                return v.toString(16);
            })

            req.srcAddr = socket.remoteAddress;
            req.srcPort = socket.remotePort;

            var handled = false;

            function accept(intercept) {
                if (handled)
                    return;

                handled = true;
                if (socket.writable)
                    self.spawnSocket(socket, uid, req);
                else
                    console.log("Dropped connection due to socket unwritable");
            }

            function deny() {
                if (handled)
                    return;

                handled = true;
                if (socket.writable)
                    socket.end(BUF_REP_DISALLOW);
            }

            dns.lookup(req.dstAddr, function(err, ip) {
                if (err) {
                    self.handleProxyError(socket, err);
                    return;
                }

                // Scan the blacklist first
                var dirty = false;
                self.options.blacklist.forEach(function (e) {
                    if (!dirty)
                        dirty = ipcheck(ip, e);
                });

                if (dirty) {
                    socket.end(new Buffer([0x05, REP.CONNREFUSED]));
                    return;
                }

                self.emit('connection', req, uid, accept, deny);
            });
        });

        function onClose() {
            if (socket.dstSock && socket.dstSock.writable)
            socket.dstSock.end();
            socket.dstSock = undefined;
        }

        socket.on('error', self.onError)
            //.on('end', onClose)
            .on('close', onClose);
    }

    killConns() {
        for (var s in this.sockets) {
            this.sockets[s].src.end();
            this.sockets[s].dst.end();

            delete this.sockets[s];
        }
    }

    getNewSocket() {
        return net.Socket();
    }

    spawnSocket(socket, uid, req) {
        var self = this;
        var dstSock = self.getNewSocket(),
            connected = false;

        self.sockets[uid] = {
            src: socket,
            dst: dstSock
        };

        dstSock.on('error', function onError(err) {
            if (!connected)
                self.handleProxyError(socket, err);
        }).on('connect', function() {
            connected = true;
            if (socket.writable) {
                var localbytes = ipbytes(dstSock.socket.localAddress),
                    bufrep = new Buffer(6 + localbytes.length);
                bufrep[0] = 0x05;
                bufrep[1] = REP.SUCCESS;
                bufrep[2] = 0x00;
                bufrep[3] = (localbytes.length === 4 ? ATYP.IPv4 : ATYP.IPv6);
                for (var i = 0; i < localbytes.length; ++i)
                    bufrep[i + 4] = localbytes[i];
                bufrep.writeUInt16BE(dstSock.socket.localPort, bufrep.length, true);

                socket.write(bufrep);

                socket.on('error', function (err) {
                    self.emit('connection.error', err);
                }).on('close', function () {
                    self.emit('connection.close', uid);
                    dstSock.socket.removeAllListeners("close");
                    dstSock.socket.end();
                    delete self.sockets[uid];
                });

                var flag = false;

                socket.on('data', function (data) {
                    dstSock.write(data);
                })
                dstSock.on('data', function (data) {
                    socket.write(data);
                })
                socket.resume();
            } else if (dstSock.socket.writable)
                dstSock.socket.end();
        })/*.on('data', function (chunk) {
            self.limitInbound(chunk, uid, dstSock, socket);
        })//*/
        .on('close', function () {
            self.emit('connection.close', uid);
            socket.removeAllListeners("close");
            socket.end();
            delete self.sockets[uid];
        })
        .connect(extend(true, {}, self.options.socket, {
            port: req.dstPort,
            host: req.dstAddr
        }));
    }

    onError(err) {}

    handleProxyError(socket, err) {
        if (socket.writable) {
            var errbuf = new Buffer([0x05, REP.GENFAIL]);
            if (err.code) {
                switch (err.code) {
                    case 'ENOENT':
                    case 'ENOTFOUND':
                    case 'ETIMEDOUT':
                    case 'EHOSTUNREACH':
                        errbuf[1] = REP.HOSTUNREACH;
                    break;
                    case 'ENETUNREACH':
                        errbuf[1] = REP.NETUNREACH;
                    break;
                    case 'ECONNREFUSED':
                        errbuf[1] = REP.CONNREFUSED;
                    break;
                }
            }
            socket.end(errbuf);
        }
    }

    close() {
        this.server.close();
    }
}
