"use strict";

const net = require('net');
const extend = require('extend');
const normalizeConnectArgs = net._normalizeConnectArgs;
const dns = require('dns');
const util = require('util');
const inherits = util.inherits;
const EventEmitter = require('events').EventEmitter;
const Parser = require('./client.parser');
const ipbytes = require('./utils').ipbytes;
const CMD = require('./constants').CMD;
const ATYP = require('./constants').ATYP;
const DEFAULTS = {
    socket: {

    },
    proxy: {
        port: 1080,
    },
    dns: {
        local: false,
        strict: false
    },
    auth: false
};

module.exports = class Socks5Socket extends EventEmitter {

    static createConnection(opts) {
        return new Socks5Socket(opts);
    }

    constructor(options) {
        super();
        var self = this;

        EventEmitter.call(this);

        // Set some flags
        self.ready = false;
        self.hadError = false;

        // Setup the Socket
        self.socket = new net.Socket();

        // Bind to socket
        self.socket.on('connect', function() {
            connectSocks(self);
        }).on('close', function(isErr) {
            var a = ['close'];
            for (var i in arguments) a.push(arguments[i]);
            self.emit.apply(self, a);
        }).on('end', function() {
            var a = ['end'];
            for (var i in arguments) a.push(arguments[i]);
            self.emit.apply(self, a);
        });

        self.options = extend(true, {}, DEFAULTS, options);

        self.auth = self.options.auth === false ?
            require('./auth/None.js')() :
            require('./auth/UserPassword.js')();
    }

    connect(a, b, c) {
        var options = {},
            cb = function() {},
            self = this;

        // Normailize arguments
        switch (typeof a) {
            case "string":
                options.host = a;
                switch (typeof b) {
                    case "number":
                    case "string":
                        options.port = b;
                        break;
                    case "function":
                        cb = b;
                        break;
                }
                if (typeof c == "function")
                    cb = c;
                break;
            case "object":
                options = a;
                if (typeof b == "function")
                    cb = b;
                break;
        }

        if (Object.keys(options).length > 0) {
            options = extend({}, self.options.proxy, options); // needed?
            self.options.socket = extend(self.options.socket, options);
        }

        if (!options.port)
            throw new Error('Can only connect to TCP hosts');

        var dsthost = self.options.socket.host,
            dstport = self.options.socket.port;

        self.parser = new Parser(self.socket);

        self.parser.once('connect', function() {
            self.socket.on('lookup', function() {
                self.emit('lookup');
            }).on('data', function(chunk) {
                self.emit('data', chunk)
            }).on('drain', function() {
                self.emit('drain');
            })

            self.emit('connect', self.socket);
            if (typeof cb === 'function')
                cb();

            self.ready = true;
            self.socket.resume();
        });

        self.hadError = self.ready = false;

        if (net.isIP(dsthost) === 0 && self.options.dns.local) {
            dns.lookup(dsthost, function(err, addr) {
                if (err && self.options.dns.strict) {
                    self.hadError = true;
                    self.emit('error', err);
                    self.emit('close', true);
                    return;
                }
                if (addr)
                    self.options.socket.host = addr;
                self.socket.connect(self.options.proxy);
            });
        } else {
            console.log(self.options);
            self.socket.connect(self.options.proxy);
        }

        return this;
    }

    // Copy functionality of a normal Socket
    setTimeout(msecs, callback) {
        return this.socket.setTimeout.apply(this.socket, arguments);
    };

    setNoDelay(noDelay) {
        return this.socket.setNoDelay.apply(this.socket, arguments);
    };

    setKeepAlive(setting, msecs) {
        return this.socket.setKeepAlive.apply(this.socket, arguments);
    };

    address() {
        return this.socket.address.apply(this.socket, arguments);
    };

    cork() {
        return this.socket.cork.apply(this.socket, arguments);
    };

    uncork() {
        return this.socket.uncork.apply(this.socket, arguments);
    };

    pause() {
        return this.socket.pause.apply(this.socket, arguments);
    };

    resume() {
        return this.socket.resume.apply(this.socket, arguments);
    };

    pipe(e) {
        return this.socket.pipe.apply(this.socket, arguments);
    };

    end(data, encoding) {
        return this.socket.end.apply(this.socket, arguments);
    };

    destroy(exception) {
        return this.socket.destroy.apply(this.socket, arguments);
    };

    destroySoon() {
        this.socket.destroySoon.apply(this.socket, arguments);
    };

    setEncoding(encoding) {
        return this.socket.setEncoding.apply(this.socket, arguments);
    };

    write(data, encoding, cb) {
        try {
            return this.socket.write.apply(this.socket, arguments);
        } catch (e) {
            console.log(data.toString());
        }
    };

    read(size) {
        return this.socket.read.apply(this.socket, arguments);
    };

}

function connectSocks(self) {
    self.write(Buffer.concat([
        new Buffer([0x05, 1]),
        new Buffer([self.auth.METHOD])
    ]));

    self.parser.on('method', function(method) {
        if (self.auth.METHOD !== method)
            self.parser.emit('error', 'Authentication method mismatch', 'EAUTHNOTSUPPORT');
        else {
            self.auth.client(self.options.auth, self.socket, function(result) {
                self.parser.start();
                if (result === true) {
                    self.parser.authed = true;
                    sendConnectCmd(self);
                } else if (util.isError(result))
                    self.parser.emit('error', result);
                else
                    self.parser.emit('error', 'Authentication failed', 'EAUTHFAILED');
            });

            self.socket.resume();
        }
    }).on('error', function(err, code) {
        self.hadError = true;
        if (typeof err === "string") {
            err = new Error(err);
            err.code = code;
        }
        self.emit('error', err);
        if (self.socket.writable)
            self.socket.end();
    });
}

function sendConnectCmd(self) {
    var sopts = self.options.socket,
        iptype = net.isIP(sopts.host),
        buff = new Buffer(4);

    buff.writeUInt16BE(sopts.port ? sopts.port : 80, 0, true);
    var size = 1;
    for (var i = 0; i < 4; i++) {
        if (buff[i] != 0x00)
            size = i + 1;

    }
    var buf = new Buffer(size);
    buf.writeUInt16BE(sopts.port ? sopts.port : 80, 0, true);

    var boof = Buffer.concat([
        new Buffer([0x05, CMD.CONNECT, 0x00]),
        iptype === 0 ?
        new Buffer([ATYP.NAME, sopts.host.length]) :
        new Buffer([iptype === 4 ? ATYP.IPv4 : ATYP.IPv6]),
        iptype === 0 ?
        new Buffer(sopts.host) :
        new Buffer(ipbytes(sopts.host)),
        buf
    ]);

    self.write(boof);
};
