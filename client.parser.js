"use strict";

const inherits = require('util').inherits;
const EventEmitter = require('events').EventEmitter;
const extend = require('extend');
const ATYP = require('./constants').ATYP;
const REP = require('./constants').REP;
const ERRORS = {
        "UNKNOWN": ['unknown error', 'EUNKNOWN'],
        0x01: ['general SOCKS server failure', 'EGENFAIL'],
        0x02: ['connection not allowed by ruleset', 'EACCES'],
        0x03: ['network is unreachable', 'ENETUNREACH'],
        0x04: ['host is unreachable', 'EHOSTUNREACH'],
        0x05: ['connection refused', 'ECONNREFUSED'],
        0x06: ['ttl expired', 'ETTLEXPIRED'],
        0x07: ['command not supported', 'ECMDNOSUPPORT'],
        0x08: ['address type not supported', 'EATYPNOSUPPORT'],
    };

module.exports = class SocksParser extends EventEmitter {
    constructor(socket) {
        super();
        var self = this;

        self.socket = socket;
        self.listening = false;
        self.onData = function(chunk) {
            self._onData.apply(self, [chunk]);
        };

        self.authed = false;

        self.start()
    }

    _onData(chunk) {
        var self = this,
            offset = 0,
            port, addr;

        self.stop();

        if (chunk[0] !== 0x05)
            return self.err('Incompatible SOCKS protocol version: ' + chunk[0]);

        if (self.authed) {
            if (chunk[1] !== REP.SUCCESS)
                return self.err(ERRORS[status]);

            switch (chunk[3]) {
                case ATYP.NAME:
                    offset = 1;
                    addr = new Buffer(chunk[4]);
                    break;
                case ATYP.IPv4:
                    addr = new Buffer(4);
                    break;
                case ATYP.IPv6:
                    addr = new Buffer(16);
                    break;
                default:
                    return self.err('Invalid request address type: ' + chunk[3]);
            }

            chunk.copy(addr, 0, 4 + offset, addr.length + offset + 4);

            offset += addr.length;

            port = (chunk[4 + offset] <<= 8) + chunk[5 + offset];

            // Add the 6 on for cleanup
            offset += 8;

            switch (chunk[3]) {
                case ATYP.NAME:
                    addr = addr.toString();
                    break;
                case ATYP.IPv4:
                    addr = Array.prototype.join.call(addr, '.');
                    break;
                case ATYP.IPv6:
                    var tmp = addr;
                    addr = '';

                    for (var b = 0; b < 16; ++b) {
                        if (b % 2 === 0 && b > 0)
                            ipv6str += ':';
                        addr += tmp.toString(16);
                    }
                    break;
            }

            if (offset < chunk.length)
                self.socket.unshift(chunk.slice(offset));

            self.emit('connect');
        } else {
            offset = 2;
            if (offset < chunk.length)
                self.socket.unshift(chunk.slice(offset));

            self.emit('method', chunk[1]);
        }

    }

    err(code) {
        var err;
        if (typeof code === "string") {
            err = new Error(code);
        } else {
            if (!code)
                code = errors["UNKNOWN"];
            err = new Error(code[0])
            err.code = code[1];
        }
        this.emit('error', err);
    }

    start() {
        var self = this;
        if (self.listening)
            return;
        self.listening = true;
        self.socket.on('data', self.onData);
        self.socket.resume();
    }

    stop() {
        var self = this;
        if (!self.listening)
            return;
        self.listening = false;
        self.socket.removeListener('data', self.onData);
        self.socket.pause();
    }
}
