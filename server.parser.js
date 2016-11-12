"use strict";

const inherits = require('util').inherits;
const extend = require('extend');
const EventEmitter = require('events').EventEmitter;
const CMD = require('./constants').CMD;
const ATYP = require('./constants').ATYP;

module.exports = class Parser extends EventEmitter {

    constructor(socket) {
        super();
        var self = this;

        self.socket = socket;
        self.listener = false;

        self.onData = function (chunk) {
            self.handleData(chunk);
        }

        self.authed = false;
        self.start();
    }

    handleData(chunk) {
        var self = this,
            cursor = 1,
            err = false,
            methods, offset, cmd, dstaddr, dstport, type, cmdc;

        if (chunk[0] !== 0x05)
            return self.err('Incompatible SOCKS protocol version: ' + chunk[0]);

        if (!self.authed) {
            // Provide methods
            if (chunk[1] == 0)
                return self.err('Unexpected empty methods list');

            offset = chunk[1];
            methods = new Buffer(offset);

            chunk.copy(methods, 0, 2, 2 + offset);

            // Cleanup
            self.stop();
            if (2 + offset < chunk.length)
                self.socket.unshift(chunk.slice(2 + offset));

            // Emit methods
            self.emit('methods', methods);
        } else {
            // Determine the command thats going to execute
            cmdc = chunk[cursor++];
            if (cmdc === CMD.CONNECT)
                cmd = 'connect';
            else if (cmdc === CMD.BIND)
                cmd = 'bind';
            else if (cmdc == CMD.UDP)
                cmd = 'udp';
            else {
                self.stop();
                return self.err('Invalid request command: '+cmd);
            }

            // Skip STATE_REQ_RSV
            cursor++;

            // Determine the address type
            type = chunk[cursor++];
            if (type === ATYP.IPv4)
                dstaddr = new Buffer(4);
            else if (type === ATYP.IPv6)
                dstaddr = new Buffer(16);
            else if (type === ATYP.NAME)
                dstaddr = new Buffer(chunk[cursor++]);
            else {
                self.stop();
                return self.err('Invalid request address type: ' + atyp);
            }

            // Copy the address
            chunk.copy(dstaddr, 0, cursor, cursor + dstaddr.length);

            // Add the address length onto the cursor
            cursor += dstaddr.length;

            // Read the port
            if (dstport === undefined)
                dstport = chunk[cursor++];

            dstport <<= 8;
            dstport += chunk[cursor++];

            // Cleanup
            self.stop();
            if (cursor < chunk.length)
                self.socket.unshift(chunk.slice(cursor));

            // Format the address properly
            if (type === ATYP.IPv4)
                dstaddr = Array.prototype.join.call(dstaddr, '.');
            else if (type === ATYP.IPv6)
                dstaddr = (function (addr) {
                    var str = '';
                    for (var b = 0; b < 16; ++b)
                    str += ((b % 2 === 0 && b > 0) ? ':' : '')
                    + addr[b].toString(16);
                    return str;
                })(dstaddr);
            else
                dstaddr = dstaddr.toString();

            // Emit the request
            self.emit('request', {
                cmd: cmd,
                srcAddr: undefined,
                srcPort: undefined,
                dstAddr: dstaddr,
                dstPort: dstport
            });
        }
    }

    err(err) {
        this.emit('error', new Error(err));
    }

    start() {
        if (this.listener)
            return;
        this.listener = true;
        this.socket.on('data', this.onData);
        this.socket.resume();
    }

    stop() {
        if (!this.listener)
            return;
        this.listener = false;
        this.socket.removeListener('data', this.onData);
        this.socket.pause();
    }
}
