# SOCKSv5 client and server implementation for Node

This is a rewrite of https://github.com/mscdex/socksv5

# Client usage
```js
const socks = require('socksv5');

var socket = new socks.Socket({
    proxy: {
        host: 'myproxy.com'
        port: 1080,
    },
    auth: false
});

socket.on('connect', function () {
    // Connected to google.com through socks
})

```

`socks.Socket` can be treated as a regular `net.Socket` in most cases, and
as a basic (only supports `createConnection`) `http.Agent` as well:

```js
const request = require('request');
const socks = require('socksv5');

request({
    url: 'http://google.com/',
    agentClass: socks.Socket,
    agentOptions: {
        proxy: {
            host: 'myproxy.com'
        }
    }
}, function (err, httpResponse, body) {
    // Response of google.com through socksv5 proxy
})
```

# Server usage
```js
const socks = require('socksv5');

var server = new socks.Server({
    server: {
        host: 'localhost',
        port: 1080
    },
    auth: {
        user: "username",
        pass: "password"
    }
}).on('ready', function () {
    // Listening
}).on('connection', function(info, uid, accept, deny) {
    accept(); // Must accept() or deny() in this event
}).listen();

// And close it
server.close();
```
