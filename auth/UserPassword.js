module.exports = function PassAuth(authcb) {
    return {
        METHOD: 0x02,
        server: function serverHandler(socks, stream, cb) {
            stream.on('data', function onData(chunk) {
                var err = false,
                    user, pass,
                    offset = 0,
                    headlen = 0;

                // Check that version is correct
                if (chunk[0] !== 0x01)
                    err = 'Unsupported auth request version: ' + chunk[0];

                // Check user length is valid
                if (chunk[1] === 0)
                    err = 'Bad username length (0)';

                user = new Buffer(chunk[1]);

                // Set the offset to be length of the chunk
                offset = chunk[1];

                // Extract the username
                chunk.copy(user, 0, 2, 2 + offset);

                // Check that password is valid
                if (chunk[2 + offset] == 0)
                    err = 'Bad password length (0)';

                pass = new Buffer(chunk[2 + offset]);

                // Set the head length
                headlen = 3 + offset + pass.length;

                // Extract the password
                chunk.copy(pass, 0, 3 + offset, headlen);

                stream.removeListener('data', onData);

                user = user.toString('utf-8');
                pass = pass.toString('utf-8');

                // If error, handle it
                if (err) {
                    cb(new Error(err));
                    return;
                }

                if (headlen < chunk.length)
                    stream.unshift(chunk.slice(headlen));

                authcb(socks, user, pass, function(success) {
                    if (stream.writable) {
                        stream.write(new Buffer([0x01, success ? 0x00 : 0x01]));
                        cb(success);
                    }
                });
            });
        },
        client: function clientHandler(auth, stream, cb) {
            var onData = function(chunk) {
                var err = false;

                // Check if auth byte is right
                if (chunk[0] != 0x01)
                    err = 'Unsupported auth request version: ' + chunk[0];

                // Remove listener from stream
                stream.removeListener('data', onData);

                // Unshift so data can be processed correctly
                if (2 < chunk.length)
                    stream.socket.unshift(chunk.slice(2));

                // Callback, error or confirmed
                cb(err ? new Error(err) : chunk[1] === 0);
            }
            stream.on('data', onData);

            // Write the data to the stream
            stream.write(Buffer.concat([
                new Buffer([0x01, auth.user.length]),
                new Buffer(auth.user),
                new Buffer([auth.pass.length]),
                new Buffer(auth.pass)
            ]));
        }
    };
};
