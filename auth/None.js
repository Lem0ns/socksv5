module.exports = function NoneAuthHandlers() {
  return {
    METHOD: 0x00,
    server: function serverHandler(socks, stream, cb) {
      cb(true);
    },
    client: function clientHandler(auth, stream, cb) {
      cb(true);
    }
  };
};
