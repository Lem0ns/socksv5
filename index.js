const extend = require('extend');

module.exports = {
    Server: require("./server.js"),
    Socket: require("./client.js"),
    HttpAgent: require("./agent.js").HttpAgent,
    HttpsAgent: require("./agent.js").HttpsAgent
};
