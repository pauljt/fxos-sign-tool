#!/usr/bin/env node
var static = require("node-static");
var file = new static.Server('test', {
  headers: {
    "Content-Security-Policy": "default-src *; script-src 'self'; object-src 'none'; style-src 'self';"
  }
});

const PORT = process.env.PORT || 12345;
require ('http').createServer(function (req, res) {
  req.addListener('end', function () {
    file.serve(req, res);
  }).resume();
}).listen(PORT);

console.log("> node-static is listening on http://127.0.0.1:"+PORT);
