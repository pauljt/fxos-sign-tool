var fs = require('fs');
var walk = require('walk');
var path = require('path');
var buffer = require('buffer');
var mime = require('mime');

//manifest is blacklisted since we prepend it at the end, after file hashes are calculated.
var fileBlacklist = [".DS_Store"];

function token_generator(length) {
  var chars = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ';
  var result = '';
  for (var i = length; i > 0; --i) result += chars[Math.round(Math.random() * (chars.length - 1))];
  return "--"+result;
}

var token = token_generator(10);

if (process.argv.length <= 3) {
  console.log("usage: node make_web_package.js <app-folder> <package-name>");
  process.exit(1);
}

var packageRoot = process.argv[2];
var packageFilename = process.argv[3];

console.log(`Packing ${packageRoot} to ${packageFilename}`);

//move to content dir and perform some checks
var paths = [];
var writeStream = fs.createWriteStream(packageFilename);
var script_dir = process.cwd();
process.chdir(packageRoot);

if (!fs.existsSync('./manifest.webapp')) {
  console.log('Can\'t find "./manifest.webapp, exiting."');
  process.exit(1)
}

walker = walk.walk(".");

walker.on("file", function (root, fileStat, next) {
  fs.readFile(path.resolve(root, fileStat.name), function (err, buffer) {
    if (fileBlacklist.indexOf(fileStat.name) < 0) {
      var contentLocation = path.join(root, fileStat.name);
      if(contentLocation!='manifest.webapp'){
        console.log(`Adding ${contentLocation} (${buffer.length} bytes)...`);
        writeStream.write(token+"\r\n");
        writeStream.write("Content-Location: " + contentLocation + "\r\n");
        var mimeType = mime.lookup(path.extname(contentLocation));
        writeStream.write("Content-Type: " + mimeType + "\r\n");
        writeStream.write("\r\n");
        writeStream.write(buffer);
        writeStream.write("\r\n");
        paths.push(contentLocation);
      }
    }
    next();
  });
});

walker.on("errors", function (root, nodeStatsArray, next) {
  next();
});

walker.on("end", function () {
  console.log('Package saved to:' + __dirname + "/" + packageFilename);
  console.log(JSON.stringify(paths));
  writeStream.end();
});


