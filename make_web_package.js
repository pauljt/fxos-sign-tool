var fs = require('fs');
var walk = require('walk');
var path = require('path');
var buffer = require('buffer');
var mime = require('mime');
var crypto = require('crypto');

//files you don't want to include in the package, but might exist in the working directory
var fileBlacklist = [".DS_Store"];

//will the package be signed?
var signed = true;

var token = createToken(10);

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

if (!fs.existsSync('manifest.webapp')) {
  console.log('Can\'t find "./manifest.webapp, exiting."');
  process.exit(1)
}

var newManifest = JSON.parse(fs.readFileSync("manifest.webapp"));


walker = walk.walk(".");

walker.on("file", function (root, fileStat, next) {
  fs.readFile(path.resolve(root, fileStat.name), function (err, buffer) {
    if (fileBlacklist.indexOf(fileStat.name) < 0) {
      var contentLocation = path.join(root, fileStat.name);

      //skip the manifest since we need to prepend it after we have calculated hashes
      if (contentLocation != 'manifest.webapp') {
        console.log(`Adding ${contentLocation} (${buffer.length} bytes)...`);
        var header = createHeader(contentLocation);

        writeStream.write(token + "\r\n");
        writeStream.write(header);
        writeStream.write(buffer);
        writeStream.write("\r\n");

        //create hash for manifest
        paths.push({"src": contentLocation, "integrity": createHash(header, buffer)});
      }
    }
    next();
  });
});

walker.on("errors", function (root, nodeStatsArray, next) {
  next();
});

walker.on("end", function () {
  console.log(JSON.stringify(paths));
  writeStream.end(function () {
    //prepend manifest & signature
    process.chdir(script_dir);


    newManifest["moz-resources"] = paths;
    var newManifestChunk = createHeader("manifest.webapp") + JSON.stringify(newManifest, null, '  ') + "\r\n";
    var signature = signManifest(newManifestChunk);
    var prependBlock = new Buffer(signature + token + "\r\n" + newManifestChunk);


    var data = fs.readFileSync(packageFilename);
    console.log(prependBlock.toString() + data)
    var fd = fs.openSync(packageFilename, 'w');
    fs.writeSync(fd, prependBlock + data);
    fs.close(fd);

    console.log('Package saved to:' + __dirname + "/" + packageFilename);
  });

});

function createToken(length) {
  var chars = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ';
  var result = '';
  for (var i = length; i > 0; --i) result += chars[Math.round(Math.random() * (chars.length - 1))];
  return "--" + result;
}


function createHeader(contentLocation) {
  var mimeType = mime.lookup(path.extname(contentLocation));
  return `Content-Location: ${contentLocation}\r\n` +
    `Content-Type: ${mimeType}\r\n` +
    `\r\n`;
}


function createHash(header, buffer) {
  var shasum = crypto.createHash('sha256');
  shasum.update(header);
  shasum.update(buffer);
  return shasum.digest('base64');
}

function signManifest(manifest) {
  var signingKey = fs.readFileSync('trusted_ca1.der');
  signingKey = derToPem(signingKey);

  //debug key
  fs.writeFileSync('out.pem', signingKey);

  var shasum = crypto.createHash('sha1')
    .update(manifest)
    .digest('base64');

  console.log(shasum)

  var signature = crypto.createSign('RSA-SHA256')
    .update(shasum)

  //TODO - this fails because Error: error:0906D06C:PEM routines:PEM_read_bio:no start line
  //.sign(signingKey, 'base64')
  //return signature + "\r\n";

  return "SIGNATURE GOES HERE!\r\n"
}


function derToPem(der) {
  var body=der.toString('base64').match(/.{1,64}/g).join("\n");
  return "-----BEGIN CERTIFICATE-----\n" +body+
    "\n-----END CERTIFICATE-----\n"
}