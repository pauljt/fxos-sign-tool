var fs = require('fs');
var walk = require('walk');
var path = require('path');
var buffer = require('buffer');
var mime = require('mime');
var crypto = require('crypto');
var forge = require('node-forge')

const SIGNINGKEY = 'privatekey.pem';
const DEVELOPERCERT = 'developercert.der'

//files you don't want to include in the package, but might exist in the working directory
var fileBlacklist = [".DS_Store"];

//will the package be signed?
var signed = true;


var token = createToken(10);

if (process.argv.length <= 3) {
  console.log("usage: node make_web_package.js <app-folder> <package-name>");
  console.log("To test, run: node make_web_package.js test/myapp test.pak");
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
  writeStream.end(function () {
    //prepend manifest & signature
    process.chdir(script_dir);

    newManifest["moz-resources"] = paths;
    var newManifestChunk = createHeader("manifest.webapp") + JSON.stringify(newManifest, null, '  ') + "\r\n";
    var signature = signManifest(newManifestChunk);
    var prependBlock = new Buffer(signature + token + "\r\n" + newManifestChunk);


    var data = fs.readFileSync(packageFilename);
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
  var privateKey = createOrLoadSigningKey();

  var shasum = crypto.createHash('sha1')
    .update(manifest)
    .digest('base64');

  var signature = crypto.createSign('RSA-SHA256')
    .update(shasum)
    .sign(privateKey, 'base64');
  return `manifest-signature: ${signature}\n`;
}

//Loads a privatekey from
function createOrLoadSigningKey() {
  var pki=forge.pki;
  var keys = pki.rsa.generateKeyPair({bits: 512, e: 0x10001});
  var cert = forge.pki.createCertificate();
  cert.publicKey = keys.publicKey;
  cert.serialNumber = '01';
  cert.validity.notBefore = new Date();
  cert.validity.notAfter = new Date();
  cert.validity.notAfter.setFullYear(cert.validity.notBefore.getFullYear() + 1);
  var attrs = [{
    name: 'commonName',
    value: 'example.org'
  }, {
    name: 'countryName',
    value: 'US'
  }, {
    shortName: 'ST',
    value: 'Virginia'
  }, {
    name: 'localityName',
    value: 'Blacksburg'
  }, {
    name: 'organizationName',
    value: 'Test'
  }, {
    shortName: 'OU',
    value: 'Test'
  }];
  cert.setSubject(attrs);
  cert.setIssuer(attrs);
  cert.setExtensions([{
    name: 'basicConstraints',
    cA: true
  }, {
    name: 'keyUsage',
    keyCertSign: true,
    digitalSignature: true,
    nonRepudiation: true,
    keyEncipherment: true,
    dataEncipherment: true
  }, {
    name: 'extKeyUsage',
    serverAuth: true,
    clientAuth: true,
    codeSigning: true,
    emailProtection: true,
    timeStamping: true
  }, {
    name: 'nsCertType',
    client: true,
    server: true,
    email: true,
    objsign: true,
    sslCA: true,
    emailCA: true,
    objCA: true
  }, {
    name: 'subjectAltName',
    altNames: [{
      type: 6, // URI
      value: 'http://example.org/webid#me'
    }, {
      type: 7, // IP
      ip: '127.0.0.1'
    }]
  }, {
    name: 'subjectKeyIdentifier'
  }]);

  cert.sign(keys.privateKey,forge.md.sha256.create());

  var asn1=pki.certificateToAsn1(cert);
  var der = forge.asn1.toDer(asn1);
  fs.writeFileSync(DEVELOPERCERT, der.getBytes(), {encoding: 'binary'});

  //write out private key
  var privateKeyPem = pki.privateKeyToPem(keys.privateKey);
  fs.writeFileSync(SIGNINGKEY, privateKeyPem);

  return privateKeyPem;
}