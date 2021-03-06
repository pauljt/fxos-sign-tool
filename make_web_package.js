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
    //go back to script dir first
    process.chdir(script_dir);
    //generate signed manifest, including file hashes
    newManifest["moz-resources"] = paths;
    var newManifestChunk = createHeader("manifest.webapp") + JSON.stringify(newManifest, null, '  ') + "\r\n";
    var signature = signManifest(newManifestChunk);
    var prependBlock = new Buffer(signature + token + "\r\n" + newManifestChunk);

    //prepend manifest & signature

    var data = fs.readFileSync(packageFilename);
    var fd = fs.openSync(packageFilename, 'w');
    fs.writeSync(fd, prependBlock + data + token);
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
  var certASN = forge.asn1.fromDer(forge.util.createBuffer(fs.readFileSync(DEVELOPERCERT), 'raw'));
  var devcert = forge.pki.certificateFromAsn1(certASN);

  var shasum = crypto.createHash('sha1')
    .update(manifest)
    .digest('base64');
  console.log(shasum)

  var p7 = forge.pkcs7.createSignedData();
  p7.content = forge.util.createBuffer(shasum, 'utf8');
  p7.addSigner({
    key: forge.pki.privateKeyFromPem(privateKey),
    certificate: devcert,
    digestAlgorithm: forge.pki.oids.sha1,
    authenticatedAttributes: [{
      type: forge.pki.oids.contentType,
      value: forge.pki.oids.data
    }, {
      type: forge.pki.oids.messageDigest
    }, {
      type: forge.pki.oids.signingTime
    }]
  });
  p7.addCertificate(devcert);
  p7.sign();

  //detach content
  //p7.content=null;

  var p7Asn1 = p7.toAsn1();
  var p7Der= forge.asn1.toDer(p7Asn1);
  fs.writeFileSync('badsig.sig',p7Der.getBytes(),{encoding: 'binary'});

  var signature=forge.util.encode64(p7Der);

  /*
   var pem = forge.pkcs7.messageToPem(p7);


   console.log(pem);
   // strip of the pksc7 header and remove new lines to convert from pem to der
   signature=pem.match(/-----BEGIN PKCS7-----([\s\S]*)-----END PKCS7-----/)[1];
   console.log(1,signature);
   signature=signature.replace(/\r\n/gi,'');
   console.log(2,signature);*/


  return `manifest-signature: ${signature}\n`;
}

//Loads a privatekey from
function createOrLoadSigningKey() {
 /*
  //if there is a signing key in the directory already, use it

  if (fs.existsSync(SIGNINGKEY) || fs.existsSync(DEVELOPERCERT)) {
    console.log(`Signging with existing ${SIGNINGKEY} file`)
    var privateKeyPem = fs.readFileSync(SIGNINGKEY);
    return privateKeyPem;
  }
  */


  console.log('No signing key found, generating new key and certificate');
  var pki = forge.pki;
  var keys = pki.rsa.generateKeyPair({bits: 2048, e: 0x10001});
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
    name: 'extKeyUsage',
    codeSigning: true
  }, {
    name: 'keyUsage',
    keyCertSign: true,
    digitalSignature: true
  },{
    name: 'nsCertType',
    client: true,
    server: true,
    email: true,
    objsign: true,
    sslCA: true,
    emailCA: true,
    objCA: true
  }]);

  cert.sign(keys.privateKey, forge.md.sha256.create());

  var asn1 = pki.certificateToAsn1(cert);
  var der = forge.asn1.toDer(asn1);
  fs.writeFileSync(DEVELOPERCERT, der.getBytes(), {encoding: 'binary'});

  //write out private key
  var privateKeyPem = pki.privateKeyToPem(keys.privateKey);
  fs.writeFileSync(SIGNINGKEY, privateKeyPem);

  return privateKeyPem;
}


function createCAcert() {

}

function createSigningCert() {

}


function loadCertFromDer(filename) {
  var derString = fs.readFileSync(filename);
  var buffer = forge.util.createBuffer(derString, 'raw');
  var asn1 = forge.asn1.fromDer(buffer);
  return cert = forge.pki.certificateFromAsn1(asn1);
}