'use strict';

var constants = require('constants')
, https = require('https')
, http = require('http')
, url    = require('url')
, fs     = require('fs')
, cfg = {
    key: '/etc/letsencrypt/live/v4.ip.ms/privkey.pem',
    cert: '/etc/letsencrypt/live/v4.ip.ms/fullchain.pem',
    listeners: [
        { ip: "::", port: 80, ssl: false }, 
        { ip: "::", port: 443, ssl: true } 
    ],
}
, opt = { 
    key: fs.readFileSync(cfg.key).toString(), 
    cert: fs.readFileSync(cfg.cert).toString(),
    ciphers: "EECDH+ECDSA+AESGCM EECDH+aRSA+AESGCM EECDH+ECDSA+SHA384 EECDH+ECDSA+SHA256 EECDH+aRSA+SHA384 EECDH+aRSA+SHA256 EECDH+aRSA+RC4 EECDH EDH+aRSA RC4 !aNULL !eNULL !LOW !3DES !MD5 !EXP !PSK !SRP !DSS !RC4",
    honorCipherOrder: true,
    secureOptions: constants.SSL_OP_NO_SSLv3 | constants.SSL_OP_NO_SSLv2
}
, header = {
    "Server": "IPMS-Engine", 
    "Content-Type": "text/plain", 
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains", 
    "Access-Control-Allow-Origin": "*"
}
, handler = function (req, res) {
    if (req.url === '/') {
        console.log("200 " + req.connection.remoteAddress);
        res.writeHead(200, header);
        res.end(req.connection.remoteAddress);
    }
    else if (req.url.substr(0,13) === '/.well-known/') {
        fs.readFile(__dirname + req.url, "binary", function(err, file) {
            if (err) {
                res.writeHead(404, header);
                res.end("404 Not Found\n");
            }
            else {
                res.writeHead(200, header);
                res.end(file, "binary");
            }
        });
    }
    else {
        console.log("404 " + req.connection.remoteAddress + " " + req.url);
        res.writeHead(404, header);
        res.end("404 Not Found\n");  
    }
};

cfg.listeners.forEach(function(ip) {
    var s = (ip.ssl)?https.createServer(opt, handler):http.createServer(handler);
    s.listen(ip.port, ip.ip);
});
