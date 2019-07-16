"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
var axios_1 = __importDefault(require("axios"));
var chai_1 = require("chai");
var crypto_1 = require("crypto");
var querystring_1 = require("querystring");
var index_1 = require("../index");
var keys_1 = require("../keys");
var utils_1 = require("../utils");
var ETH_PRVHEX = "0x95d3c5e483e9b1d4f5fc8e79b2deaf51362980de62dbb082a9a4257eef653d7d";
var ETH_PUBHEX = "0x98afe4f150642cd05cc9d2fa36458ce0a58567daeaf5fde7333ba9b403011140"
    + "a4e28911fcf83ab1f457a30b4959efc4b9306f514a4c3711a16a80e3b47eb58b";
var PYTHON_BACKEND = "https://eciespy.herokuapp.com/";
describe("test encrypt and decrypt", function () {
    var text = "helloworld";
    var config = {
        headers: {
            "Content-Type": "application/x-www-form-urlencoded",
        },
    };
    it("tests aes with random key", function () {
        var key = crypto_1.randomBytes(32);
        var data = Buffer.from("this is a test");
        chai_1.expect(data.equals(utils_1.aesDecrypt(key, utils_1.aesEncrypt(key, data)))).to.be.equal(true);
    });
    it("tests aes decrypt with known key and text", function () {
        var key = Buffer.from(utils_1.decodeHex("0000000000000000000000000000000000000000000000000000000000000000"));
        var nonce = Buffer.from(utils_1.decodeHex("f3e1ba810d2c8900b11312b7c725565f"));
        var tag = Buffer.from(utils_1.decodeHex("ec3b71e17c11dbe31484da9450edcf6c"));
        var encrypted = Buffer.from(utils_1.decodeHex("02d2ffed93b856f148b9"));
        var data = Buffer.concat([nonce, tag, encrypted]);
        var decrypted = utils_1.aesDecrypt(key, data);
        chai_1.expect(decrypted.toString()).to.be.equal(text);
    });
    it("test encrypt/decrypt against python version", function () {
        var prv = new keys_1.PrivateKey(utils_1.decodeHex(ETH_PRVHEX));
        axios_1.default.post(PYTHON_BACKEND, querystring_1.stringify({
            data: text,
            pub: ETH_PUBHEX,
        })).then(function (res) {
            var encryptedKnown = Buffer.from(utils_1.decodeHex(res.data));
            var decrypted = index_1.decrypt(prv.toHex(), encryptedKnown);
            chai_1.expect(decrypted.toString()).to.be.equal(text);
        });
        var encrypted = index_1.encrypt(prv.publicKey.toHex(), Buffer.from(text));
        axios_1.default.post(PYTHON_BACKEND, querystring_1.stringify({
            data: encrypted.toString("hex"),
            prv: prv.toHex(),
        })).then(function (res) {
            chai_1.expect(text).to.be.equal(res.data);
        });
    });
});
describe("test keys", function () {
    it("test invalid", function () {
        // 0 < private key < group order int
        var groupOrderInt = "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141";
        chai_1.expect(function () { return new keys_1.PrivateKey(utils_1.decodeHex(groupOrderInt)); }).to.throw(Error);
        var groupOrderIntAdd1 = "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364142";
        chai_1.expect(function () { return new keys_1.PrivateKey(utils_1.decodeHex(groupOrderIntAdd1)); }).to.throw(Error);
        chai_1.expect(function () { return new keys_1.PrivateKey(utils_1.decodeHex("0")); }).to.throw(Error);
    });
    it("tests equal", function () {
        var prv = new keys_1.PrivateKey();
        var pub = keys_1.PublicKey.fromHex(prv.publicKey.toHex(false));
        var isPubEqual = pub.uncompressed.equals(prv.publicKey.uncompressed);
        chai_1.expect(isPubEqual).to.be.equal(true);
        var isFromHexWorking = prv.equals(keys_1.PrivateKey.fromHex(prv.toHex()));
        chai_1.expect(isFromHexWorking).to.be.equal(true);
    });
    it("tests eth key compatibility", function () {
        var ethPrv = keys_1.PrivateKey.fromHex(ETH_PRVHEX);
        var ethPub = keys_1.PublicKey.fromHex(ETH_PUBHEX);
        chai_1.expect(ethPub.equals(ethPrv.publicKey)).to.be.equal(true);
    });
    it("tests ecdh", function () {
        var one = Buffer.from(new Uint8Array(32));
        one[31] = 1;
        var two = Buffer.from(new Uint8Array(32));
        two[31] = 2;
        var k1 = new keys_1.PrivateKey(one);
        var k2 = new keys_1.PrivateKey(two);
        chai_1.expect(k1.ecdh(k2.publicKey).equals(k2.ecdh(k1.publicKey))).to.be.equal(true);
    });
});
//# sourceMappingURL=crypt.test.js.map