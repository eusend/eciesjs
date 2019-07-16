"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
var crypto_browserify_1 = require("crypto-browserify");
// import * as crypto from "crypto-browserify"
var secp256k1_1 = __importDefault(require("secp256k1"));
function sha256(msg) {
    var hash = crypto_browserify_1.createHash("sha256");
    hash.update(msg);
    return hash.digest();
}
exports.sha256 = sha256;
function remove0x(hex) {
    if (hex.startsWith("0x") || hex.startsWith("0X")) {
        return hex.slice(2);
    }
    return hex;
}
exports.remove0x = remove0x;
function decodeHex(hex) {
    return Buffer.from(remove0x(hex), "hex");
}
exports.decodeHex = decodeHex;
function getValidSecret() {
    var key;
    do {
        key = crypto_browserify_1.randomBytes(32);
    } while (!secp256k1_1.default.privateKeyVerify(key));
    return key;
}
exports.getValidSecret = getValidSecret;
function aesEncrypt(key, plainText) {
    var nonce = crypto_browserify_1.randomBytes(16);
    var cipher = crypto_browserify_1.createCipheriv("aes-256-gcm", key, nonce);
    var encrypted = Buffer.concat([cipher.update(plainText), cipher.final()]);
    var tag = cipher.getAuthTag();
    return Buffer.concat([nonce, tag, encrypted]);
}
exports.aesEncrypt = aesEncrypt;
function aesDecrypt(key, cipherText) {
    var nonce = cipherText.slice(0, 16);
    var tag = cipherText.slice(16, 32);
    var ciphered = cipherText.slice(32);
    var decipher = crypto_browserify_1.createDecipheriv("aes-256-gcm", key, nonce);
    decipher.setAuthTag(tag);
    return Buffer.concat([decipher.update(ciphered), decipher.final()]);
}
exports.aesDecrypt = aesDecrypt;
//# sourceMappingURL=utils.js.map