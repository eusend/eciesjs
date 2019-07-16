"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
var keys_1 = require("./keys");
var utils_1 = require("./utils");
function encrypt(receiverPubhex, msg) {
    var disposableKey = new keys_1.PrivateKey();
    var receiverPubkey = keys_1.PublicKey.fromHex(receiverPubhex);
    var aesKey = disposableKey.ecdh(receiverPubkey);
    var encrypted = utils_1.aesEncrypt(aesKey, msg);
    return Buffer.concat([disposableKey.publicKey.uncompressed, encrypted]);
}
exports.encrypt = encrypt;
function decrypt(receiverPrvhex, msg) {
    var receiverPrvkey = keys_1.PrivateKey.fromHex(receiverPrvhex);
    var senderPubkey = new keys_1.PublicKey(msg.slice(0, 65));
    var encrypted = msg.slice(65);
    var aesKey = receiverPrvkey.ecdh(senderPubkey);
    return utils_1.aesDecrypt(aesKey, encrypted);
}
exports.decrypt = decrypt;
var keys_2 = require("./keys");
exports.PrivateKey = keys_2.PrivateKey;
exports.PublicKey = keys_2.PublicKey;
exports.utils = {
    aesDecrypt: utils_1.aesDecrypt, aesEncrypt: utils_1.aesEncrypt, decodeHex: utils_1.decodeHex, getValidSecret: utils_1.getValidSecret, remove0x: utils_1.remove0x, sha256: utils_1.sha256,
};
//# sourceMappingURL=index.js.map