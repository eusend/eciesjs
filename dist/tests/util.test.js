"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
var secp256k1_1 = __importDefault(require("secp256k1"));
var chai_1 = require("chai");
var utils_1 = require("../utils");
describe("test string <-> buffer utils ", function () {
    it("tests sha256", function () {
        var digest = utils_1.sha256(Buffer.from(new Uint8Array(16))).toString("hex");
        var allZeroDigest = "374708fff7719dd5979ec875d56cd2286f6d3cf7ec317a3b25632aab28ec37bb";
        chai_1.expect(digest).to.equal(allZeroDigest);
    });
    it("should remove 0x", function () {
        chai_1.expect(utils_1.remove0x("0x0011")).to.equal("0011");
        chai_1.expect(utils_1.remove0x("0011")).to.equal("0011");
        chai_1.expect(utils_1.remove0x("0X0022")).to.equal("0022");
        chai_1.expect(utils_1.remove0x("0022")).to.equal("0022");
    });
    it("should generate valid secret", function () {
        var key = utils_1.getValidSecret();
        chai_1.expect(secp256k1_1.default.privateKeyVerify(key)).to.equal(true);
    });
    it("should convert hex to buffer", function () {
        var decoded = utils_1.decodeHex("0x0011");
        chai_1.expect(decoded.equals(Buffer.from([0, 0x11]))).to.equal(true);
    });
});
//# sourceMappingURL=util.test.js.map