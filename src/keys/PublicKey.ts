import secp256k1 from "secp256k1";

import { decodeHex } from "../utils";

export default class PublicKey {

    public static fromHex(hex: string): PublicKey {
        const decoded = decodeHex(hex);
        if (decoded.length === 64) {
            // eth public key
            const prefix: Buffer = Buffer.from([0x04]);
            const fixed: Buffer = Buffer.concat([prefix, decoded]);
            return new PublicKey(fixed);
        }
        return new PublicKey(decoded);
    }

    public readonly uncompressed: Buffer;
    public readonly compressed: Buffer;

    constructor(buffer: Buffer) {
        this.uncompressed = secp256k1.publicKeyConvert(buffer, false);
        this.compressed = secp256k1.publicKeyConvert(buffer, true);
    }

    public toHex(compressed: boolean = true): string {
        if (compressed) {
            return this.compressed.toString("hex");
        } else {
            return this.uncompressed.toString("hex");
        }
    }

    public equals(other: PublicKey): boolean {
        return this.uncompressed.equals(other.uncompressed);
    }

}
