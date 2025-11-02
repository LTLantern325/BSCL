const Nacl = require("./Nacl"),
Nonce = require("./Nonce"),
crypto = require("crypto");

module.exports = class {
    constructor() {
        this.server_public_key = fromHexString("076802FC015600FD802FC036601FB00F046802FC012C00DF8057003FE00DC007");
        this.client_secret_key = new Uint8Array(crypto.randomBytes(32));
        this.client_public_key = new Uint8Array(32);
        Nacl.lowlevel.crypto_scalarmult_base(this.client_public_key, this.client_secret_key);
        this.key = Nacl.box.before(this.server_public_key, this.client_secret_key);
        this.nonce = new Nonce({
            Keys: [
                this.client_public_key,
                this.server_public_key
            ]
        });
        this.client_nonce = new Nonce();
        this.session_key = null;
        this.snonce = null;
    }
    
    // snonce 생성 메서드 추가
    generateSnonce() {
        this.snonce = new Uint8Array(crypto.randomBytes(24));
        return this.snonce;
    }
    
    encrypt(type, payload) {
        if (type == 10100) {
            return payload;
        } else if (type == 10101) {
            // ScDocumentation 프로토콜에 따른 수정:
            // 1. payload는 이미 Session Token + snonce + LoginMessage 내용을 포함
            // 2. payload만 암호화
            // 3. client_public_key를 앞에 붙임
            let encrypted = Nacl.box.after(payload, this.nonce.bytes(), this.key);
            return Buffer.concat([this.client_public_key, encrypted]);
        } else {
            this.client_nonce.increment();
            return Buffer.from(Nacl.box.after(payload, this.client_nonce.bytes(), this.key));
        }
    }
    
    decrypt(type, payload) {
        if (type == 20100) {
            this.session_key = payload.slice(4, 28);
            return payload;
        } else if ([20104, 20103].includes(type)) {
            if (!this.session_key) return payload;
            let nonce = new Nonce({
                nonce: this.client_nonce.bytes(),
                Keys: [
                    this.client_public_key,
                    this.server_public_key
                ]
            });
            let decrypted = Nacl.box.open.after(payload, nonce.bytes(), this.key);
            this.server_nonce = new Nonce({
                nonce: decrypted.slice(0, 24)
            });
            this.key = decrypted.slice(24, 56);
            return decrypted.slice(56);
        } else {
            this.server_nonce.increment();
            return Nacl.box.open.after(payload, this.server_nonce.bytes(), this.key);
        }
    }
}

function fromHexString (hexString) {
    hexString = hexString.replaceAll(" ", "")
    return new Uint8Array(hexString.match(/.{1,2}/g).map((byte) => parseInt(byte, 16)))
}