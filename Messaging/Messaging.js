const LogicLaserMessageFactory = require("./LogicLaserMessageFactory");
const ClientHelloMessage = require("./Messages/Client/ClientHelloMessage");
const LoginMessage = require("./Messages/Client/LoginMessage");
const PepperCrypto = require("../Crypto/PepperCrypto");
let messages = {}

let fs;
if (dump) {
    fs = require("fs");
    if (!fs.existsSync("./PacketsDumps")) {
        fs.mkdirSync("./PacketsDumps");
    }
}


class Messaging {
    constructor(socket, queue) {
        this._queue = queue;
        this._socket = socket;
        this.crypto = new PepperCrypto();
    }
    pendingJob() {
        if (this._queue.size() < 7) return false;
        return this._queue.get().readUIntBE(2, 3) <= this._queue.size() - 7;
    }
    update() {
        const buffer = this._queue.get();
        const length = buffer.readUIntBE(2, 3);
        const type = buffer.readUInt16BE(0);
        const version = buffer.readUInt16BE(5);
        this._queue.release(length + 7);
        const payload = this.crypto.decrypt(type, buffer.slice(7, length + 7));
        if (payload == null) {
            return Debugger.fatal("failed to decrypt {}".format(type))
        }
        Debugger.info("received message of type: {}, length: {}, version: {}".format(type, length, version));
        const message = LogicLaserMessageFactory.createMessageByType(type);
        if (message) {
            message.ByteStream.set(payload);
            message.decode();
            message.process(this);
        } else {
            Debugger.info("ignoring unsupported message ({})".format(type));
        }
        if (dump) {
            if (!messages[type]) messages[type] = 0;
            fs.writeFileSync("./PacketsDumps/{}-{}.bin".format(type, messages[type]), payload);
            messages[type] += 1;
        }
    }
    sendPepperAuthentication() {
        const message = new ClientHelloMessage();
        message.ByteStream.set(100);
        message.encode();
        this.encryptAndWriteToSocket(10100, 0, message.ByteStream.getBytes());
    }
    sendPepperLogin() {
        // ScDocumentation 프로토콜에 따라 snonce 생성
        const snonce = this.crypto.generateSnonce();
        
        // LoginMessage에 session_key와 snonce 전달
        const message = new LoginMessage(this.crypto.session_key, snonce);
        message.ByteStream.set(250);
        message.encode();
        this.encryptAndWriteToSocket(10101, 0, message.ByteStream.getBytes());
    }
    encryptAndWriteToSocket(type, version, buffer) {
        const header = Buffer.alloc(7);
        header.writeUInt16BE(type, 0);
        buffer = this.crypto.encrypt(type, buffer);
        if (!buffer) {
            return Debugger.fatal("Failed to encrypt message {}".format(type));
        }
        header.writeUIntBE(buffer.length, 2, 3);
        header.writeUInt16BE(version, 5);
        this._socket.write(header);
        this._socket.write(buffer);
        Debugger.info("sent message of type: {}, length: {}".format(type, buffer.length));
    }
}

module.exports = Messaging