const ByteStream = require("../../../DataStream/ByteStream");

module.exports = class {
    constructor(sessionToken = null, snonce = null) {
        this.ByteStream = new ByteStream();
        this.sessionToken = sessionToken;
        this.snonce = snonce;
    }
    
    encode() {
        // ScDocumentation 프로토콜에 따라 Session Token과 snonce를 먼저 추가
        if (this.sessionToken && this.sessionToken.length === 24) {
            for (let i = 0; i < 24; i++) {
                this.ByteStream.write(this.sessionToken[i]);
            }
        }
        if (this.snonce && this.snonce.length === 24) {
            for (let i = 0; i < 24; i++) {
                this.ByteStream.write(this.snonce[i]);
            }
        }

        // 기존 LoginMessage 필드들
        this.ByteStream.writeInt(settings.hi || 0); // high
        this.ByteStream.writeInt(settings.lo || 0); // low
        this.ByteStream.writeString(settings.token || ""); // token

        this.ByteStream.writeInt(settings.major);
        this.ByteStream.writeInt(settings.build);
        this.ByteStream.writeInt(settings.minor);
        this.ByteStream.writeString(settings.hash);

        this.ByteStream.writeString();
        this.ByteStream.writeDataReference(1, 0);
        this.ByteStream.writeString("en-US");
        this.ByteStream.writeString();
        this.ByteStream.writeBoolean(false);
        this.ByteStream.writeString();
        this.ByteStream.writeString();
        this.ByteStream.writeBoolean(true);
        this.ByteStream.writeString();
        this.ByteStream.writeInt(1448);
        this.ByteStream.writeVInt(0);
        this.ByteStream.writeString();

        this.ByteStream.writeString();
        this.ByteStream.writeString();
        this.ByteStream.writeVInt(0);

        this.ByteStream.writeString();
        this.ByteStream.writeString();
        this.ByteStream.writeString();

        this.ByteStream.writeString(); // Supercell ID Session Token, must be compressed with zlib

        this.ByteStream.writeBoolean(false);
        this.ByteStream.writeString();
        this.ByteStream.writeString();
    }
}