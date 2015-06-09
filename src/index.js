function readUnsignedInt(arr, offset) {
    return (arr[offset + 3] << 24) | (arr[offset + 2] << 16) |
        (arr[offset + 1] << 8) | arr[offset];
}

module.exports = function (buff, cb) {
    var view = new Uint8Array(buff);

    if (readUnsignedInt(view, 0) !== 0x34327243 /* Cr24 */) {
        return cb(new Error('Unexpected CRX magic number')), undefined;
    }

    if (readUnsignedInt(view, 4) !== 2) {
        return cb(new Error('Unexpected CRX version')), undefined;
    }

    var publicKeyLength = readUnsignedInt(view, 8);
    var signatureLength = readUnsignedInt(view, 12);
    var metaOffset = 16;
    var publicKey = new Buffer(view.slice(metaOffset,
        metaOffset + publicKeyLength)).toString('base64');
    var signature = new Buffer(view.slice(metaOffset + publicKeyLength,
        metaOffset + publicKeyLength + signatureLength)).toString('base64');

    cb(null, {
        header: {
            publicKey: publicKey,
            signature: signature
        },
        body: buff.slice(metaOffset + publicKeyLength + signatureLength)
    });
};
