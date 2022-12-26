const zcrypto = require('./zcrypto');

(async () => {
    await zcrypto.ready;

    let args = process.argv;
    args.shift();
    args.shift();

    let command = args.shift();
    if (command === 'generate') {
        let file = args.length !== 0 ? args[0] : 'key';
        let keys = await zcrypto.generate(file + '.private');
        console.log(`Private key saved in file : ${file}`);
        console.log('Public key (base58) :');
        console.log(keys.publicKey.toString('base58'));

    } else if (command === 'derive') {
        let file = args.length !== 0 ? args[0] : 'key';
        let keys = await zcrypto.read(file + '.private');
        console.log('Public key (base58) :');
        console.log(keys.publicKey.toString('base58'));

    } else if (command === 'sign') {
        let file = args.shift();
        let message;
        if (args.length === 0) {
            message = file;
            file = 'key';
        } else {
            message = args.shift();
        }
        let keys = await zcrypto.read(file + '.private', false);
        let signature = zcrypto.sign(message, keys.privateKey);
        console.log(signature.toString('base58'));

    } else if (command === 'verify') {
        let publicKey = args.shift();
        let signature = args.shift();
        let message = args.shift();
        let check = zcrypto.verify(signature.toUint8Array(), message, publicKey.toUint8Array());
        console.log(check);

    } else if (command === 'compute') {
        let remotePublicKey = args.shift();
        let privateKeyFile = 'key.private';
        if (args.length !== 0) {
            privateKeyFile = args.shift();
        }
        let key = await zcrypto.read(privateKeyFile + '.private');
        let sharedKey = zcrypto.computeSharedKey(remotePublicKey.toUint8Array(), key.privateKey);
        console.log(sharedKey.toString('base58'));

    } else if (command === 'help') {
        console.log('generate <file.private>');
        console.log('\tGenerate Ed25519 key pair.\n');
        console.log('derive <file.private>');
        console.log('\tDerive public key from private key.\n');
        console.log('sign <file.private> <message>');
        console.log('\tSign a message.\n')
        console.log('verify <public key> <signature> <message>');
        console.log('\tVerify a message signature.\n');
        console.log('compute <file.private> <public key>');
        console.log('\tCompute shared key with Diffie-Hellman.\n');

    } else {
        console.log(`Error : Unknown command : '${command}'.`);
    }
})();
