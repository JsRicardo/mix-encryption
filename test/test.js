import { MixEncryption } from "../dist/index.esm.js";

const server = MixEncryption();
const client = MixEncryption();

console.log(server.randomStr(32));

const clientKeyPair = client.generateSM2Key();
const serverKeyPair = server.generateSM2Key();

server.acceptPartnerKey(clientKeyPair.publicKey);
client.acceptPartnerKey(serverKeyPair.publicKey);

function send(encryptedData) {
  const res = server.mixCryptoDeCrypto(
    encryptedData.encryptedData,
    encryptedData.encryptKey
  );
  const { publicKey } = server.generateSM2Key();
  server.acceptPartnerKey(res.key);
  return publicKey;
}

await client.renewKeyPair(send);

const clientRequest = {
  name: "JsRicardo",
  age: 18,
};

const encryptedData = client.mixCryptoEnCrypto(clientRequest);

const serverDecryptedData = server.mixCryptoDeCrypto(
  encryptedData.encryptedData,
  encryptedData.encryptKey
);

console.log("Server Decrypted Data:", serverDecryptedData);
