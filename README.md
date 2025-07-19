# SM 混合加密工具包

基于国密算法 SM2 和 SM4 实现的混合加密解决方案。

## 安装

```bash
pnpm install mix-encryption
```

## 使用示例

```typescript
// 客户端 与 服务端操作相同
import getCryptoInstance from "mix-encryption";

// 支持传入本地缓存的密钥对 可选参数
const client = getCryptoInstance({
  cipherMode: 1,
  selfPriKey: "your_private_key",
  selfPubKey: "your_public_key",
  partnerKey: "partner_public_key",
});

// client 首次使用 初始化密钥对
const { publicKey } = client.generateSM2Key();

// client 将公钥发给服务端配对使用
sendToServer({ publicKey });

// server 生成自己的密钥对，并存储客户端公钥
const server = getCryptoInstance();
server.acceptPartnerKey(publicKey);

// server 服务端使用密钥加密返回体
const { encryptedData, encryptKey } = server.mixCryptoEnCrypto({
  data: "data",
  publicKey: server.publicKey,
});

// server 将公钥返回给客户端
sendToClient({ encryptedData, encryptKey });

// client 从服务端获取服务端公钥配对，第一次解密不用验签
const decryptedData = client.mixCryptoDeCrypto(
  encryptedData,
  encryptKey,
  false
);

// client 完成配对
client.acceptPartnerKey(decryptedData.publicKey);

// 重置密钥对
// 将新的密钥通过某次请求发送给后端，通过中间件处理
// 或者新增接口专门处理
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
```
