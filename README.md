# SM 混合加密工具包

基于国密算法 SM2 和 SM4 实现的混合加密解决方案。

## 安装

```bash
npm install mix-encryption
```

## 使用示例

```typescript
// 客户端 与 服务端操作相同
import { getCryptoInstance } from "mix-encryption";

// 支持传入本地缓存的密钥对 可选参数
const instance = getCryptoInstance({
  cipherMode: 1,
  privateKey1: "your_private_key",
  publicKey1: "your_public_key",
  publicKey2: "partner_public_key",
});

// 首次使用 初始化密钥对  将公钥发给服务端配对使用
const { publicKey } = instance.generateSM2Key();

// 从服务端获取服务端公钥配对
instance.publicKey2("server_publicKey");

// 加密
const { encryptedData, encryptKey } = instance.mixCryptoEnCrypto({
  data: "data",
});

// 解密
const decryptedData = instance.mixCryptoDeCrypto(encryptedData, encryptKey);
```
