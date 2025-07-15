# SM 混合加密工具包

基于国密算法 SM2 和 SM4 实现的混合加密解决方案。

## 安装

```bash
npm install mix-encryption
```

## 使用示例

```typescript
import { getCryptoInstance } from "mix-encryption";

const crypto = getCryptoInstance({
  cipherMode: 1,
  privateKey1: "your_private_key",
  publicKey1: "partner_public_key",
});

// 加密
const { encryptedData, encryptKey } = crypto.mixCryptoEnCrypto({
  data: "secret",
});

// 解密
const decrypted = crypto.mixCryptoDeCrypto(encryptedData, encryptKey);
```
