import MD5 from "md5";
import { sm2, sm4 } from "sm-crypto-v2";

/**
 * 国密混合加密处理器（SM2+SM4）
 * 功能：
 * 1. 使用SM4加密业务数据
 * 2. 使用SM2加密SM4密钥
 * 3. 提供数字签名验证功能
 */
class MixEncryption {
  constructor({
    cipherMode = 1,
    privateKey1 = "",
    publicKey1 = "",
    publicKey2 = "",
    openEncrypt = true,
  } = {}) {
    this.cipherMode = cipherMode;
    this.privateKey1 = privateKey1;
    this.publicKey1 = publicKey1;
    this.publicKey2 = publicKey2;
    this.openEncrypt = openEncrypt;
  }

  resetKeyPair() {
    this.publicKey1 = "";
    this.privateKey1 = "";
    this.publicKey2 = "";
  }

  /**
   * 混合加密方法，使用 SM4 加密请求数据，使用 SM2 加密 SM4 密钥
   * @param {Object} requestData - 需要加密的请求数据，类型为键值对对象
   * @returns {Object} 包含加密后的请求数据和加密后的 SM4 密钥的对象
   * @throws 若公钥未初始化，抛出 "Public key not initialized" 错误
   * @throws 若请求数据不是对象，抛出 "requestData must be an Object" 错误
   */
  mixCryptoEnCrypto(requestData) {
    if (!this.publicKey1) {
      throw new Error("Public key not initialized");
    }
    if (typeof requestData !== "object" || requestData === null) {
      throw new Error("requestData must be an Object");
    }
    // 使用sm4加密请求，使用sm2加密sm4秘钥，返回密文请求和加密秘钥
    const encryptKey = this.generateSM4key(); // 秘钥
    const encryptedData = this.sm4EnCrypto(requestData, encryptKey);
    const secretSM4Key = this.sm2EnCrypto(encryptKey);
    return {
      encryptedData,
      encryptKey: secretSM4Key,
    };
  }

  /**
   * 混合解密方法，使用 SM2 解密 SM4 密钥，再使用解密后的 SM4 密钥解密密文响应数据
   * @param {string} responseData - 需要解密的响应数据，类型为字符串
   * @param {string} secretSM4Key - 加密后的 SM4 密钥，类型为字符串
   * @returns {Object|string} 解密后的明文响应数据
   * @throws 若私钥未初始化，调用 sm2DeCrypto 方法时会抛出 "Private key not initialized" 错误
   */
  mixCryptoDeCrypto(responseData, secretSM4Key) {
    // 使用sm2解密sm4秘钥，使用sm4秘钥解密密文，返回明文请求
    const decryptKey = this.sm2DeCrypto(secretSM4Key);

    const result = this.sm4DeCrypto(responseData, decryptKey);

    const { signValueHex, data } = result;

    const verifySignFlag = this.doVerifySign(
      MD5(JSON.stringify(data)),
      signValueHex
    );
    if (verifySignFlag) {
      return data;
    } else {
      throw new Error("signValueHex not match");
    }
  }

  // 生成公钥和私钥
  generateSM2Key() {
    if (this.openEncrypt) {
      const { privateKey, publicKey } = sm2.generateKeyPairHex(); // 在请求成功之后再存储，防止重复登录导致重复加密

      this.privateKey1 = privateKey;
      this.publicKey1 = publicKey;

      return {
        publicKey,
        privateKey,
      };
    }
    return {};
  }

  doVerifySign(msg, signValueHex) {
    const res = sm2.doVerifySignature(msg, signValueHex, this.publicKey2, {
      hash: true,
    });
    return res;
  }

  // 请求签名 防篡改
  doSign(request) {
    const str = JSON.stringify(request);
    const msg = MD5(str);

    const signValueHex = sm2.doSignature(msg, this.privateKey1, {
      hash: true,
    });

    return signValueHex;
  }

  randomStr(length) {
    const crypto = this.getCrypto();
    const buffer = new Uint8Array(length);
    crypto.getRandomValues(buffer);
    return Array.from(buffer, (byte) =>
      byte.toString(16).padStart(2, "0")
    ).join("");
  }

  // 使用sm2加密sm4key
  sm2EnCrypto(key) {
    const secretKey = sm2.doEncrypt(key, this.publicKey2, this.cipherMode);
    return secretKey;
  }

  // sm2解密key
  sm2DeCrypto(secretKey) {
    if (!this.privateKey1) {
      throw new Error("Private key not initialized");
    }
    const key = sm2.doDecrypt(secretKey, this.privateKey1, this.cipherMode);
    return key;
  }

  // sm4加密请求
  sm4EnCrypto(request, encryptKey) {
    const signValueHex = this.doSign(request);
    const _req = {
      data: request,
      signValueHex,
    };
    const requestData = sm4.encrypt(JSON.stringify(_req), encryptKey);
    return requestData;
  }

  generateSM4key() {
    const res = this.randomStr(16);
    return res;
  }

  // sm4解密响应
  sm4DeCrypto(responseString, deCryptoKey) {
    if (responseString) {
      const str = sm4.decrypt(responseString, deCryptoKey);
      return JSON.parse(str);
    }
    return "";
  }

  getCrypto() {
    if (typeof crypto !== "undefined") return crypto;
    if (typeof window !== "undefined" && window.crypto) return window.crypto;
    return require("crypto");
  }
}

const instance = new MixEncryption({});
const instance2 = new MixEncryption({});

const { publicKey: pb1 } = instance.generateSM2Key();
const { publicKey: pb2 } = instance2.generateSM2Key();
instance2.publicKey2 = pb1;
instance.publicKey2 = pb2;

const enData = instance.mixCryptoEnCrypto({ data: 1, msg: 2 });

try {
  const res = instance2.mixCryptoDeCrypto(
    enData.encryptedData,
    enData.encryptKey
  );
  console.error("log by Ricardo M Lee rocket", res);
} catch (e) {}
