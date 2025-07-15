import { CipherMode, sm2, sm4 } from "sm-crypto";
import * as MD5 from "md5";

export interface EncryptionOption {
  cipherMode?: CipherMode;
  privateKey1?: string;
  publicKey1?: string;
  publicKey2?: string;
  openEncrypt?: boolean;
}

/**
 * 国密混合加密处理器（SM2+SM4）
 * 功能：
 * 1. 使用SM4加密业务数据
 * 2. 使用SM2加密SM4密钥
 * 3. 提供数字签名验证功能
 */
class MixEncryption {
  public cipherMode: CipherMode = 1;
  public privateKey1 = "";
  public publicKey1 = "";
  public publicKey2 = "";
  public openEncrypt = false;

  constructor({
    cipherMode = 1,
    privateKey1 = "",
    publicKey1 = "",
    publicKey2 = "",
    openEncrypt = false,
  }: EncryptionOption) {
    this.cipherMode = cipherMode;
    this.privateKey1 = privateKey1;
    this.publicKey1 = publicKey1;
    this.publicKey2 = publicKey2;
    this.openEncrypt = openEncrypt;
  }

  public resetKeyPair() {
    this.publicKey1 = "";
    this.privateKey1 = "";
    this.publicKey2 = "";
  }

  public mixCryptoEnCrypto(requestData: Record<string, any>) {
    if (!this.publicKey1) {
      throw new Error("Public key not initialized");
    }
    if (!requestData) {
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

  public mixCryptoDeCrypto(responseData: string, secretSM4Key: string) {
    // 使用sm2解密sm4秘钥，使用sm4秘钥解密密文，返回明文请求
    const decryptKey = this.sm2DeCrypto(secretSM4Key);
    const result = this.sm4DeCrypto(responseData, decryptKey);
    return result;
  }

  // 生成客户端公钥和私钥
  public generateSM2Key() {
    if (this.openEncrypt) {
      const { privateKey, publicKey } = sm2.generateKeyPairHex(); // 在请求成功之后再存储，防止重复登录导致重复加密

      return {
        publicKey,
        privateKey,
      };
    } else {
      return {};
    }
  }
  private generateSM4key() {
    const res = this.randomStr(32);
    return res;
  }

  public doVerifySign(msg: string | number[], signValueHex: string) {
    const res = sm2.doVerifySignature(msg, signValueHex, this.publicKey2, {
      hash: true,
    });
    return res;
  }

  // 请求签名 防篡改
  public doSign(request: Record<string, any>) {
    const str = JSON.stringify(request);
    const msg = MD5(str);

    const signValueHex = sm2.doSignature(msg, this.privateKey1, {
      hash: true,
      publicKey: this.publicKey2,
    });

    return signValueHex;
  }

  // 使用sm2加密key
  private sm2EnCrypto(key: string) {
    const secretKey = sm2.doEncrypt(key, this.publicKey1, this.cipherMode);
    return secretKey;
  }

  // sm2解密key
  private sm2DeCrypto(secretKey: string) {
    if (!this.privateKey1) {
      throw new Error("Private key not initialized");
    }
    const key = sm2.doDecrypt(secretKey, this.privateKey1, this.cipherMode);
    return key;
  }

  // sm4加密请求
  private sm4EnCrypto(request: any, encryptKey: string) {
    const signValueHex = this.doSign(request);
    const _req = {
      ...request,
      signValueHex,
    };
    const requestData = sm4.encrypt(JSON.stringify(_req), encryptKey);
    return requestData;
  }

  // sm4解密响应
  private sm4DeCrypto(responseString: string, deCryptoKey: string) {
    if (responseString) {
      const str = sm4.decrypt(responseString, deCryptoKey);
      return JSON.parse(str);
    } else {
      return "";
    }
  }

  private getCrypto() {
    if (typeof crypto !== "undefined") return crypto;
    if (typeof window !== "undefined" && window.crypto) return window.crypto;
    return require("crypto");
  }

  public randomStr(length: number): string {
    const crypto = this.getCrypto();
    const buffer = new Uint8Array(length);
    crypto.getRandomValues(buffer);
    return Array.from(buffer, (byte) =>
      byte.toString(16).padStart(2, "0")
    ).join("");
  }
}

let instance: MixEncryption;

export function getCryptoInstance(options: EncryptionOption): MixEncryption {
  if (!instance) {
    instance = new MixEncryption(options);
  }
  return instance;
}
