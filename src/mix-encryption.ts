import { sm2, sm4 } from "sm-crypto-v2";
import MD5 from "md5";

// 加密配置选项接口
export interface EncryptionOption {
  cipherMode?: number;
  privateKey1?: string;
  publicKey1?: string;
  publicKey2?: string;
  openEncrypt?: boolean;
}

// 混合加密结果接口
interface MixEncryptResult {
  encryptedData: string;
  encryptKey: string;
}

// 签名验证结果接口
interface VerifyResult {
  signValueHex: string;
  data: Record<string, any>;
}

/**
 * 国密混合加密处理器（SM2+SM4）
 * 功能：
 * 1. 使用SM4加密业务数据
 * 2. 使用SM2加密SM4密钥
 * 3. 提供数字签名验证功能
 */
class MixEncryption {
  // 定义类的属性及其类型
  private cipherMode: number;
  private privateKey1: string;
  private publicKey1: string;
  private publicKey2: string;
  private openEncrypt: boolean;

  constructor({
    cipherMode = 1,
    privateKey1 = "",
    publicKey1 = "",
    publicKey2 = "",
    openEncrypt = true,
  }: EncryptionOption = {}) {
    this.cipherMode = cipherMode;
    this.privateKey1 = privateKey1;
    this.publicKey1 = publicKey1;
    this.publicKey2 = publicKey2;
    this.openEncrypt = openEncrypt;
  }

  get publicKey() {
    return this.publicKey1;
  }

  resetKeyPair() {
    this.publicKey1 = "";
    this.privateKey1 = "";
    this.publicKey2 = "";
  }

  /**
   * 混合加密方法，使用 SM4 加密请求数据，使用 SM2 加密 SM4 密钥
   * @param requestData - 需要加密的请求数据，类型为键值对对象
   * @returns 包含加密后的请求数据和加密后的 SM4 密钥的对象
   * @throws 若公钥未初始化，抛出 "Public key not initialized" 错误
   * @throws 若请求数据不是对象，抛出 "requestData must be an Object" 错误
   */
  mixCryptoEnCrypto(requestData: Record<string, any>): MixEncryptResult {
    if (!this.publicKey1) {
      throw new Error("Public key not initialized");
    }
    if (typeof requestData !== "object" || requestData === null) {
      throw new Error("requestData must be an Object");
    }

    const encryptKey = this.generateSM4key();
    const encryptedData = this.sm4EnCrypto(requestData, encryptKey);
    const secretSM4Key = this.sm2EnCrypto(encryptKey);

    return {
      encryptedData,
      encryptKey: secretSM4Key,
    };
  }

  /**
   * 混合解密方法，使用 SM2 解密 SM4 密钥，再使用解密后的 SM4 密钥解密密文响应数据
   * @param responseData - 需要解密的响应数据，类型为字符串
   * @param secretSM4Key - 加密后的 SM4 密钥，类型为字符串
   * @param needVerifySign - 是否需要验证签名，类型为布尔值，默认值为 true，首次和服务端通信时，还未拿到服务端公钥，不能验签
   * @returns 解密后的明文响应数据
   * @throws 若私钥未初始化，调用 sm2DeCrypto 方法时会抛出 "Private key not initialized" 错误
   */
  mixCryptoDeCrypto(
    responseData: string,
    secretSM4Key: string,
    needVerifySign: boolean = true
  ): Record<string, any> | string {
    const decryptKey = this.sm2DeCrypto(secretSM4Key);
    const result = this.sm4DeCrypto(responseData, decryptKey);
    const { signValueHex, data } = result;

    const verifySignFlag = needVerifySign
      ? this.doVerifySign(MD5(JSON.stringify(data)), signValueHex)
      : true;

    if (verifySignFlag) {
      return data;
    } else {
      throw new Error("signValueHex not match");
    }
  }

  // 生成公钥和私钥
  generateSM2Key(): { publicKey: string; privateKey: string } | {} {
    if (this.openEncrypt) {
      const { privateKey, publicKey } = sm2.generateKeyPairHex();
      this.privateKey1 = privateKey;
      this.publicKey1 = publicKey;
      return {
        publicKey,
        privateKey,
      };
    }
    return {};
  }

  doVerifySign(msg: string, signValueHex: string): boolean {
    const res = sm2.doVerifySignature(msg, signValueHex, this.publicKey2, {
      hash: true,
    });
    return res;
  }

  // 请求签名 防篡改
  doSign(request: Record<string, any>): string {
    const str = JSON.stringify(request);
    const msg = MD5(str);

    const signValueHex = sm2.doSignature(msg, this.privateKey1, {
      hash: true,
    });

    return signValueHex;
  }

  /**
   * 接收配对公钥
   * @param key 服务端公钥
   */
  acceptPartnerKey(key: string) {
    if (!key) {
      throw new Error("partner public key must be a string");
    }

    this.publicKey2 = key;
  }

  randomStr(length: number): string {
    const crypto = this.getCrypto();
    const buffer = new Uint8Array(length);
    crypto.getRandomValues(buffer);
    return Array.from(buffer, (byte) =>
      byte.toString(16).padStart(2, "0")
    ).join("");
  }

  // 使用sm2加密sm4key
  sm2EnCrypto(key: string): string {
    const secretKey = sm2.doEncrypt(key, this.publicKey2, this.cipherMode);
    return secretKey;
  }

  // sm2解密key
  sm2DeCrypto(secretKey: string): string {
    if (!this.privateKey1) {
      throw new Error("Private key not initialized");
    }
    const key = sm2.doDecrypt(secretKey, this.privateKey1, this.cipherMode, {
      output: "string",
    });

    return key;
  }

  // sm4加密请求
  sm4EnCrypto(request: Record<string, any>, encryptKey: string): string {
    const signValueHex = this.doSign(request);
    const _req = {
      data: request,
      signValueHex,
    };

    const requestData = sm4.encrypt(JSON.stringify(_req), encryptKey, {
      output: "string",
    });

    return requestData;
  }

  generateSM4key(): string {
    const res = this.randomStr(16);
    return res;
  }

  // sm4解密响应
  sm4DeCrypto(responseString: string, deCryptoKey: string): VerifyResult {
    if (responseString) {
      const str = sm4.decrypt(responseString, deCryptoKey, {
        output: "string",
      });
      return JSON.parse(str);
    }

    return {} as VerifyResult;
  }

  getCrypto(): Crypto | { getRandomValues: (array: Uint8Array) => Uint8Array } {
    if (typeof crypto !== "undefined") return crypto;
    if (typeof window !== "undefined" && window.crypto) return window.crypto;
    return require("crypto").webcrypto;
  }
}

let instance: MixEncryption | undefined;

export function getCryptoInstance(
  options: EncryptionOption = {}
): MixEncryption {
  if (!instance) {
    instance = new MixEncryption(options);
  }
  return instance;
}
