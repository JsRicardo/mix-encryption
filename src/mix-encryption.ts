import { sm2, sm4 } from "sm-crypto-v2";
import MD5 from "md5";

// 加密配置选项接口
export interface EncryptionOption {
  cipherMode?: number;
  selfPriKey?: string;
  selfPubKey?: string;
  partnerKey?: string;
}

// 混合加密结果接口
export interface MixEncryptResult {
  encryptedData: string;
  encryptKey: string;
}

// 签名验证结果接口
export interface VerifyResult {
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
  private selfPriKey: string;
  private selfPubKey: string;
  private partnerKey: string;

  constructor({
    cipherMode = 1,
    selfPriKey = "",
    selfPubKey = "",
    partnerKey = "",
  }: EncryptionOption = {}) {
    this.cipherMode = cipherMode;
    this.selfPriKey = selfPriKey;
    this.selfPubKey = selfPubKey;
    this.partnerKey = partnerKey;
  }

  get publicKey() {
    return this.selfPubKey;
  }

  /**
   * 重置密钥对
   * 清空当前实例的公钥、私钥及合作方公钥
   * 适用于需要重新生成密钥对或清除密钥的场景
   */
  public resetKeyPair() {
    this.selfPubKey = "";
    this.selfPriKey = "";
    this.partnerKey = "";
  }

  /**
   * 混合加密方法，使用 SM4 加密请求数据，使用 SM2 加密 SM4 密钥
   * @param requestData - 需要加密的请求数据，类型为键值对对象
   * @returns 包含加密后的请求数据和加密后的 SM4 密钥的对象
   * @throws 若公钥未初始化，抛出 "Public key not initialized" 错误
   * @throws 若请求数据不是对象，抛出 "requestData must be an Object" 错误
   */
  public mixCryptoEnCrypto(requestData: Record<string, any>): MixEncryptResult {
    if (!this.selfPubKey) {
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
  public mixCryptoDeCrypto(
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

  /**
   * 生成SM2算法密钥对
   * 当开启加密功能时，生成新的SM2公私钥对并更新实例密钥
   * 适用于密钥初始化或密钥轮换场景
   * @returns 包含十六进制格式公钥和私钥的对象（openEncrypt为true时返回），否则返回空对象
   */
  public generateSM2Key(): { publicKey: string; privateKey: string } {
    const { privateKey, publicKey } = sm2.generateKeyPairHex();
    this.selfPriKey = privateKey;
    this.selfPubKey = publicKey;
    return {
      publicKey,
      privateKey,
    };
  }

  /**
   * 接收配对公钥
   * @param key partner公钥
   */
  public acceptPartnerKey(key: string) {
    if (!key) {
      throw new Error("partner public key must be a string");
    }

    this.partnerKey = key;
  }

  /**
   * 更新密钥对
   * @param sendCallBack - 发送新公钥到合作端并获取新公钥的回调函数
   */
  public async renewKeyPair(
    sendCallBack: (data: MixEncryptResult) => Promise<string>
  ) {
    const { privateKey, publicKey } = sm2.generateKeyPairHex();
    const encryptedData = this.mixCryptoEnCrypto({ key: publicKey });
    const newPartnerKey = await sendCallBack(encryptedData);
    this.selfPriKey = privateKey;
    this.selfPubKey = publicKey;
    this.partnerKey = newPartnerKey;
  }

  /**
   * 生成随机HEX字符串
   * @param length - 需要生成的字符串长度（实际输出长度为此参数值）
   */
  public randomStr(length: number): string {
    const crypto = this.getCrypto();
    const byteLength = Math.ceil(length / 2);
    const buffer = new Uint8Array(byteLength);
    crypto.getRandomValues(buffer);

    return Array.from(buffer, (byte) => {
      const hex = byte.toString(16);
      return hex.length === 1 ? "0" + hex : hex;
    })
      .join("")
      .substring(0, length);
  }

  private doVerifySign(msg: string, signValueHex: string): boolean {
    const res = sm2.doVerifySignature(msg, signValueHex, this.partnerKey, {
      hash: true,
    });
    return res;
  }

  // 请求签名 防篡改
  private doSign(request: Record<string, any>): string {
    const str = JSON.stringify(request);
    const msg = MD5(str);

    const signValueHex = sm2.doSignature(msg, this.selfPriKey, {
      hash: true,
    });

    return signValueHex;
  }

  // 使用sm2加密sm4key
  private sm2EnCrypto(key: string): string {
    const secretKey = sm2.doEncrypt(key, this.partnerKey, this.cipherMode);
    return secretKey;
  }

  // sm2解密key
  private sm2DeCrypto(secretKey: string): string {
    if (!this.selfPriKey) {
      throw new Error("Private key not initialized");
    }
    const key = sm2.doDecrypt(secretKey, this.selfPriKey, this.cipherMode, {
      output: "string",
    });

    return key;
  }

  // sm4加密请求
  private sm4EnCrypto(
    request: Record<string, any>,
    encryptKey: string
  ): string {
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

  private generateSM4key(): string {
    const res = this.randomStr(16);
    return res;
  }

  // sm4解密响应
  private sm4DeCrypto(
    responseString: string,
    deCryptoKey: string
  ): VerifyResult {
    if (responseString) {
      const str = sm4.decrypt(responseString, deCryptoKey, {
        output: "string",
      });
      return JSON.parse(str);
    }

    return {} as VerifyResult;
  }

  private getCrypto():
    | Crypto
    | { getRandomValues: (array: Uint8Array) => Uint8Array } {
    if (typeof crypto !== "undefined") return crypto;
    if (typeof window !== "undefined" && window.crypto) return window.crypto;
    return require("crypto").webcrypto;
  }
}

let instance: MixEncryption | undefined;

export default function getCryptoInstance(
  options: EncryptionOption = {}
): MixEncryption {
  if (!instance) {
    instance = new MixEncryption(options);
  }
  return instance;
}
