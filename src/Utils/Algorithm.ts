import { AES, enc } from "crypto-js";
import { BOOKLIFE, BOOKLIFEAUTH } from "./Seeds";

/**
 * 북앤라이프 로그인시 사용되는 암호화 알고리즘
 * @param string 암호화할 문자열
 * @returns AES-256 암호화된 문자열
 */
export function EncryptLoginInfo(string: string): string {
  const key = enc.Hex.parse(BOOKLIFEAUTH.keyHash);
  const iv = enc.Hex.parse(BOOKLIFEAUTH.ivHash);

  return AES.encrypt(string, key, { iv }).toString();
}

/**
 * 북앤라이프 암호화 알고리즘
 * @param string 암호화할 문자열
 * @returns AES-256 암호화된 문자열
 */
export function EncryptAES(string: string): string {
  const key = enc.Hex.parse(BOOKLIFE.keyHash);
  const iv = enc.Hex.parse(BOOKLIFE.ivHash);

  return AES.encrypt(string, key, { iv }).toString();
}

/**
 * 북앤라이프 복호화 알고리즘
 * @param string
 * @returns plain text
 */
export function DeEncryptAES(string: string): string {
  const key = enc.Hex.parse(BOOKLIFE.keyHash);
  const iv = enc.Hex.parse(BOOKLIFE.ivHash);

  return AES.decrypt(string, key, { iv }).toString(enc.Utf8);
}
