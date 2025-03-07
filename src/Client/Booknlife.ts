import { DeEncryptAES, EncryptAES, EncryptLoginInfo } from "../Utils/Algorithm";
import axios, { AxiosInstance } from "axios";
import {
  BOOKNLIFE_API_KEY,
  BOOKNLIFE_AUTH_API_KEY,
  CAPTCHA_DATA_SITE_KEY,
} from "../Utils/Seeds";
import { Solver } from "@2captcha/captcha-solver";
import { HttpCookieAgent, HttpsCookieAgent } from "http-cookie-agent/http";
import { CookieJar } from "tough-cookie";
import { CAPTCHA_API_KEY } from "../../config";

class Booknlife {
  private client: AxiosInstance;
  private jar: CookieJar;
  private readyInfo: string = "";
  private accessToken: string = "";
  private _id: string = "";
  private _password: string = "";

  constructor(id: string, password: string) {
    this.jar = new CookieJar();
    this.client = axios.create({
      headers: {
        "User-Agent":
          "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3",
        Connection: "keep-alive",
      },
      httpAgent: new HttpCookieAgent({ cookies: { jar: this.jar } }),
      httpsAgent: new HttpsCookieAgent({ cookies: { jar: this.jar } }),
    });
    this._id = id;
    this._password = password;
  }

  private async AuthApiReady(type?: string | "Bearer") {
    const Request = await this.client.post(
      `https://authapi.booknlife.com/api/Common/Ready`,
      {},
      {
        headers: {
          Authorization: type || "Bearer",
          Host: "authapi.booknlife.com",
          "X-Api-Key": BOOKNLIFE_AUTH_API_KEY,
        },
      }
    );

    const Response = await Request.data;

    if (Response.ResultCd !== "0000") {
      throw new Error(`AuthApiReady Error`);
    }

    // ReadyInfo가 없을 경우 에러 반환
    if (!Response.ResultData.readyInfo) {
      throw new Error(`AuthApiReady Error`);
    }

    this.readyInfo = Response.ResultData.readyInfo;

    return Response;
  }

  private async solveCaptcha(pageURL: string, googleKey: string) {
    const solver = new Solver(CAPTCHA_API_KEY);

    const solve = await solver.recaptcha({
      pageurl: pageURL,
      googlekey: googleKey,
    });

    return solve.data;
  }

  /**
   * 북앤라이프 로그인에 로그인하는 함수입니다. Class가 생성될때 인자로 받은 id와 passwd를 사용해 로그인합니다.
   */
  public async login() {
    const id = EncryptLoginInfo(this._id);
    const passwd = EncryptLoginInfo(this._password);

    const captchaResponse = await this.solveCaptcha(
      "https://www.booknlife.com/auth/login/",
      CAPTCHA_DATA_SITE_KEY
    );

    await this.AuthApiReady(); //login 요청전 ready api 호출

    const Request = await this.client.post(
      `https://authapi.booknlife.com/api/Auth/Login`,
      {
        accessType: "H",
        loginType: "ID",
        id,
        passwd,
        vrfInfo: this.readyInfo,
        vrtInfo: captchaResponse,
      },
      {
        headers: {
          "X-Api-Key": BOOKNLIFE_AUTH_API_KEY,
          Authorization: "Bearer",
        },
      }
    );

    // 로그인 성공시 토큰 저장
    if (Request.data.ResultCd === "0000") {
      this.accessToken = Request.data.ResultData.accessToken;
    } else {
      throw new Error(`Login Error`);
    }
  }

  /**
   * 현재 로그인되어있는지 확인하는 함수입니다.
   * @returns 로그인 상태를 반환합니다.
   */
  public async isLogin() {
    const Request = await this.client.post(
      `https://webapi.booknlife.com/api/Member/GetMembInfoV2`,
      {},
      {
        headers: {
          Authorization: `Bearer ${this.accessToken}`,
          "X-Api-Key": BOOKNLIFE_API_KEY,
        },
      }
    );

    if (Request.data.ResultCd === "0000") {
      return true;
    } else {
      return false;
    }
  }

  /**
   * 북앤라이프에 핀코드를 충전하는 함수입니다. 여러개의 핀코드를 충전할 수 있습니다.
   * @param data PinCode[]
   * @example 
   * charge([
      {
        pin: "1234567890123456",
        code: "0000",
      },
      {
        pin: "1234567890123457",
        code: "0000",
      },
    ]);
   * @returns
   */
  public async charge(data: PinCode[]) {
    if (!this.accessToken) {
      throw new Error(`Login Required`);
    }

    if (!(await this.isLogin())) {
      throw new Error(
        `AccessToken Expired. (Use the isLogin() method to configure logic to re-login when the AccessToken expires.)`
      );
    }

    const pinList = data.map((v) => {
      return {
        pinNo: EncryptAES(v.pin),
        pinPw: EncryptAES(v.code),
      };
    });

    const captchaResponse = await this.solveCaptcha(
      "https://www.booknlife.com/cashcharge/",
      CAPTCHA_DATA_SITE_KEY
    );

    const Request = await this.client.post(
      "https://webapi.booknlife.com/api/Pay/PinCashCharge",
      {
        pinCashChargeType: "NORMAL",
        pinList: pinList,
        vrtInfo: captchaResponse,
      },
      {
        headers: {
          Authorization: `Bearer ${this.accessToken}`,
          "X-Api-Key": BOOKNLIFE_API_KEY,
        },
      }
    );

    if (Request.data.ResultCd !== "0000") {
      throw new Error(`Charge Error`);
    }

    return Request.data.ResultData;
  }

  public async getBalance() {
    if (!this.accessToken) {
      throw new Error(`Login Required`);
    }

    if (!(await this.isLogin())) {
      throw new Error(
        `AccessToken Expired. (Use the isLogin() method to configure logic to re-login when the AccessToken expires.)`
      );
    }

    const Request = await this.client.post(
      "https://webapi.booknlife.com/api/Member/GetMembInfoV2",
      {},
      {
        headers: {
          Authorization: `Bearer ${this.accessToken}`,
          "X-Api-Key": BOOKNLIFE_API_KEY,
        },
      }
    );

    if (Request.data.ResultCd !== "0000") {
      throw new Error(`MemberInfoFetch Error`);
    }

    const balance = DeEncryptAES(Request.data.ResultData.cashBal);

    return balance;
  }
}

export default Booknlife;

interface PinCode {
  pin: string;
  code: string;
}
