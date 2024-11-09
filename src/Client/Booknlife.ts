import { EncryptAES, EncryptLoginInfo } from "../Utils/Algorithm";
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

  public async AuthApiReady(type?: string | "Bearer") {
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

  public async charge(data: PinCode[]) {
    if (!this.accessToken) {
      throw new Error(`Login Required`);
    }

    if (!(await this.isLogin())) {
      // 엑세스 토큰이 만료되었을 경우 다시 로그인
      await this.login();
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
}

export default Booknlife;

interface PinCode {
  pin: string;
  code: string;
}
