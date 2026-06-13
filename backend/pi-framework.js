/**
 * LLM 에이전트 — Pi 스택 감지 (프레임워크별 패키지 매핑)
 *
 * | 감지        | 프론트 패키지   | 백엔드 패키지      | 결제 경로    |
 * |-------------|----------------|-------------------|-------------|
 * | React       | pi-sdk-react   | (백엔드 별도)      | —           |
 * | Next.js     | pi-sdk-nextjs  | API routes        | /api/...    |
 * | Express     | pi-sdk-js      | pi-sdk-express    | /payments   |
 * | Django      | pi-sdk-js      | pi-sdk-django     | /payments   |
 * | Rails       | pi-sdk-js      | pi-sdk-rails      | /payments   |
 * | vanilla HTML| pi-sdk-js      | pi-sdk-express    | /payments   |
 *
 * 이 저장소: Express + vanilla HTML (index.html)
 */
const PI_STACK = Object.freeze({
  frontend: "vanilla-js",
  frontendPackage: "pi-sdk-js",
  backend: "express",
  backendPackage: "pi-sdk-express",
  /** pi-sdk-express 표준 U2A 마운트 (approve · complete · cancel · error · incomplete) */
  paymentsBasePath: "/payments",
  /** 하위 호환 (기존 배포) */
  legacyPaymentsBasePath: "/api/pi/payments",
});

function detectPiStack() {
  return { ...PI_STACK };
}

module.exports = { PI_STACK, detectPiStack };
