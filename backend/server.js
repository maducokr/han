/**
 * KRSLOT (한글·섬 슬롯) 백엔드
 * index.html 의 PI_AUTH_VERIFY_URL 및 Pi 결제 콜백과 연동
 * 배포: https://han-xe9x.onrender.com
 *
 * 보안: PI_API_KEY, PI_WALLET_SEED 등은 .env / 호스팅 환경 변수에만 저장.
 *       이 파일·응답·로그 어디에도 비밀값을 출력하지 않습니다.
 */
require("dotenv").config();

const fs = require("fs");
const path = require("path");
const express = require("express");
const cors = require("cors");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const axios = require("axios");
const PiNetwork = require("pi-backend").default;
const { PiExpress, createPiPaymentRouter } = require("./pi-payment-router");
const { PI_STACK } = require("./pi-framework");

const IS_PROD = process.env.NODE_ENV === "production";
const PORT = Number(process.env.PORT) || 3000;

/** 런타임에만 메모리에 보관 — export·응답·로그 금지 */
const PI_API_KEY = process.env.PI_API_KEY || "";
const PI_SANDBOX_API_KEY = process.env.PI_SANDBOX_API_KEY || "";
const PI_WALLET_SEED = process.env.PI_WALLET_SEED || "";
/** Testnet 앱 지갑 Seed — 미설정 시 PI_WALLET_SEED 사용 (Developer Portal → Testnet Wallet) */
const PI_SANDBOX_WALLET_SEED = process.env.PI_SANDBOX_WALLET_SEED || "";
const PI_API_BASE = process.env.PI_API_BASE || "https://api.minepi.com";
const PI_TO_KR_RATE = 3141590;

const DEFAULT_CORS = [
  "https://krslotcaaad0999.pinet.com",
  "https://maducokr.github.io",
  "http://localhost:5500",
  "http://127.0.0.1:5500",
  "http://localhost:3000",
  "http://127.0.0.1:3000",
];

const corsOrigins = (process.env.CORS_ORIGINS || DEFAULT_CORS.join(","))
  .split(",")
  .map((s) => s.trim())
  .filter(Boolean);

/** Pi Browser·PiNet·GitHub Pages 등 Origin 허용 (CORS 차단 시 로그인 verify 실패) */
function isAllowedCorsOrigin(origin) {
  if (!origin) return true;
  if (corsOrigins.includes(origin)) return true;
  try {
    const { hostname, protocol } = new URL(origin);
    if (protocol !== "https:" && protocol !== "http:") return false;
    const host = hostname.toLowerCase();
    if (host === "localhost" || host === "127.0.0.1") return true;
    const suffixes = ["minepi.com", "pinet.com", "github.io", "onrender.com", "socialchain.app"];
    return suffixes.some((suffix) => host === suffix || host.endsWith(`.${suffix}`));
  } catch {
    return false;
  }
}

const SENSITIVE_PATH_RE =
  /(?:^|\/)\.env(?:\/|$|\.|$)|(?:^|\/)\.git(?:\/|$)|(?:^|\/)package(?:-lock)?\.json$|(?:^|\/)server\.js$/i;

/** 로그·에러 문자열에서 비밀값·토큰 마스킹 */
function redactSecrets(input) {
  if (input == null) return input;
  const text = typeof input === "string" ? input : String(input);
  let out = text;

  if (PI_API_KEY.length > 8) {
    out = out.split(PI_API_KEY).join("[REDACTED_API_KEY]");
  }
  if (PI_WALLET_SEED.length > 8) {
    out = out.split(PI_WALLET_SEED).join("[REDACTED_WALLET_SEED]");
  }
  if (PI_SANDBOX_WALLET_SEED.length > 8) {
    out = out.split(PI_SANDBOX_WALLET_SEED).join("[REDACTED_SANDBOX_WALLET_SEED]");
  }

  return out
    .replace(/Bearer\s+[A-Za-z0-9._-]+/gi, "Bearer [REDACTED]")
    .replace(/Authorization:\s*Key\s+\S+/gi, "Authorization: Key [REDACTED]")
    .replace(/\bS[A-Z2-7]{55}\b/g, "[REDACTED_SEED]")
    .replace(/"accessToken"\s*:\s*"[^"]+"/gi, '"accessToken":"[REDACTED]"');
}

function safeWarn(tag, ...parts) {
  const msg = parts
    .map((p) => {
      if (p instanceof Error) return redactSecrets(p.message);
      if (typeof p === "object") {
        try {
          return redactSecrets(JSON.stringify(p));
        } catch {
          return "[object]";
        }
      }
      return redactSecrets(String(p));
    })
    .join(" ");
  console.warn(tag, msg);
}

/** 프로덕션에서는 내부 상세 숨김 */
function publicError(err, fallback) {
  if (!IS_PROD && err?.message) {
    return redactSecrets(err.message);
  }
  return fallback;
}

/** accessToken → Pi /v2/me 검증 (index.html verifyPiAccessToken 용) */
async function verifyAccessToken(accessToken) {
  if (typeof accessToken !== "string" || accessToken.length < 16 || accessToken.length > 4096) {
    const err = new Error("Invalid access token");
    err.status = 401;
    throw err;
  }

  const res = await axios.get(`${PI_API_BASE}/v2/me`, {
    headers: {
      Authorization: `Bearer ${accessToken}`,
      Accept: "application/json",
    },
    timeout: 20000,
    validateStatus: (s) => s < 500,
  });

  if (res.status !== 200 || !res.data?.uid) {
    const err = new Error("Invalid or expired access token");
    err.status = 401;
    throw err;
  }
  return res.data;
}

/** pi-backend (A2U) — sandbox 시 Testnet API Key · Testnet Wallet Seed */
const piNetworkCache = { main: null, sandbox: null };

function resolvePiCredentials(sandbox = false) {
  const apiKey = sandbox ? PI_SANDBOX_API_KEY || PI_API_KEY : PI_API_KEY;
  const walletSeed = sandbox
    ? PI_SANDBOX_WALLET_SEED || PI_WALLET_SEED
    : PI_WALLET_SEED;
  return { apiKey, walletSeed, sandbox: !!sandbox };
}

function getPiNetwork(sandbox = false) {
  const { apiKey, walletSeed, sandbox: isSandbox } = resolvePiCredentials(sandbox);
  if (!apiKey || !walletSeed) {
    throw new Error(
      isSandbox
        ? "Testnet payout not configured (PI_SANDBOX_API_KEY / PI_SANDBOX_WALLET_SEED)"
        : "Payout service is not configured (PI_API_KEY / PI_WALLET_SEED)"
    );
  }
  const cacheKey = isSandbox ? "sandbox" : "main";
  if (!piNetworkCache[cacheKey]) {
    piNetworkCache[cacheKey] = new PiNetwork(apiKey, walletSeed, {
      baseUrl: PI_API_BASE,
    });
  }
  return piNetworkCache[cacheKey];
}

const app = express();
app.disable("x-powered-by");
app.set("trust proxy", Number(process.env.TRUST_PROXY_HOPS) || 1);

app.use(
  helmet({
    contentSecurityPolicy: false,
    crossOriginResourcePolicy: { policy: "cross-origin" },
    hsts: IS_PROD ? { maxAge: 31536000, includeSubDomains: true } : false,
  })
);

/** .env 등 민감 경로 직접 접근 차단 */
app.use((req, res, next) => {
  const path = req.path || "";
  if (SENSITIVE_PATH_RE.test(path)) {
    return res.status(404).json({ error: "Not found" });
  }
  next();
});

app.use(
  cors({
    origin(origin, callback) {
      if (isAllowedCorsOrigin(origin)) {
        callback(null, true);
        return;
      }
      callback(new Error("CORS blocked"));
    },
    methods: ["GET", "POST", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Accept"],
  })
);

app.use(express.json({ limit: "32kb" }));

const globalApiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: IS_PROD ? 120 : 600,
  standardHeaders: true,
  legacyHeaders: false,
  message: { success: false, error: "Too many requests" },
});

const verifyLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: IS_PROD ? 30 : 120,
  standardHeaders: true,
  legacyHeaders: false,
  message: { success: false, error: "Too many requests" },
});

const paymentLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: IS_PROD ? 60 : 120,
  standardHeaders: true,
  legacyHeaders: false,
  message: { success: false, error: "Too many requests" },
});

app.use("/api/", globalApiLimiter);

/** Pi Developer Portal 도메인 검증 — https://han-xe9x.onrender.com/validation-key.txt */
const VALIDATION_KEY_PATH = path.join(__dirname, "validation-key.txt");
app.get("/validation-key.txt", (_req, res) => {
  try {
    const key = fs.readFileSync(VALIDATION_KEY_PATH, "utf8").trim();
    if (!key) {
      return res.status(404).type("text/plain").send("Not found");
    }
    res.type("text/plain; charset=utf-8").send(key);
  } catch {
    res.status(404).type("text/plain").send("Not found");
  }
});

/** 상태 확인 — LLM 스택 감지용 (프레임워크·결제 경로) */
app.get("/health", (_req, res) => {
  res.json({
    ok: true,
    version: "2026-06-15b",
    pi: {
      stack: PI_STACK.backend,
      package: PI_STACK.backendPackage,
      paymentsPath: PI_STACK.paymentsBasePath,
      sandboxKeyConfigured: !!PI_SANDBOX_API_KEY,
      sandboxWalletConfigured: !!(PI_SANDBOX_WALLET_SEED || PI_WALLET_SEED),
    },
  });
});

/**
 * POST /api/pi/verify
 * index.html verifyPiAccessToken() 가 호출하는 엔드포인트
 * Body: { "accessToken": "..." }
 */
app.post("/api/pi/verify", verifyLimiter, async (req, res) => {
  const accessToken = req.body?.accessToken;
  if (!accessToken || typeof accessToken !== "string") {
    return res.status(400).json({ success: false, error: "accessToken required" });
  }
  if (!PI_API_KEY && !PI_SANDBOX_API_KEY) {
    return res.status(503).json({ success: false, error: "Service unavailable" });
  }

  try {
    const me = await verifyAccessToken(accessToken);
    return res.json({
      success: true,
      user: {
        uid: me.uid,
        username: me.username || null,
      },
    });
  } catch (err) {
    const status = err.status || err.response?.status || 401;
    safeWarn("[verify]", status, err.message);
    return res.status(status === 401 ? 401 : 502).json({
      success: false,
      error: status === 401 ? "Invalid access token" : "Verification failed",
    });
  }
});

/** pi-sdk-express — sandbox(테스트넷) / production(메인넷) API Key · Wallet Seed 분리 */
function getPiExpress(sandbox = false) {
  const { apiKey, walletSeed } = resolvePiCredentials(sandbox);
  if (!apiKey) {
    throw new Error(
      sandbox
        ? "PI_SANDBOX_API_KEY is not configured (Developer Portal → Testnet API Key)"
        : "PI_API_KEY is not configured"
    );
  }
  return new PiExpress({
    apiKey,
    walletPrivateSeed: walletSeed,
    apiBase: PI_API_BASE,
  });
}

/**
 * U2A 결제 — pi-sdk-express (Express 표준 /payments)
 * LLM: Express 감지 시 pi-sdk-express → /payments/approve · /payments/complete
 */
function createPiPaymentMiddleware() {
  return createPiPaymentRouter({
    getPiExpress,
    verifyAccessToken,
    incompleteCallback: async () => "complete",
  });
}

if (PI_API_KEY || PI_SANDBOX_API_KEY) {
  const piPaymentRouter = createPiPaymentMiddleware();
  app.use(PI_STACK.paymentsBasePath, paymentLimiter, piPaymentRouter);
  app.use(PI_STACK.legacyPaymentsBasePath, paymentLimiter, piPaymentRouter);
} else {
  const unavailable = (_req, res) => {
    res.status(503).json({ success: false, error: "Service unavailable" });
  };
  app.use(PI_STACK.paymentsBasePath, unavailable);
  app.use(PI_STACK.legacyPaymentsBasePath, unavailable);
}

/**
 * POST /api/pi/stake
 * π U2A 스테이킹 확인 — 선택 금액 → KR CASH 세션 시작
 * Body: { accessToken, piAmount, paymentId?, rate?, sandbox? }
 */
app.post("/api/pi/stake", paymentLimiter, async (req, res) => {
  const accessToken = req.body?.accessToken;
  const piAmount = Number(req.body?.piAmount);
  const paymentId = req.body?.paymentId || null;
  const rate = Number(req.body?.rate) || PI_TO_KR_RATE;
  const sandbox = !!req.body?.sandbox;

  if (!accessToken || !Number.isFinite(piAmount) || piAmount <= 0) {
    return res.status(400).json({
      success: false,
      error: "accessToken and positive piAmount required",
    });
  }

  try {
    const me = await verifyAccessToken(accessToken);
    const krAmount = Math.floor(piAmount * rate);
    safeWarn(
      "[stake]",
      sandbox ? "sandbox" : "main",
      me.username || me.uid,
      "pi",
      piAmount,
      "kr",
      krAmount,
      paymentId || "-"
    );
    return res.json({
      success: true,
      stake: {
        piAmount,
        krAmount,
        rate,
        paymentId,
        uid: me.uid,
        username: me.username || null,
        sandbox,
      },
    });
  } catch (err) {
    const status = err.status || 502;
    safeWarn("[stake]", status, err.message);
    return res.status(status === 401 ? 401 : 502).json({
      success: false,
      error: publicError(err, "Stake failed"),
    });
  }
});

/**
 * POST /api/pi/session/settle
 * STOP·게임 종료 시 세션 베팅 KR → π 환산 → 제작자(앱) 지갑 정산
 * Body: { accessToken, krBalance, krBet, krWon, krConsumed, rate, settleType }
 */
app.post("/api/pi/session/settle", paymentLimiter, async (req, res) => {
  const accessToken = req.body?.accessToken;
  const krBalance = Math.floor(Number(req.body?.krBalance) || 0);
  const krBet = Math.floor(Number(req.body?.krBet) || 0);
  const krWon = Math.floor(Number(req.body?.krWon) || 0);
  const settleType = req.body?.settleType || "session_stop";
  const rate = Number(req.body?.rate) || PI_TO_KR_RATE;
  /** 베팅 KR 합계 = 제작자 수익 (당첨 π는 A2U로 별도 지급됨) */
  const krConsumed = Math.max(
    0,
    Math.floor(Number(req.body?.krConsumed) || krBet)
  );

  if (!accessToken) {
    return res.status(400).json({ success: false, error: "accessToken required" });
  }
  if (krConsumed <= 0) {
    return res.status(400).json({ success: false, error: "krConsumed must be positive" });
  }

  try {
    const me = await verifyAccessToken(accessToken);
    const housePi = Math.floor((krConsumed / rate) * 1e7) / 1e7;
    const userPi = Math.floor((krBalance / rate) * 1e7) / 1e7;
    safeWarn(
      "[settle]",
      settleType,
      me.username || me.uid,
      "krBet",
      krBet,
      "krConsumed",
      krConsumed,
      "housePi",
      housePi,
      "userPi",
      userPi
    );
    return res.json({
      success: true,
      settleType,
      krBet,
      krWon,
      krConsumed,
      krBalance,
      housePi,
      userPi,
      developerWallet: {
        wallet: "app_wallet",
        piAmount: housePi,
        krAmount: krConsumed,
        status: "deposited",
      },
      message: `베팅 ${krConsumed.toLocaleString("ko-KR")} KR (≈ ${housePi} π)이 제작자 지갑에 입금되었습니다.`,
    });
  } catch (err) {
    const status = err.status || 502;
    safeWarn("[settle]", status, err.message);
    return res.status(status === 401 ? 401 : 502).json({
      success: false,
      error: publicError(err, "Session settle failed"),
    });
  }
});

/**
 * POST /api/pi/payments/payout
 * A2U: 당첨·게임종료 → 유저 지갑 π 지급 (pi-backend)
 * Body: { accessToken, amount, memo, metadata, sandbox?: boolean }
 */
app.post("/api/pi/payments/payout", paymentLimiter, async (req, res) => {
  const accessToken = req.body?.accessToken;
  const amount = Number(req.body?.amount);
  const memo = req.body?.memo || "KRSLOT prize";
  const metadata = req.body?.metadata || {};
  const sandbox = !!req.body?.sandbox;

  if (!accessToken || !Number.isFinite(amount) || amount <= 0) {
    return res.status(400).json({
      success: false,
      error: "accessToken and positive amount required",
    });
  }

  try {
    const me = await verifyAccessToken(accessToken);
    const pi = getPiNetwork(sandbox);
    const paymentId = await pi.createPayment({
      amount,
      memo,
      metadata,
      uid: me.uid,
    });
    const txid = await pi.submitPayment(paymentId);
    const payment = await pi.completePayment(paymentId, txid);
    return res.json({ success: true, paymentId, txid, payment, sandbox });
  } catch (err) {
    safeWarn("[payout]", "sandbox:", sandbox, err.message);
    return res.status(502).json({
      success: false,
      error: publicError(err, "Payout failed"),
    });
  }
});

app.use((_req, res) => {
  res.status(404).json({ error: "Not found" });
});

app.use((err, _req, res, _next) => {
  if (err.message === "CORS blocked") {
    return res.status(403).json({ error: "Forbidden" });
  }
  safeWarn("[error]", err);
  res.status(500).json({ error: "Internal server error" });
});

process.on("uncaughtException", (err) => {
  safeWarn("[uncaughtException]", err);
});

process.on("unhandledRejection", (reason) => {
  safeWarn("[unhandledRejection]", reason);
});

app.listen(PORT, () => {
  console.log(`KRSLOT backend listening on port ${PORT}`);
  if (!PI_API_KEY && !PI_SANDBOX_API_KEY) {
    console.warn("WARN: PI_API_KEY / PI_SANDBOX_API_KEY not set");
  }
  if (PI_SANDBOX_API_KEY && !PI_SANDBOX_WALLET_SEED && !PI_WALLET_SEED) {
    console.warn("WARN: Testnet payout needs PI_SANDBOX_WALLET_SEED or PI_WALLET_SEED");
  }
});
