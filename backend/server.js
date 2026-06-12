/**
 * KRSLOT (한글·섬 슬롯) 백엔드
 * index.html 의 PI_AUTH_VERIFY_URL 및 Pi 결제 콜백과 연동
 * 배포: https://han-xe9x.onrender.com
 *
 * 보안: PI_API_KEY, PI_WALLET_SEED 등은 .env / 호스팅 환경 변수에만 저장.
 *       이 파일·응답·로그 어디에도 비밀값을 출력하지 않습니다.
 */
require("dotenv").config();

const express = require("express");
const cors = require("cors");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const axios = require("axios");
const PiNetwork = require("pi-backend").default;

const IS_PROD = process.env.NODE_ENV === "production";
const PORT = Number(process.env.PORT) || 3000;

/** 런타임에만 메모리에 보관 — export·응답·로그 금지 */
const PI_API_KEY = process.env.PI_API_KEY || "";
const PI_WALLET_SEED = process.env.PI_WALLET_SEED || "";
const PI_API_BASE = process.env.PI_API_BASE || "https://api.minepi.com";
const PI_TO_KR_RATE = 3141590;

const DEFAULT_CORS = [
  "https://krslotcaaad0999.pinet.com",
  "https://han-krslot.onrender.com",
];

const corsOrigins = (process.env.CORS_ORIGINS || DEFAULT_CORS.join(","))
  .split(",")
  .map((s) => s.trim())
  .filter(Boolean);

/** PiNet·Render( onrender.com ) Origin 허용 */
function isAllowedCorsOrigin(origin) {
  if (!origin) return true;
  if (corsOrigins.includes(origin)) return true;
  try {
    const host = new URL(origin).hostname.toLowerCase();
    return host === "onrender.com" || host.endsWith(".onrender.com");
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

/** Pi Platform API (Server API Key) */
function piServerClient() {
  if (!PI_API_KEY) {
    throw new Error("PI_API_KEY is not configured");
  }
  return axios.create({
    baseURL: PI_API_BASE,
    timeout: 20000,
    headers: {
      Authorization: `Key ${PI_API_KEY}`,
      "Content-Type": "application/json",
      Accept: "application/json",
    },
  });
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

/** pi-backend (A2U: 앱 → 사용자 Pi 지급) — 지갑 시드 설정 시에만 사용 */
let piNetwork = null;
function getPiNetwork() {
  if (!PI_API_KEY || !PI_WALLET_SEED) {
    throw new Error("Payout service is not configured");
  }
  if (!piNetwork) {
    piNetwork = new PiNetwork(PI_API_KEY, PI_WALLET_SEED, {
      baseUrl: PI_API_BASE,
    });
  }
  return piNetwork;
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
  max: IS_PROD ? 20 : 80,
  standardHeaders: true,
  legacyHeaders: false,
  message: { success: false, error: "Too many requests" },
});

app.use("/api/", globalApiLimiter);

/** 상태 확인 — 비밀·설정 노출 없음 */
app.get("/health", (_req, res) => {
  res.json({ ok: true });
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
  if (!PI_API_KEY) {
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

/**
 * POST /api/pi/payments/approve
 * Pi.createPayment → onReadyForServerApproval 연동용 (U2A: 사용자 → 앱 입금)
 */
app.post("/api/pi/payments/approve", paymentLimiter, async (req, res) => {
  const paymentId = req.body?.paymentId;
  const accessToken = req.body?.accessToken;
  if (!paymentId || !accessToken) {
    return res.status(400).json({ success: false, error: "paymentId and accessToken required" });
  }
  if (!PI_API_KEY) {
    return res.status(503).json({ success: false, error: "Service unavailable" });
  }

  try {
    await verifyAccessToken(accessToken);
    const client = piServerClient();
    const { data: payment } = await client.post(`/v2/payments/${paymentId}/approve`);
    return res.json({ success: true, payment });
  } catch (err) {
    const status = err.response?.status || 502;
    safeWarn("[approve]", paymentId, status, err.message);
    return res.status(status >= 400 && status < 600 ? status : 502).json({
      success: false,
      error: publicError(err, "Payment approval failed"),
    });
  }
});

/**
 * POST /api/pi/payments/complete
 * Pi.createPayment → onReadyForServerCompletion 연동용
 */
app.post("/api/pi/payments/complete", paymentLimiter, async (req, res) => {
  const paymentId = req.body?.paymentId;
  const txid = req.body?.txid;
  const accessToken = req.body?.accessToken;
  if (!paymentId || !txid || !accessToken) {
    return res.status(400).json({
      success: false,
      error: "paymentId, txid, and accessToken required",
    });
  }
  if (!PI_API_KEY) {
    return res.status(503).json({ success: false, error: "Service unavailable" });
  }

  try {
    await verifyAccessToken(accessToken);
    const client = piServerClient();
    const { data: payment } = await client.post(`/v2/payments/${paymentId}/complete`, { txid });
    return res.json({ success: true, payment });
  } catch (err) {
    const status = err.response?.status || 502;
    safeWarn("[complete]", paymentId, status, err.message);
    return res.status(status >= 400 && status < 600 ? status : 502).json({
      success: false,
      error: publicError(err, "Payment completion failed"),
    });
  }
});

/**
 * POST /api/pi/session/settle
 * 게임 종료 시 소모 KR → 제작자(앱) 지갑 정산 기록
 * Body: { accessToken, krBalance, krBet, krWon, krConsumed, rate }
 */
app.post("/api/pi/session/settle", paymentLimiter, async (req, res) => {
  const accessToken = req.body?.accessToken;
  const krBalance = Math.floor(Number(req.body?.krBalance) || 0);
  const krBet = Math.floor(Number(req.body?.krBet) || 0);
  const krWon = Math.floor(Number(req.body?.krWon) || 0);
  const krConsumed = Math.max(
    0,
    Math.floor(Number(req.body?.krConsumed) || krBet - krWon)
  );
  const rate = Number(req.body?.rate) || PI_TO_KR_RATE;

  if (!accessToken) {
    return res.status(400).json({ success: false, error: "accessToken required" });
  }

  try {
    const me = await verifyAccessToken(accessToken);
    const housePi = Math.floor((krConsumed / rate) * 1e7) / 1e7;
    const userPi = Math.floor((krBalance / rate) * 1e7) / 1e7;
    safeWarn(
      "[settle]",
      me.username || me.uid,
      "krConsumed",
      krConsumed,
      "housePi",
      housePi,
      "userPi",
      userPi
    );
    return res.json({
      success: true,
      krConsumed,
      krBalance,
      housePi,
      userPi,
      developerWallet: "app_wallet",
      note: "소모 KR에 해당하는 π는 입금 시 앱 지갑에 보관됩니다.",
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
 * A2U: 게임 종료 잔액·상금 → 유저 지갑 π 지급 (pi-backend)
 */
app.post("/api/pi/payments/payout", paymentLimiter, async (req, res) => {
  const accessToken = req.body?.accessToken;
  const amount = Number(req.body?.amount);
  const memo = req.body?.memo || "KRSLOT prize";
  const metadata = req.body?.metadata || {};

  if (!accessToken || !Number.isFinite(amount) || amount <= 0) {
    return res.status(400).json({
      success: false,
      error: "accessToken and positive amount required",
    });
  }

  try {
    const me = await verifyAccessToken(accessToken);
    const pi = getPiNetwork();
    const paymentId = await pi.createPayment({
      amount,
      memo,
      metadata,
      uid: me.uid,
    });
    const txid = await pi.submitPayment(paymentId);
    const payment = await pi.completePayment(paymentId, txid);
    return res.json({ success: true, paymentId, txid, payment });
  } catch (err) {
    safeWarn("[payout]", err.message);
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
  if (!PI_API_KEY) {
    console.warn("WARN: PI_API_KEY not set — set it in .env or hosting env vars");
  }
});
