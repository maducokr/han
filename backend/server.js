/**
 * KRSLOT (한글·섬 슬롯) 백엔드
 * index.html 의 PI_AUTH_VERIFY_URL 및 Pi 결제 콜백과 연동
 *
 * index.html 설정 예:
 *   window.PI_AUTH_VERIFY_URL = "https://YOUR-BACKEND/api/pi/verify";
 */
require("dotenv").config();

const express = require("express");
const cors = require("cors");
const axios = require("axios");
const PiNetwork = require("pi-backend").default;

const PORT = Number(process.env.PORT) || 3000;
const PI_API_KEY = process.env.PI_API_KEY || "";
const PI_WALLET_SEED = process.env.PI_WALLET_SEED || "";
const PI_API_BASE = process.env.PI_API_BASE || "https://api.minepi.com";

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
    throw new Error("PI_API_KEY and PI_WALLET_SEED are required for payouts");
  }
  if (!piNetwork) {
    piNetwork = new PiNetwork(PI_API_KEY, PI_WALLET_SEED, {
      baseUrl: PI_API_BASE,
    });
  }
  return piNetwork;
}

const app = express();
app.set("trust proxy", 1);

app.use(
  cors({
    origin(origin, callback) {
      if (!origin || corsOrigins.includes(origin)) {
        callback(null, true);
        return;
      }
      callback(new Error(`CORS blocked: ${origin}`));
    },
    methods: ["GET", "POST", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Accept"],
  })
);
app.use(express.json({ limit: "32kb" }));

app.get("/health", (_req, res) => {
  res.json({
    ok: true,
    app: "krslot-backend",
    piApiConfigured: Boolean(PI_API_KEY),
    walletConfigured: Boolean(PI_WALLET_SEED),
  });
});

/**
 * POST /api/pi/verify
 * index.html verifyPiAccessToken() 가 호출하는 엔드포인트
 * Body: { "accessToken": "..." }
 */
app.post("/api/pi/verify", async (req, res) => {
  const accessToken = req.body?.accessToken;
  if (!accessToken || typeof accessToken !== "string") {
    return res.status(400).json({ success: false, error: "accessToken required" });
  }
  if (!PI_API_KEY) {
    return res.status(503).json({ success: false, error: "Server PI_API_KEY not configured" });
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
    console.warn("[verify]", status, err.message);
    return res.status(status === 401 ? 401 : 502).json({
      success: false,
      error: status === 401 ? "Invalid access token" : "Pi API verification failed",
    });
  }
});

/**
 * POST /api/pi/payments/approve
 * Pi.createPayment → onReadyForServerApproval 연동용 (U2A: 사용자 → 앱 입금)
 * Body: { "paymentId": "...", "accessToken": "..." }
 */
app.post("/api/pi/payments/approve", async (req, res) => {
  const paymentId = req.body?.paymentId;
  const accessToken = req.body?.accessToken;
  if (!paymentId || !accessToken) {
    return res.status(400).json({ success: false, error: "paymentId and accessToken required" });
  }
  if (!PI_API_KEY) {
    return res.status(503).json({ success: false, error: "PI_API_KEY not configured" });
  }

  try {
    await verifyAccessToken(accessToken);
    const client = piServerClient();
    const { data: payment } = await client.post(`/v2/payments/${paymentId}/approve`);
    return res.json({ success: true, payment });
  } catch (err) {
    const status = err.response?.status || 502;
    console.warn("[approve]", paymentId, status, err.response?.data || err.message);
    return res.status(status >= 400 && status < 600 ? status : 502).json({
      success: false,
      error: err.response?.data?.error || "Payment approval failed",
    });
  }
});

/**
 * POST /api/pi/payments/complete
 * Pi.createPayment → onReadyForServerCompletion 연동용
 * Body: { "paymentId": "...", "txid": "...", "accessToken": "..." }
 */
app.post("/api/pi/payments/complete", async (req, res) => {
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
    return res.status(503).json({ success: false, error: "PI_API_KEY not configured" });
  }

  try {
    await verifyAccessToken(accessToken);
    const client = piServerClient();
    const { data: payment } = await client.post(`/v2/payments/${paymentId}/complete`, { txid });
    return res.json({ success: true, payment });
  } catch (err) {
    const status = err.response?.status || 502;
    console.warn("[complete]", paymentId, status, err.response?.data || err.message);
    return res.status(status >= 400 && status < 600 ? status : 502).json({
      success: false,
      error: err.response?.data?.error || "Payment completion failed",
    });
  }
});

/**
 * POST /api/pi/payments/payout
 * A2U: 승리 상금 등 Pi 코인을 사용자에게 지급 (pi-backend)
 * Body: { "accessToken": "...", "amount": 1, "memo": "...", "metadata": {} }
 */
app.post("/api/pi/payments/payout", async (req, res) => {
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
    console.warn("[payout]", err.response?.data || err.message);
    return res.status(502).json({
      success: false,
      error: err.message || "Payout failed",
    });
  }
});

app.use((_req, res) => {
  res.status(404).json({ error: "Not found" });
});

app.use((err, _req, res, _next) => {
  if (err.message?.startsWith("CORS blocked")) {
    return res.status(403).json({ error: err.message });
  }
  console.error(err);
  res.status(500).json({ error: "Internal server error" });
});

app.listen(PORT, () => {
  console.log(`KRSLOT backend listening on http://localhost:${PORT}`);
  console.log(`  verify  POST /api/pi/verify`);
  console.log(`  approve POST /api/pi/payments/approve`);
  console.log(`  complete POST /api/pi/payments/complete`);
  if (!PI_API_KEY) console.warn("  WARN: PI_API_KEY not set — copy .env.example to .env");
});
