/**
 * pi-sdk-express 호환 — PiExpress + U2A 결제 라우터
 * GenAI 워크플로: approve(paymentId) → 블록체인 txid → complete(paymentId, txid)
 * @see https://pi-apps.github.io/pi-sdk-docs/
 */
const { Router } = require("express");

function getPiServerConfig(overrides = {}) {
  const apiUrlBase =
    overrides.apiBase ||
    process.env.PI_API_URL_BASE ||
    process.env.PI_API_BASE ||
    "https://api.minepi.com";
  const apiVersion = process.env.PI_API_VERSION || "v2";
  const apiController = process.env.PI_API_CONTROLLER || "payments";
  const apiKey = overrides.apiKey || process.env.PI_API_KEY || "";
  if (!apiKey) {
    throw new Error("PI_API_KEY is not configured");
  }
  return { apiUrlBase, apiVersion, apiController, apiKey };
}

async function postToPiServer(action, paymentId, body = {}, opts = {}) {
  const { apiUrlBase, apiVersion, apiController, apiKey } = getPiServerConfig(opts);
  const url = `${apiUrlBase.replace(/\/$/, "")}/${apiVersion}/${apiController}/${paymentId}/${action}`;
  const headers = {
    "Content-Type": "application/json",
    Authorization: `Key ${apiKey}`,
    ...(opts.header || {}),
  };

  let res;
  try {
    res = await fetch(url, {
      method: "POST",
      body: JSON.stringify(body),
      headers,
    });
  } catch (err) {
    opts.logFail?.(`Pi server POST ${action} network error`, err);
    throw err;
  }

  const text = await res.text();
  let data;
  try {
    data = text ? JSON.parse(text) : {};
  } catch {
    opts.logFail?.(`Pi server POST ${action} invalid JSON (${res.status})`, text, res.status);
    throw new Error(`Invalid JSON from Pi server: ${text}`);
  }

  if (res.ok) {
    opts.logOk?.(`Pi server POST ${action} OK (${res.status})`, data);
    return data;
  }
  opts.logFail?.(`Pi server POST ${action} HTTP ${res.status}`, data, res.status);
  const err = new Error(data?.error || `Pi server HTTP ${res.status}`);
  err.status = res.status;
  throw err;
}

function pickTransactionId(body) {
  return body?.txid || body?.transactionId || null;
}

/**
 * pi-sdk-express PiExpress — approvePayment / completePayment
 * const pi = new PiExpress({ apiKey, walletPrivateSeed });
 */
class PiExpress {
  constructor(options = {}) {
    this.apiKey = options.apiKey || process.env.PI_API_KEY || "";
    this.walletPrivateSeed = options.walletPrivateSeed || process.env.PI_WALLET_SEED || "";
    this.apiBase = options.apiBase || process.env.PI_API_BASE || "https://api.minepi.com";
    if (!this.apiKey) {
      throw new Error("PiExpress: apiKey (PI_API_KEY) is required");
    }
  }

  _logOpts(paymentId) {
    return {
      apiKey: this.apiKey,
      apiBase: this.apiBase,
      logOk: (msg) => console.info("[PiExpress]", msg, paymentId),
      logFail: (msg, err) =>
        console.warn("[PiExpress]", msg, paymentId, err?.message || err),
    };
  }

  /** onReadyForServerApproval — Pi Platform /payments/:id/approve */
  async approvePayment(paymentId) {
    if (!paymentId) throw new Error("paymentId required");
    return postToPiServer("approve", paymentId, {}, this._logOpts(paymentId));
  }

  /** onReadyForServerCompletion — Pi Platform /payments/:id/complete */
  async completePayment(paymentId, txid) {
    if (!paymentId || !txid) throw new Error("paymentId and txid required");
    return postToPiServer("complete", paymentId, { txid }, this._logOpts(paymentId));
  }

  async cancelPayment(paymentId) {
    if (!paymentId) throw new Error("paymentId required");
    return postToPiServer("cancel", paymentId, {}, this._logOpts(paymentId));
  }
}

function resolvePiExpress(options, sandbox) {
  if (typeof options.getPiExpress === "function") {
    return options.getPiExpress(!!sandbox);
  }
  return options.piExpress || new PiExpress();
}

function createApproveHandler(verifyAccessToken, options) {
  const opts = typeof options === "object" && options !== null ? options : { piExpress: options };
  return async function approveHandler(req, res) {
    const { paymentId, sandbox } = req.body || {};
    try {
      if (!paymentId) {
        return res.status(400).json({ success: false, error: "paymentId required" });
      }
      if (paymentId === "__warmup__") {
        return res.json({ success: true, result: "warmup", paymentId });
      }
      /* Pi SDK 승인 타임아웃(~20s) — approve를 최우선, accessToken 검증은 생략 */
      const pi = resolvePiExpress(opts, sandbox);
      const payment = await pi.approvePayment(paymentId);
      if (verifyAccessToken && req.body?.accessToken) {
        verifyAccessToken(req.body.accessToken).catch((err) => {
          console.warn("[approve] accessToken verify (non-blocking):", err?.message || err);
        });
      }
      return res.json({ success: true, result: "approved", paymentId, payment, sandbox: !!sandbox });
    } catch (err) {
      const status = err.status === 401 ? 401 : err.status >= 400 && err.status < 600 ? err.status : 502;
      const piError = err.message || "Payment approval failed";
      console.warn("[approve]", paymentId, "sandbox:", !!sandbox, piError);
      return res.status(status).json({
        success: false,
        error: piError,
      });
    }
  };
}

function createCompleteHandler(options) {
  const opts = typeof options === "object" && options !== null ? options : { piExpress: options };
  return async function completeHandler(req, res) {
    try {
      const { paymentId, sandbox } = req.body || {};
      const txid = pickTransactionId(req.body);
      if (!paymentId || !txid) {
        return res.status(400).json({
          success: false,
          error: "paymentId and txid required",
        });
      }
      const pi = resolvePiExpress(opts, sandbox);
      const payment = await pi.completePayment(paymentId, txid);
      return res.json({ success: true, result: "completed", paymentId, payment });
    } catch (err) {
      const status = err.status >= 400 && err.status < 600 ? err.status : 502;
      return res.status(status).json({
        success: false,
        error: err.message || "Payment completion failed",
      });
    }
  };
}

function createCancelHandler(options) {
  const opts = typeof options === "object" && options !== null ? options : { piExpress: options };
  return async function cancelHandler(req, res) {
    try {
      const { paymentId, sandbox } = req.body || {};
      if (!paymentId) {
        return res.status(400).json({ success: false, error: "paymentId required" });
      }
      const pi = resolvePiExpress(opts, sandbox);
      const payment = await pi.cancelPayment(paymentId);
      return res.json({ success: true, result: "cancelled", paymentId, payment });
    } catch (err) {
      const status = err.status >= 400 && err.status < 600 ? err.status : 502;
      return res.status(status).json({ success: false, error: err.message || "Payment cancel failed" });
    }
  };
}

function createErrorHandler() {
  return async function errorHandler(req, res) {
    const { paymentId, error: paymentError } = req.body || {};
    if (!paymentId) {
      return res.status(400).json({ success: false, error: "paymentId required" });
    }
    console.warn("[pi-payment] client error", paymentId, paymentError || "(no detail)");
    return res.json({ success: true, result: "error-logged", paymentId });
  };
}

function createIncompleteHandler(incompleteCallback, options) {
  const opts = typeof options === "object" && options !== null ? options : { piExpress: options };
  return async function incompleteHandler(req, res) {
    try {
      const { paymentId, sandbox } = req.body || {};
      const txid = pickTransactionId(req.body);
      if (!paymentId || !txid) {
        return res.status(400).json({
          success: false,
          error: "paymentId and txid required",
        });
      }

      let decision = "complete";
      if (incompleteCallback) {
        const result = await incompleteCallback(paymentId, txid, req.body);
        decision = result === "cancel" ? "cancel" : "complete";
      }

      const pi = resolvePiExpress(opts, sandbox);
      const payment =
        decision === "cancel"
          ? await pi.cancelPayment(paymentId)
          : await pi.completePayment(paymentId, txid);

      return res.json({ success: true, result: decision, paymentId, payment });
    } catch (err) {
      const status = err.status >= 400 && err.status < 600 ? err.status : 502;
      return res.status(status).json({
        success: false,
        error: err.message || "Incomplete payment handling failed",
      });
    }
  };
}

/**
 * U2A 결제 라우터 — /approve · /complete · /cancel · /error · /incomplete
 * @param {{ piExpress?: PiExpress, verifyAccessToken?: Function, incompleteCallback?: Function, middleware?: Function[] }} options
 */
function createPiPaymentRouter(options = {}) {
  const router = Router();
  const { piExpress, getPiExpress, verifyAccessToken, incompleteCallback, middleware = [] } = options;
  const routerOpts = getPiExpress ? { getPiExpress } : { piExpress: piExpress || (process.env.PI_API_KEY ? new PiExpress() : null) };
  const hasPi = getPiExpress || routerOpts.piExpress;

  middleware.forEach((fn) => router.use(fn));

  if (!hasPi) {
    router.use((_req, res) => {
      res.status(503).json({ success: false, error: "Service unavailable" });
    });
    return router;
  }

  router.post("/approve", createApproveHandler(verifyAccessToken, routerOpts));
  router.post("/complete", createCompleteHandler(routerOpts));
  router.post("/cancel", createCancelHandler(routerOpts));
  router.post("/error", createErrorHandler());
  router.post("/incomplete", createIncompleteHandler(incompleteCallback, routerOpts));

  return router;
}

module.exports = {
  PiExpress,
  createPiPaymentRouter,
  postToPiServer,
  getPiServerConfig,
};
