/**
 * pi-sdk-express 호환 U2A 결제 라우터 (Express)
 * ※ Rails(pi-sdk-rails) 미사용 — 이 프로젝트 스택은 Express + pi-backend(A2U)
 * @see https://github.com/pi-apps/pi-sdk-express
 * npm 패키지 미배포 시 로컬 구현 — API 경로·페이로드 동일
 */
const { Router } = require("express");

function getPiServerConfig() {
  const apiUrlBase = process.env.PI_API_URL_BASE || process.env.PI_API_BASE || "https://api.minepi.com";
  const apiVersion = process.env.PI_API_VERSION || "v2";
  const apiController = process.env.PI_API_CONTROLLER || "payments";
  const apiKey = process.env.PI_API_KEY || "";
  if (!apiKey) {
    throw new Error("PI_API_KEY is not configured");
  }
  return { apiUrlBase, apiVersion, apiController, apiKey };
}

async function postToPiServer(action, paymentId, body = {}, opts = {}) {
  const { apiUrlBase, apiVersion, apiController, apiKey } = getPiServerConfig();
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
  return body?.transactionId || body?.txid || null;
}

function createApproveHandler(verifyAccessToken) {
  return async function approveHandler(req, res) {
    try {
      const { accessToken, paymentId } = req.body || {};
      if (!paymentId) {
        return res.status(400).json({ success: false, error: "paymentId required" });
      }
      if (!accessToken) {
        return res.status(400).json({ success: false, error: "accessToken required" });
      }
      if (verifyAccessToken) {
        await verifyAccessToken(accessToken);
      }
      const payment = await postToPiServer("approve", paymentId, {}, {
        logOk: (msg) => console.info("[pi-payment]", msg, paymentId),
        logFail: (msg, err) => console.warn("[pi-payment]", msg, paymentId, err?.message || err),
      });
      return res.json({ success: true, result: "approved", paymentId, payment });
    } catch (err) {
      const status = err.status === 401 ? 401 : err.status >= 400 && err.status < 600 ? err.status : 502;
      return res.status(status).json({
        success: false,
        error: err.message || "Payment approval failed",
      });
    }
  };
}

function createCompleteHandler() {
  return async function completeHandler(req, res) {
    try {
      const { paymentId } = req.body || {};
      const transactionId = pickTransactionId(req.body);
      if (!paymentId || !transactionId) {
        return res.status(400).json({
          success: false,
          error: "paymentId and transactionId required",
        });
      }
      const payment = await postToPiServer(
        "complete",
        paymentId,
        { txid: transactionId },
        {
          logOk: (msg) => console.info("[pi-payment]", msg, paymentId),
          logFail: (msg, err) => console.warn("[pi-payment]", msg, paymentId, err?.message || err),
        }
      );
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

function createCancelHandler() {
  return async function cancelHandler(req, res) {
    try {
      const { paymentId } = req.body || {};
      if (!paymentId) {
        return res.status(400).json({ success: false, error: "paymentId required" });
      }
      const payment = await postToPiServer("cancel", paymentId, {}, {
        logOk: (msg) => console.info("[pi-payment]", msg, paymentId),
        logFail: (msg, err) => console.warn("[pi-payment]", msg, paymentId, err?.message || err),
      });
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

function createIncompleteHandler(incompleteCallback) {
  return async function incompleteHandler(req, res) {
    try {
      const { paymentId } = req.body || {};
      const transactionId = pickTransactionId(req.body);
      if (!paymentId || !transactionId) {
        return res.status(400).json({
          success: false,
          error: "paymentId and transactionId required",
        });
      }

      let decision = "complete";
      if (incompleteCallback) {
        const result = await incompleteCallback(paymentId, transactionId, req.body);
        decision = result === "cancel" ? "cancel" : "complete";
      }

      const action = decision === "cancel" ? "cancel" : "complete";
      const body = action === "complete" ? { txid: transactionId } : {};
      const payment = await postToPiServer(action, paymentId, body, {
        logOk: (msg) => console.info("[pi-payment]", msg, paymentId, decision),
        logFail: (msg, err) => console.warn("[pi-payment]", msg, paymentId, err?.message || err),
      });

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
 * pi-sdk-express createPiPaymentRouter 호환
 * @param {{ verifyAccessToken?: (token: string) => Promise<object>, incompleteCallback?: Function, middleware?: Function[] }} options
 */
function createPiPaymentRouter(options = {}) {
  const router = Router();
  const { verifyAccessToken, incompleteCallback, middleware = [] } = options;

  middleware.forEach((fn) => router.use(fn));

  router.post("/approve", createApproveHandler(verifyAccessToken));
  router.post("/complete", createCompleteHandler());
  router.post("/cancel", createCancelHandler());
  router.post("/error", createErrorHandler());
  router.post("/incomplete", createIncompleteHandler(incompleteCallback));

  return router;
}

module.exports = {
  createPiPaymentRouter,
  postToPiServer,
  getPiServerConfig,
};
