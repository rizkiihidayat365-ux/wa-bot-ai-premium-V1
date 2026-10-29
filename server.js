import express from "express";
import OpenAI from "openai";
import crypto from "node:crypto";
import path from "node:path";
import { fileURLToPath } from "node:url";

const app = express();
const PORT = process.env.PORT || 3000;
const __dirname = path.dirname(fileURLToPath(import.meta.url));

const {
  OPENAI_API_KEY,
  OPENAI_MODEL = "gpt-6-luna",
  WHATSAPP_ACCESS_TOKEN,
  WHATSAPP_PHONE_NUMBER_ID,
  WHATSAPP_VERIFY_TOKEN,
  WHATSAPP_API_VERSION = "v23.0",
  META_APP_SECRET,
  DASHBOARD_USER = "admin",
  DASHBOARD_PASSWORD,
  BOT_NAME = "WA Bot AI",
  BOT_INSTRUCTIONS = "Kamu adalah asisten WhatsApp yang ramah, jelas, dan membantu. Jawab dalam bahasa yang digunakan pengguna. Jangan mengaku sebagai manusia."
} = process.env;

const openai = OPENAI_API_KEY ? new OpenAI({ apiKey: OPENAI_API_KEY }) : null;

// Webhook needs the raw request body for optional Meta signature verification.
app.use("/webhook/whatsapp", express.raw({ type: "application/json", limit: "1mb" }));
app.use(express.json({ limit: "1mb" }));

function safeEqual(a, b) {
  const aa = Buffer.from(String(a || ""));
  const bb = Buffer.from(String(b || ""));
  return aa.length === bb.length && crypto.timingSafeEqual(aa, bb);
}

function dashboardAuth(req, res, next) {
  if (!DASHBOARD_PASSWORD) {
    return res.status(503).send("Dashboard belum dikunci. Tambahkan DASHBOARD_PASSWORD di Environment Variables.");
  }
  const header = req.headers.authorization || "";
  const [scheme, encoded] = header.split(" ");
  if (scheme === "Basic" && encoded) {
    let decoded = "";
    try { decoded = Buffer.from(encoded, "base64").toString("utf8"); } catch {}
    const idx = decoded.indexOf(":");
    const user = idx >= 0 ? decoded.slice(0, idx) : "";
    const pass = idx >= 0 ? decoded.slice(idx + 1) : "";
    if (safeEqual(user, DASHBOARD_USER) && safeEqual(pass, DASHBOARD_PASSWORD)) return next();
  }
  res.set("WWW-Authenticate", 'Basic realm="WA Bot AI Studio"');
  return res.status(401).send("Login dashboard diperlukan.");
}

function checkMetaSignature(req) {
  if (!META_APP_SECRET) return true; // Optional for initial setup; configure for stronger verification.
  const signature = req.get("x-hub-signature-256") || "";
  if (!signature.startsWith("sha256=")) return false;
  const rawBody = Buffer.isBuffer(req.body) ? req.body : Buffer.from(JSON.stringify(req.body || {}));
  const digest = crypto.createHmac("sha256", META_APP_SECRET).update(rawBody).digest("hex");
  return safeEqual(signature.slice(7), digest);
}

async function askAI(text) {
  if (!openai) throw new Error("OPENAI_API_KEY belum diatur.");
  const response = await openai.responses.create({
    model: OPENAI_MODEL,
    instructions: BOT_INSTRUCTIONS,
    input: String(text).slice(0, 6000),
    max_output_tokens: 500
  });
  return (response.output_text || "Maaf, aku belum bisa menjawab sekarang.").slice(0, 3500);
}

async function sendWhatsAppText(to, body) {
  if (!WHATSAPP_ACCESS_TOKEN || !WHATSAPP_PHONE_NUMBER_ID) {
    throw new Error("WHATSAPP_ACCESS_TOKEN atau WHATSAPP_PHONE_NUMBER_ID belum diatur.");
  }
  const url = `https://graph.facebook.com/${WHATSAPP_API_VERSION}/${WHATSAPP_PHONE_NUMBER_ID}/messages`;
  const response = await fetch(url, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${WHATSAPP_ACCESS_TOKEN}`,
      "Content-Type": "application/json"
    },
    body: JSON.stringify({
      messaging_product: "whatsapp",
      recipient_type: "individual",
      to,
      type: "text",
      text: { preview_url: false, body: String(body).slice(0, 3500) }
    })
  });
  const data = await response.json().catch(() => ({}));
  if (!response.ok) {
    console.error("WhatsApp send error:", response.status, JSON.stringify(data));
    throw new Error(`WhatsApp API gagal (${response.status}). Periksa konfigurasi/token.`);
  }
  return data;
}

app.get("/health", (_req, res) => {
  res.json({ ok: true, service: BOT_NAME, timestamp: new Date().toISOString() });
});

app.get("/webhook/whatsapp", (req, res) => {
  const mode = req.query["hub.mode"];
  const token = req.query["hub.verify_token"];
  const challenge = req.query["hub.challenge"];
  if (mode === "subscribe" && safeEqual(token, WHATSAPP_VERIFY_TOKEN)) {
    return res.status(200).send(String(challenge || ""));
  }
  return res.sendStatus(403);
});

app.post("/webhook/whatsapp", async (req, res) => {
  if (!checkMetaSignature(req)) return res.sendStatus(401);
  let payload = {};
  try {
    payload = Buffer.isBuffer(req.body) ? JSON.parse(req.body.toString("utf8")) : req.body;
  } catch {
    return res.sendStatus(400);
  }

  // Acknowledge quickly; process messages in the background.
  res.sendStatus(200);
  if (payload.object !== "whatsapp_business_account") return;

  for (const entry of payload.entry || []) {
    for (const change of entry.changes || []) {
      const value = change.value || {};
      for (const message of value.messages || []) {
        if (message.type !== "text" || !message.from || !message.text?.body) continue;
        const from = message.from;
        const text = message.text.body;
        try {
          const answer = await askAI(text);
          await sendWhatsAppText(from, answer);
        } catch (error) {
          console.error("Bot message error:", error.message);
          // Avoid exposing technical details or secrets to WhatsApp users.
          try { await sendWhatsAppText(from, "Maaf, bot sedang mengalami kendala. Coba lagi nanti."); } catch {}
        }
      }
    }
  }
});

app.get("/", dashboardAuth, (_req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

app.get("/api/status", dashboardAuth, (_req, res) => {
  res.json({
    service: BOT_NAME,
    aiConfigured: Boolean(OPENAI_API_KEY),
    whatsappConfigured: Boolean(WHATSAPP_ACCESS_TOKEN && WHATSAPP_PHONE_NUMBER_ID && WHATSAPP_VERIFY_TOKEN),
    model: OPENAI_MODEL
  });
});

app.post("/api/chat", dashboardAuth, async (req, res) => {
  const message = String(req.body?.message || "").trim();
  if (!message) return res.status(400).json({ error: "Tulis pesan terlebih dahulu." });
  if (message.length > 4000) return res.status(413).json({ error: "Pesan terlalu panjang (maksimal 4000 karakter)." });
  try {
    const answer = await askAI(message);
    res.json({ answer });
  } catch (error) {
    console.error("Dashboard AI error:", error.message);
    res.status(500).json({ error: "AI belum siap. Periksa OPENAI_API_KEY dan akses model di Environment Variables." });
  }
});

app.listen(PORT, "0.0.0.0", () => {
  console.log(`${BOT_NAME} running on port ${PORT}`);
});