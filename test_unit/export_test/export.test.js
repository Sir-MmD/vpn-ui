// Node test for web/assets/js/util/export.js — the client-side TXT/PDF account
// export. The panel UI is browserless in this harness, so instead of driving a
// real browser we load the REAL export.js (and the REAL vendored jsPDF) under
// Node with small stubs for the browser-only bits (QRious canvas, FileManager
// download, SizeFormatter/IntlUtil formatters), then assert:
//   - TXT: a boxed credential card per account, with the fields, and the xray
//     account's share-link present.
//   - PDF: output is a real %PDF; a QR image is embedded ONLY for accounts that
//     have a real share-link URI (xray), never for VPN accounts.
//   - buildCards: link is populated for xray inbounds and empty for VPN.
"use strict";
const fs = require("fs");
const path = require("path");

const REPO = path.resolve(__dirname, "..", "..");
const EXPORT_JS = path.join(REPO, "web/assets/js/util/export.js");
const JSPDF = path.join(REPO, "web/assets/jspdf/jspdf.umd.min.js");

// ---- real jsPDF (UMD -> CommonJS export in Node) ------------------------
const { jsPDF } = require(JSPDF);

// ---- capture hooks ------------------------------------------------------
let qrCount = 0;      // # of QR images embedded into the PDF
let saved = [];       // captured PDF saves {fn, bytes}
let txtCapture = null;

const origAddImage = jsPDF.API.addImage;
jsPDF.API.addImage = function (...args) { qrCount++; return origAddImage.apply(this, args); };
jsPDF.API.save = function (fn) { saved.push({ fn, bytes: this.output("arraybuffer") }); return this; };

// Real jsPDF has a strict PNG decoder, so the QRious stub must return a genuinely
// valid PNG. Build a tiny RGB PNG with Node's zlib (browser QRious builds one via
// canvas.toDataURL — same net effect: a real PNG data URL).
const zlib = require("zlib");
function makePng(size) {
  const crcTable = (() => {
    const t = [];
    for (let n = 0; n < 256; n++) {
      let c = n;
      for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
      t[n] = c >>> 0;
    }
    return t;
  })();
  const crc32 = (buf) => {
    let c = 0xffffffff;
    for (let i = 0; i < buf.length; i++) c = crcTable[(c ^ buf[i]) & 0xff] ^ (c >>> 8);
    return (c ^ 0xffffffff) >>> 0;
  };
  const chunk = (type, data) => {
    const len = Buffer.alloc(4); len.writeUInt32BE(data.length, 0);
    const t = Buffer.from(type, "latin1");
    const crc = Buffer.alloc(4); crc.writeUInt32BE(crc32(Buffer.concat([t, data])), 0);
    return Buffer.concat([len, t, data, crc]);
  };
  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(size, 0); ihdr.writeUInt32BE(size, 4);
  ihdr[8] = 8; ihdr[9] = 2; ihdr[10] = 0; ihdr[11] = 0; ihdr[12] = 0; // 8-bit RGB
  const raw = Buffer.alloc(size * (1 + size * 3)); // filter byte + RGB per row (black)
  const idat = zlib.deflateSync(raw);
  const png = Buffer.concat([
    Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]),
    chunk("IHDR", ihdr), chunk("IDAT", idat), chunk("IEND", Buffer.alloc(0)),
  ]);
  return "data:image/png;base64," + png.toString("base64");
}
const ONE_PX_PNG = makePng(8);

// ---- browser-global stubs ----------------------------------------------
global.window = { jspdf: { jsPDF } };
global.location = { hostname: "vpn.example" };
global.alert = () => {};
global.QRious = function (opts) { this.toDataURL = () => ONE_PX_PNG; };
global.FileManager = {
  downloadTextFile: (content, filename, mime) => { txtCapture = { content, filename, mime }; },
};
global.SizeFormatter = {
  sizeFormat: (b) => (b >= 1048576 ? (b / 1048576).toFixed(1) + " MB" : b + " B"),
};
global.IntlUtil = { formatDate: (ms) => new Date(ms).toISOString().slice(0, 10) };

// ---- load the real export.js and expose AccountExport ------------------
const src = fs.readFileSync(EXPORT_JS, "utf8");
(0, eval)(src + "\n;globalThis.__AccountExport = AccountExport;");
const AE = globalThis.__AccountExport;

// ---- assertion helpers --------------------------------------------------
let failures = [];
function ok(cond, msg) { if (cond) console.log("  ✓ " + msg); else { failures.push(msg); console.log("  ✗ " + msg); } }

// ---- fixtures -----------------------------------------------------------
// One xray-style card (has a real share link -> gets a QR) and one VPN card
// (no link -> no QR).
const cards = [
  {
    remark: "xray-inbound", protocol: "VLESS", network: "tcp/TLS",
    server: "1.2.3.4", port: "443", email: "alice@t", password: "",
    uuid: "11111111-2222-3333-4444-555555555555", psk: "",
    expiry: "2026-08-01", used: "20.0 MB", total: "∞", enable: true,
    link: "vless://11111111-2222-3333-4444-555555555555@1.2.3.4:443?type=tcp#alice",
  },
  {
    remark: "l2tp-inbound", protocol: "L2TP", network: "IPsec/PSK",
    server: "1.2.3.4", port: "1701", email: "bob@t", password: "s3cret",
    uuid: "", psk: "TestPSK-9182",
    expiry: "∞", used: "5.0 MB", total: "1.0 GB", enable: false,
    link: "",
  },
];

// ========================= TXT =========================
console.log("[txt]");
AE.txt(cards, "accounts");
ok(txtCapture !== null, "downloadTextFile was invoked");
ok(txtCapture && txtCapture.filename === "accounts.txt", "filename is accounts.txt");
const txt = (txtCapture && txtCapture.content) || "";
ok(txt.includes("alice@t") && txt.includes("bob@t"), "both accounts present");
ok(txt.includes("Password") && txt.includes("s3cret"), "password field rendered");
ok(txt.includes("PSK") && txt.includes("TestPSK-9182"), "PSK field rendered (l2tp)");
ok(txt.includes("═"), "boxed card style (box-drawing chars)");
ok(txt.includes("vless://11111111"), "xray share-link present in TXT");

// ========================= PDF =========================
console.log("[pdf]");
qrCount = 0; saved = [];
AE.pdf(cards, "accounts");
ok(saved.length === 1, "one PDF saved");
ok(saved.length === 1 && saved[0].fn === "accounts.pdf", "filename is accounts.pdf");
const head = saved.length ? Buffer.from(saved[0].bytes.slice(0, 5)).toString("latin1") : "";
ok(head.startsWith("%PDF"), "output is a real PDF (starts with %PDF), got " + JSON.stringify(head));
ok(qrCount === 1, "QR embedded ONLY for the xray card (1 image), got " + qrCount);

// ================== buildCards (link logic) ==================
console.log("[buildCards]");
// Minimal fake of the inbounds Vue app: an xray inbound whose genAllLinks yields
// a link, and a VPN inbound whose genAllLinks yields '' (as Inbound.genLink does).
function fakeApp() {
  const xrayInbound = {
    listen: "", settings: {}, stream: { network: "tcp", isTls: true },
    genAllLinks: () => [{ link: "vless://uuid@1.2.3.4:443#x" }],
  };
  const vpnInbound = {
    listen: "", settings: { ipsec: true, psk: "P" },
    genAllLinks: () => [{ link: "" }],  // VPN protocols return '' from genLink
  };
  const rows = {
    10: { id: 10, remark: "xray", protocol: "vless", isOpenvpn: false, isL2tp: false, isPptp: false,
          toInbound: () => xrayInbound },
    20: { id: 20, remark: "l2tp", protocol: "l2tp", isOpenvpn: false, isL2tp: true, isPptp: false,
          toInbound: () => vpnInbound },
  };
  return {
    remarkModel: "-ieo",
    dbInbounds: [rows[10], rows[20]],
    getInboundClients: (db) => db.id === 10
      ? [{ email: "x@t", password: "", id: "uuid", totalGB: 0, expiryTime: 0 }]
      : [{ email: "v@t", password: "pw", id: "vuser", totalGB: 1073741824, expiryTime: 0 }],
    getSumStats: () => 12345,
  };
}
const built = AE.buildCards(fakeApp(), [
  { inboundId: 10, email: "x@t" },
  { inboundId: 20, email: "v@t" },
]);
ok(built.length === 2, "buildCards returned a card per target");
const xc = built.find((c) => c.email === "x@t");
const vc = built.find((c) => c.email === "v@t");
ok(xc && xc.link && xc.link.startsWith("vless://"), "xray card has a share link (QR source)");
ok(vc && vc.link === "", "VPN card has no link (no QR)");
ok(vc && vc.psk === "P", "VPN (l2tp/ipsec) card carries the PSK");

// ---- verdict ------------------------------------------------------------
console.log("");
if (failures.length) {
  console.log("FAIL: " + failures.length + " assertion(s) failed:");
  failures.forEach((f) => console.log("  - " + f));
  process.exit(1);
}
console.log("PASS: export.js TXT/PDF/buildCards all good");
