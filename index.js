#!/usr/bin/env node

const http = require("http");
const express = require("express");
const { createProxyMiddleware } = require("http-proxy-middleware");
const axios = require("axios");
const os = require('os');
const fs = require("fs");
const path = require("path");
const crypto = require('crypto');
const { promisify } = require('util');
const exec = promisify(require('child_process').exec);
const { execSync } = require('child_process');

const UPLOAD_URL = process.env.UPLOAD_URL || '';      // 节点或订阅自动上传地址
const PROJECT_URL = process.env.PROJECT_URL || '';    // 需要上传订阅或保活时需填写项目分配的url
const AUTO_ACCESS = process.env.AUTO_ACCESS || false; // false关闭自动保活，true开启
const FILE_PATH = process.env.FILE_PATH || '.tmp';    // 运行目录,sub节点文件保存目录
// 【伪装修改1：修改订阅路径，防扫描】
const SUB_PATH = process.env.SUB_PATH || 'api/v2/sync';       // 订阅路径
const PORT = process.env.SERVER_PORT || process.env.PORT || 3000;        // http服务订阅端口
const UUID = process.env.UUID || '9afd1229-b893-40c1-84dd-51e7ce204913'; 
const NEZHA_SERVER = process.env.NEZHA_SERVER || '';        
const NEZHA_PORT = process.env.NEZHA_PORT || '';            
const NEZHA_KEY = process.env.NEZHA_KEY || '';              
const ARGO_DOMAIN = process.env.ARGO_DOMAIN || '';          // 固定隧道域名,留空即启用临时隧道
const ARGO_AUTH = process.env.ARGO_AUTH || '';              // 固定隧道密钥json或token
const ARGO_PORT = process.env.ARGO_PORT || 8001;            // 固定隧道端口
const S5_PORT = process.env.S5_PORT || '';                  // socks5端口
const HY2_PORT = process.env.HY2_PORT || '';                // hy2端口
const REALITY_PORT = process.env.REALITY_PORT || '';        // reality端口
const CFIP = process.env.CFIP || 'saas.sin.fan';            // 节点优选域名或优选ip
const CFPORT = process.env.CFPORT || 443;                   // 节点优选域名或优选ip对应的端口
const NAME = process.env.NAME || '';                        // 节点名称
const CHAT_ID = process.env.CHAT_ID || '';                  // Telegram chat_id 
const BOT_TOKEN = process.env.BOT_TOKEN || '';              // Telegram bot_token 
const SHOW_LOG = !['false', 'disable', 'no'].includes((process.env.SHOW_LOG || 'true').toLowerCase()); 

// 控制日志输出
if (!SHOW_LOG) {
  console.log = () => {};
  console.error = () => {};
}
function alwaysLog(msg) {
  process.stdout.write(msg + '\n');
}

// 创建运行文件夹
if (!fs.existsSync(FILE_PATH)) {
  fs.mkdirSync(FILE_PATH);
}

// 端口检查
function isValidPort(port) {
  try {
    if (port === null || port === undefined || port === '') return false;
    if (typeof port === 'string' && port.trim() === '') return false;
    const portNum = parseInt(port);
    if (isNaN(portNum)) return false;
    if (portNum < 1 || portNum > 65535) return false;
    return true;
  } catch (error) {
    return false;
  }
}

// 生成随机6位字符
function generateRandomName() {
  const characters = 'abcdefghijklmnopqrstuvwxyz';
  let result = '';
  for (let i = 0; i < 6; i++) {
    result += characters.charAt(Math.floor(Math.random() * characters.length));
  }
  return result;
}

// 全局常量
let subContent = null;
let privateKey = '';
let publicKey = '';
const npmName = generateRandomName();
const webName = generateRandomName();
const botName = generateRandomName();
const phpName = generateRandomName();
let npmPath = path.join(FILE_PATH, npmName);
let phpPath = path.join(FILE_PATH, phpName);
let webPath = path.join(FILE_PATH, webName);
let botPath = path.join(FILE_PATH, botName);
let subPath = path.join(FILE_PATH, 'sub.txt');
let listPath = path.join(FILE_PATH, 'list.txt');
let bootLogPath = path.join(FILE_PATH, 'boot.log');
let configPath = path.join(FILE_PATH, 'config.json');
let certPath = path.resolve(FILE_PATH, 'cert.pem');
let keyPath = path.resolve(FILE_PATH, 'private.key');

function deleteNodes() {
  try {
    if (!UPLOAD_URL) return;
    if (!fs.existsSync(subPath)) return;
    let fileContent;
    try { fileContent = fs.readFileSync(subPath, 'utf-8'); } catch { return null; }
    const decoded = Buffer.from(fileContent, 'base64').toString('utf-8');
    const nodes = decoded.split('\n').filter(line => /(vless|vmess|trojan|hysteria2|socks):\/\//.test(line));
    if (nodes.length === 0) return;
    axios.post(`${UPLOAD_URL}/api/delete-nodes`, JSON.stringify({ nodes }), { headers: { 'Content-Type': 'application/json' } }).catch(() => { return null; });
    return null;
  } catch (err) { return null; }
}

function cleanupOldFiles() {
  try {
    const files = fs.readdirSync(FILE_PATH);
    files.forEach(file => {
      const filePath = path.join(FILE_PATH, file);
      try {
        const stat = fs.statSync(filePath);
        if (stat.isFile()) fs.unlinkSync(filePath);
      } catch (err) {}
    });
  } catch (err) {}
}

function generateX25519Keypair() {
  const { publicKey: pubKey, privateKey: privKey } = crypto.generateKeyPairSync('x25519');
  const privateKeyRaw = privKey.export({ type: 'pkcs8', format: 'der' }).subarray(-32);
  const publicKeyRaw = pubKey.export({ type: 'spki', format: 'der' }).subarray(-32);
  return { privateKey: privateKeyRaw.toString('base64url'), publicKey: publicKeyRaw.toString('base64url') };
}

function generateOrLoadKeyPair() {
  const keyFilePath = path.join(FILE_PATH, 'key.txt');
  if (fs.existsSync(keyFilePath)) {
    const content = fs.readFileSync(keyFilePath, 'utf8');
    const privateKeyMatch = content.match(/PrivateKey:\s*(.*)/);
    const publicKeyMatch = content.match(/PublicKey:\s*(.*)/);
    if (privateKeyMatch && publicKeyMatch) {
      privateKey = privateKeyMatch[1].trim();
      publicKey = publicKeyMatch[1].trim();
      return;
    }
  }
  const keypair = generateX25519Keypair();
  privateKey = keypair.privateKey;
  publicKey = keypair.publicKey;
  fs.writeFileSync(keyFilePath, `PrivateKey: ${privateKey}\nPublicKey: ${publicKey}\n`, 'utf8');
}

const FALLBACK_EC_KEY = '-----BEGIN EC PARAMETERS-----\nBggqhkjOPQMBBw==\n-----END EC PARAMETERS-----\n-----BEGIN EC PRIVATE KEY-----\nMHcCAQEEIM4792SEtPqIt1ywqTd/0bYidBqpYV/++siNnfBYsdUYoAoGCCqGSM49\nAwEHoUQDQgAE1kHafPj07rJG+HboH2ekAI4r+e6TL38GWASANnngZreoQDF16ARa\n/TsyLyFoPkhLxSbehH/NBEjHtSZGaDhMqQ==\n-----END EC PRIVATE KEY-----\n';
const FALLBACK_CERT = '-----BEGIN CERTIFICATE-----\nMIIBejCCASGgAwIBAgIUfWeQL3556PNJLp/veCFxGNj9crkwCgYIKoZIzj0EAwIw\nEzERMA8GA1UEAwwIYmluZy5jb20wHhcNMjUwOTE4MTgyMDIyWhcNMzUwOTE2MTgy\nMDIyWjATMREwDwYDVQQDDAhiaW5nLmNvbTBZMBMGByqGSM49AgEGCCqGSM49AwEH\nA0IABNZB2nz49O6yRvh26B9npACOK/nuky9/BlgEgDZ54Ga3qEAxdegEWv07Mi8h\naD5IS8Um3oR/zQRIx7UmRmg4TKmjUzBRMB0GA1UdDgQWBBTV1cFID7UISE7PLTBR\nBfGbgkrMNzAfBgNVHSMEGDAWgBTV1cFID7UISE7PLTBRBfGbgkrMNzAPBgNVHRMB\nAf8EBTADAQH/MAoGCCqGSM49BAMCA0cAMEQCIAIDAJvg0vd/ytrQVvEcSm6XTlB+\neQ6OFb9LbLYL9f+sAiAffoMbi4y/0YUSlTtz7as9S8/lciBF5VCUoVIKS+vX2g==\n-----END CERTIFICATE-----\n';

function ensureTlsCertificates(certPath, keyPath) {
  if (fs.existsSync(certPath) && fs.existsSync(keyPath)) return;
  fs.mkdirSync(path.dirname(certPath), { recursive: true });
  try {
    execSync('openssl version', { stdio: 'ignore' });
    execSync(`openssl ecparam -genkey -name prime256v1 -out "${keyPath}"`, { stdio: 'ignore' });
    execSync(`openssl req -new -x509 -days 3650 -key "${keyPath}" -out "${certPath}" -subj "/CN=bing.com"`, { stdio: 'ignore' });
    return;
  } catch (e) { }
  fs.writeFileSync(keyPath, FALLBACK_EC_KEY);
  fs.writeFileSync(certPath, FALLBACK_CERT);
}

function getCertificateFingerprint(certPath) {
  try {
    const result = execSync(`openssl x509 -noout -fingerprint -sha256 -in "${certPath}"`, { encoding: 'utf8', timeout: 3000 }).trim();
    const match = result.match(/=(.+)$/);
    if (match && match[1]) return match[1].toUpperCase();
  } catch (e) {}
  try {
    const certData = fs.readFileSync(certPath, 'utf8');
    const derMatch = certData.match(/-----BEGIN CERTIFICATE-----([\s\S]+?)-----END CERTIFICATE-----/);
    if (!derMatch) return '';
    const derBase64 = derMatch[1].replace(/\s/g, '');
    const derBuffer = Buffer.from(derBase64, 'base64');
    const hash = crypto.createHash('sha256').update(derBuffer).digest('hex');
    return hash.match(/.{2}/g).join(':').toUpperCase();
  } catch (error) { return ''; }
}

async function generateConfig() {
  // 【伪装修改2：修改Xray底层通讯路径为常用框架路径】
  const config = {
    log: { access: '/dev/null', error: '/dev/null', loglevel: 'none' },
    inbounds: [
      { tag: 'vless-fallback-in', port: ARGO_PORT, listen: '::', protocol: 'vless', settings: { clients: [{ id: UUID, flow: 'xtls-rprx-vision' }], decryption: 'none', fallbacks: [{ dest: 3001 }, { path: "/socket.io/", dest: 3002 }, { path: "/graphql/", dest: 3003 }, { path: "/api/stream/", dest: 3004 }] }, streamSettings: { network: 'tcp' } },
      { tag: 'vless-tcp-in', port: 3001, listen: "127.0.0.1", protocol: "vless", settings: { clients: [{ id: UUID }], decryption: "none" }, streamSettings: { network: "tcp", security: "none" } },
      { tag: 'vless-ws-in', port: 3002, listen: "127.0.0.1", protocol: "vless", settings: { clients: [{ id: UUID, level: 0 }], decryption: "none" }, streamSettings: { network: "ws", security: "none", wsSettings: { path: "/socket.io/" } }, sniffing: { enabled: true, destOverride: ["http", "tls", "quic"], metadataOnly: false } },
      { tag: 'vmess-ws-in', port: 3003, listen: "127.0.0.1", protocol: "vmess", settings: { clients: [{ id: UUID, alterId: 0 }] }, streamSettings: { network: "ws", wsSettings: { path: "/graphql/" } }, sniffing: { enabled: true, destOverride: ["http", "tls", "quic"], metadataOnly: false } },
      { tag: 'trojan-ws-in', port: 3004, listen: "127.0.0.1", protocol: "trojan", settings: { clients: [{ password: UUID }] }, streamSettings: { network: "ws", security: "none", wsSettings: { path: "/api/stream/" } }, sniffing: { enabled: true, destOverride: ["http", "tls", "quic"], metadataOnly: false } },
    ],
    dns: { servers: ["https+local://8.8.8.8/dns-query"] },
    outbounds: [{ protocol: "freedom", tag: "direct" }, { protocol: "blackhole", tag: "block" }]
  };

  if (isValidPort(REALITY_PORT)) {
    config.inbounds.push({ tag: "vless-in", listen: "::", port: parseInt(REALITY_PORT), protocol: "vless", settings: { clients: [{ id: UUID, flow: "xtls-rprx-vision" }], decryption: "none" }, streamSettings: { network: "raw", security: "reality", realitySettings: { show: false, dest: "www.iij.ad.jp:443", xver: 0, serverNames: ["www.iij.ad.jp"], privateKey: privateKey, shortIds: [""] } } });
  }

  if (isValidPort(HY2_PORT)) {
    config.inbounds.push({ tag: "hysteria-in", listen: "::", port: parseInt(HY2_PORT), protocol: "hysteria", settings: { version: 2, clients: [{ auth: UUID }] }, streamSettings: { network: "hysteria", hysteriaSettings: { version: 2, masquerade: { type: "proxy", url: "https://bing.com" } }, security: "tls", tlsSettings: { alpn: ["h3"], certificates: [{ certificateFile: certPath, keyFile: keyPath }] } } });
  }

  if (isValidPort(S5_PORT)) {
    config.inbounds.push({ tag: "s5-in", listen: "::", port: parseInt(S5_PORT), protocol: "socks", settings: { auth: "password", accounts: [{ user: UUID.substring(0, 8), pass: UUID.slice(-12) }], udp: true } });
  }

  fs.writeFileSync(path.join(FILE_PATH, 'config.json'), JSON.stringify(config, null, 2));
}

function getSystemArchitecture() {
  const arch = os.arch();
  return (arch === 'arm' || arch === 'arm64' || arch === 'aarch64') ? 'arm' : 'amd';
}

function downloadFile(fileName, fileUrl, callback) {
  if (!fs.existsSync(FILE_PATH)) fs.mkdirSync(FILE_PATH, { recursive: true });
  const writer = fs.createWriteStream(fileName);
  axios({ method: 'get', url: fileUrl, responseType: 'stream' })
    .then(response => {
      response.data.pipe(writer);
      writer.on('finish', () => { writer.close(); callback(null, fileName); });
      writer.on('error', err => { fs.unlink(fileName, () => {}); callback(`Failed: ${err.message}`); });
    }).catch(err => { callback(`Failed: ${err.message}`); });
}

async function downloadFilesAndRun() {
  const architecture = getSystemArchitecture();
  const filesToDownload = getFilesForArchitecture(architecture);
  if (filesToDownload.length === 0) return;

  const downloadPromises = filesToDownload.map(fileInfo => {
    return new Promise((resolve, reject) => {
      downloadFile(fileInfo.fileName, fileInfo.fileUrl, (err, filePath) => {
        if (err) reject(err); else resolve(filePath);
      });
    });
  });

  try { await Promise.all(downloadPromises); } catch (err) { return; }

  function authorizeFiles(filePaths) {
    filePaths.forEach(absoluteFilePath => {
      if (fs.existsSync(absoluteFilePath)) fs.chmodSync(absoluteFilePath, 0o775);
    });
  }
  const filesToAuthorize = NEZHA_PORT ? [npmPath, webPath, botPath] : [phpPath, webPath, botPath];
  authorizeFiles(filesToAuthorize);

  if (NEZHA_SERVER && NEZHA_KEY) {
    if (!NEZHA_PORT) {
      const port = NEZHA_SERVER.includes(':') ? NEZHA_SERVER.split(':').pop() : '';
      const nezhatls = new Set(['443', '8443', '2096', '2087', '2083', '2053']).has(port) ? 'true' : 'false';
      const configYaml = `client_secret: ${NEZHA_KEY}\ndebug: false\ndisable_auto_update: true\ndisable_command_execute: false\ndisable_force_update: true\ndisable_nat: false\ndisable_send_query: false\ngpu: false\ninsecure_tls: true\nip_report_period: 1800\nreport_delay: 4\nserver: ${NEZHA_SERVER}\nskip_connection_count: true\nskip_procs_count: true\ntemperature: false\ntls: ${nezhatls}\nuse_gitee_to_upgrade: false\nuse_ipv6_country_code: false\nuuid: ${UUID}`;
      fs.writeFileSync(path.join(FILE_PATH, 'config.yaml'), configYaml);
      try { await exec(`nohup ${phpPath} -c "${FILE_PATH}/config.yaml" >/dev/null 2>&1 &`); await new Promise((r) => setTimeout(r, 1000)); } catch (error) {}
    } else {
      let NEZHA_TLS = ['443', '8443', '2096', '2087', '2083', '2053'].includes(NEZHA_PORT) ? '--tls' : '';
      try { await exec(`nohup ${npmPath} -s ${NEZHA_SERVER}:${NEZHA_PORT} -p ${NEZHA_KEY} ${NEZHA_TLS} --disable-auto-update --report-delay 4 --skip-conn --skip-procs >/dev/null 2>&1 &`); await new Promise((r) => setTimeout(r, 1000)); } catch (error) {}
    }
  }

  try { await exec(`nohup ${webPath} -c ${FILE_PATH}/config.json >/dev/null 2>&1 &`); await new Promise((r) => setTimeout(r, 1000)); } catch (error) {}

  if (fs.existsSync(botPath)) {
    let args = ARGO_AUTH.match(/^[A-Z0-9a-z=]{120,250}$/) ? `tunnel --edge-ip-version auto --no-autoupdate --protocol http2 run --token ${ARGO_AUTH}` : 
               ARGO_AUTH.match(/TunnelSecret/) ? `tunnel --edge-ip-version auto --config ${FILE_PATH}/tunnel.yml run` : 
               `tunnel --edge-ip-version auto --no-autoupdate --protocol http2 --logfile ${FILE_PATH}/boot.log --loglevel info --url http://localhost:${ARGO_PORT}`;
    try { await exec(`nohup ${botPath} ${args} >/dev/null 2>&1 &`); await new Promise((r) => setTimeout(r, 2000)); } catch (error) {}
  }
  await new Promise((r) => setTimeout(r, 5000));
}

function getFilesForArchitecture(architecture) {
  let baseFiles = architecture === 'arm' ? [ { fileName: webPath, fileUrl: "https://arm64.ssss.nyc.mn/web" }, { fileName: botPath, fileUrl: "https://arm64.ssss.nyc.mn/bot" } ] : [ { fileName: webPath, fileUrl: "https://amd64.ssss.nyc.mn/web" }, { fileName: botPath, fileUrl: "https://amd64.ssss.nyc.mn/bot" } ];
  if (NEZHA_SERVER && NEZHA_KEY) {
    if (NEZHA_PORT) baseFiles.unshift({ fileName: npmPath, fileUrl: architecture === 'arm' ? "https://arm64.ssss.nyc.mn/agent" : "https://amd64.ssss.nyc.mn/agent" });
    else baseFiles.unshift({ fileName: phpPath, fileUrl: architecture === 'arm' ? "https://arm64.ssss.nyc.mn/v1" : "https://amd64.ssss.nyc.mn/v1" });
  }
  return baseFiles;
}

function argoType() {
  if (!ARGO_AUTH || !ARGO_DOMAIN) return;
  if (ARGO_AUTH.includes('TunnelSecret')) {
    fs.writeFileSync(path.join(FILE_PATH, 'tunnel.json'), ARGO_AUTH);
    const tunnelYaml = `\n tunnel: ${ARGO_AUTH.split('"')[11]}\n credentials-file: ${path.join(FILE_PATH, 'tunnel.json')}\n protocol: http2\n \n ingress:\n   - hostname: ${ARGO_DOMAIN}\n     service: http://localhost:${ARGO_PORT}\n     originRequest:\n       noTLSVerify: true\n   - service: http_status:404\n `;
    fs.writeFileSync(path.join(FILE_PATH, 'tunnel.yml'), tunnelYaml);
  }
}

async function extractDomains() {
  let argoDomain;
  if (ARGO_AUTH && ARGO_DOMAIN) {
    await generateLinks(ARGO_DOMAIN);
  } else {
    try {
      const fileContent = fs.readFileSync(path.join(FILE_PATH, 'boot.log'), 'utf-8');
      const lines = fileContent.split('\n');
      const argoDomains = lines.map(line => line.match(/https?:\/\/([^ ]*trycloudflare\.com)\/?/)).filter(match => match).map(match => match[1]);
      if (argoDomains.length > 0) {
        await generateLinks(argoDomains[0]);
      } else {
        fs.unlinkSync(path.join(FILE_PATH, 'boot.log'));
        try { process.platform === 'win32' ? await exec(`taskkill /f /im ${botName}.exe > nul 2>&1`) : await exec(`pkill -f "[${botName.charAt(0)}]${botName.substring(1)}" > /dev/null 2>&1`); } catch (error) {}
        await new Promise((r) => setTimeout(r, 3000));
        try { await exec(`nohup ${botPath} tunnel --edge-ip-version auto --no-autoupdate --protocol http2 --logfile ${FILE_PATH}/boot.log --loglevel info --url http://localhost:${ARGO_PORT} >/dev/null 2>&1 &`); await new Promise((r) => setTimeout(r, 6000)); await extractDomains(); } catch (error) {}
      }
    } catch (error) {}
  }
}

async function getMetaInfo() {
  try {
    const response1 = await axios.get('https://api.ip.sb/geoip', { headers: { 'User-Agent': 'Mozilla/5.0', timeout: 3000 } });
    if (response1.data && response1.data.country_code && response1.data.isp) return `${response1.data.country_code}-${response1.data.isp}`.replace(/\s+/g, '_');
  } catch (error) {
    try {
      const response2 = await axios.get('http://ip-api.com/json', { headers: { 'User-Agent': 'Mozilla/5.0', timeout: 3000 } });
      if (response2.data && response2.data.status === 'success' && response2.data.countryCode && response2.data.org) return `${response2.data.countryCode}-${response2.data.org}`.replace(/\s+/g, '_');
    } catch (error) {}
  }
  return 'Unknown';
}

async function getServerIP() {
  let serverIP = '';
  try { serverIP = (await axios.get('http://ipv4.ip.sb', { timeout: 3000 })).data.trim(); } 
  catch (err) {
    try { serverIP = execSync('curl -sm 3 ipv4.ip.sb').toString().trim(); } 
    catch (curlErr) {
      try { serverIP = `[${(await axios.get('http://ipv6.ip.sb', { timeout: 3000 })).data.trim()}]`; } 
      catch (ipv6AxiosErr) {
        try { serverIP = `[${execSync('curl -sm 3 ipv6.ip.sb').toString().trim()}]`; } catch (ipv6CurlErr) {}
      }
    }
  }
  return serverIP;
}

// 【伪装修改3：修改客户端订阅链接中的 Path 参数】
async function generateLinks(argoDomain) {
  const ISP = await getMetaInfo();
  const nodeName = NAME ? `${NAME}-${ISP}` : ISP;
  const SERVER_IP = await getServerIP();

  return new Promise((resolve) => {
    setTimeout(() => {
      const VMESS = { v: '2', ps: `${nodeName}`, add: CFIP, port: CFPORT, id: UUID, aid: '0', scy: 'auto', net: 'ws', type: 'none', host: argoDomain, path: '/graphql/?ed=2560', tls: 'tls', sni: argoDomain, alpn: '', fp: 'firefox' };
      let subTxt = `
vless://${UUID}@${CFIP}:${CFPORT}?encryption=none&security=tls&sni=${argoDomain}&fp=firefox&type=ws&host=${argoDomain}&path=%2Fsocket.io%2F%3Fed%3D2560#${nodeName}

vmess://${Buffer.from(JSON.stringify(VMESS)).toString('base64')}

trojan://${UUID}@${CFIP}:${CFPORT}?security=tls&sni=${argoDomain}&fp=firefox&type=ws&host=${argoDomain}&path=%2Fapi%2Fstream%2F%3Fed%3D2560#${nodeName}
    `;

      if (isValidPort(HY2_PORT)) {
        const fingerprint = getCertificateFingerprint(certPath);
        const fingerprintParam = fingerprint ? `&pinSHA256=${encodeURIComponent(fingerprint)}` : '';
        subTxt += `\nhysteria2://${UUID}@${SERVER_IP}:${HY2_PORT}/?sni=www.bing.com&insecure=0&alpn=h3&obfs=none${fingerprintParam}#${nodeName}`;
      }

      if (isValidPort(REALITY_PORT)) {
        subTxt += `\nvless://${UUID}@${SERVER_IP}:${REALITY_PORT}?encryption=none&flow=xtls-rprx-vision&security=reality&sni=www.iij.ad.jp&fp=firefox&pbk=${publicKey}&type=tcp&headerType=none#${nodeName}`;
      }

      if (isValidPort(S5_PORT)) {
        const S5_AUTH = Buffer.from(`${UUID.substring(0, 8)}:${UUID.slice(-12)}`).toString('base64');
        subTxt += `\nsocks://${S5_AUTH}@${SERVER_IP}:${S5_PORT}#${nodeName}`;
      }

      fs.writeFileSync(subPath, Buffer.from(subTxt).toString('base64'));
      fs.writeFileSync(listPath, subTxt, 'utf8');
      subContent = Buffer.from(subTxt).toString('base64');
      uploadNodes();
      resolve(subTxt);
    }, 2000);
  });
}

async function uploadNodes() {
  if (UPLOAD_URL && PROJECT_URL) {
    try { await axios.post(`${UPLOAD_URL}/api/add-subscriptions`, { subscription: [`${PROJECT_URL}/${SUB_PATH}`] }, { headers: { 'Content-Type': 'application/json' } }); } catch (error) {}
  } else if (UPLOAD_URL) {
    if (!fs.existsSync(listPath)) return;
    const content = fs.readFileSync(listPath, 'utf-8');
    const nodes = content.split('\n').filter(line => /(vless|vmess|trojan|hysteria2|socks):\/\//.test(line));
    if (nodes.length === 0) return;
    try { await axios.post(`${UPLOAD_URL}/api/add-nodes`, JSON.stringify({ nodes }), { headers: { 'Content-Type': 'application/json' } }); } catch (error) {}
  }
}

function cleanFiles() {
  setTimeout(() => {
    const filesToDelete = [bootLogPath, configPath, webPath, botPath, listPath, certPath, keyPath];
    if (NEZHA_PORT) filesToDelete.push(npmPath);
    else if (NEZHA_SERVER && NEZHA_KEY) filesToDelete.push(phpPath);
    const cmd = process.platform === 'win32' ? `del /f /q ${filesToDelete.join(' ')} > nul 2>&1` : `rm -rf ${filesToDelete.join(' ')} >/dev/null 2>&1`;
    exec(cmd, () => { console.clear(); alwaysLog('App is running with Deep Camouflage'); });
  }, 90000);
}
cleanFiles();

async function sendTelegram() {
  if (!BOT_TOKEN || !CHAT_ID) return;
  try {
    const message = fs.readFileSync(subPath, 'utf8');
    const url = `https://api.telegram.org/bot${BOT_TOKEN}/sendMessage`;
    const escapedName = NAME.replace(/[_*\[\]()~`>#+=|{}.!-]/g, '\\$&');
    await axios.post(url, null, { params: { chat_id: CHAT_ID, text: `**${escapedName}节点推送**\n\`\`\`${message}\`\`\``, parse_mode: 'MarkdownV2' } });
  } catch (error) {}
}

async function AddVisitTask() {
  if (!AUTO_ACCESS || !PROJECT_URL) return;
  try { await axios.post('https://oooo.serv00.net/add-url', { url: PROJECT_URL }, { headers: { 'Content-Type': 'application/json' } }); } catch (error) {}
}

async function startserver() {
  try {
    argoType();
    deleteNodes();
    cleanupOldFiles();
    if (isValidPort(REALITY_PORT)) generateOrLoadKeyPair();
    if (isValidPort(HY2_PORT)) ensureTlsCertificates(certPath, keyPath);
    await generateConfig();
    await downloadFilesAndRun();
    await extractDomains();
    await sendTelegram();
    await AddVisitTask();
  } catch (error) {}
}
startserver().catch(() => {});

// 【伪装修改4：使用 Express 构建 Web 服务，并挂载代理组件】
const app = express();

// 订阅路由拦截：匹配隐藏路径
app.get(`/${SUB_PATH}`, (req, res) => {
  if (subContent) {
    res.setHeader('Content-Type', 'text/plain; charset=utf-8');
    res.send(subContent);
  } else {
    try {
      const fileContent = fs.readFileSync(subPath, 'utf-8');
      res.setHeader('Content-Type', 'text/plain; charset=utf-8');
      res.send(fileContent);
    } catch (err) {
      res.status(503).send('Subscription content not yet available, please try again later.');
    }
  }
});

// 根路由反代：伪装成大型真实网站 (例如 Bootstrap 官方文档)
app.use('/', createProxyMiddleware({
  target: 'https://getbootstrap.com',
  changeOrigin: true,
  ws: false, // 务必保持 false，将真正的 WebSocket 流量放行给后端的 Xray
  onProxyRes: function (proxyRes, req, res) {
    // 移除跨站限制 header，防止浏览器白屏拦截
    delete proxyRes.headers['x-frame-options'];
    delete proxyRes.headers['content-security-policy'];
  }
}));

// 启动服务器
const server = http.createServer(app);
server.listen(PORT, () => alwaysLog(`Node server is running on ${PORT} with Deep Camouflage!`));