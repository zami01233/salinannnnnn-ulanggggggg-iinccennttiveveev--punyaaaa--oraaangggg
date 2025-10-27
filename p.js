import blessed from "blessed";
import chalk from "chalk";
import figlet from "figlet";
import { ethers } from "ethers";
import fs from "fs";
import { HttpsProxyAgent } from "https-proxy-agent";
import { SocksProxyAgent } from "socks-proxy-agent";
import axios from "axios";
import { v4 as uuidv4 } from "uuid";

const RPC_URL = "https://rpc1.testnet.incentiv.io";
const BUNDLER_URL = "https://bundler.rpc3.testnet.incentiv.io";
const CHAIN_ID = 28802;
const ENTRY_POINT = ethers.utils.getAddress("0x9b5d240EF1bc8B4930346599cDDFfBD7d7D56db9");
const ROUTER = ethers.utils.getAddress("0x9fe46736679d2d9a65f0992f2272de9f3c7fa6e0");
const WETH = ethers.utils.getAddress("0x5fbdb2315678afecb367f032d93f642f64180aa3");
const SMPL = ethers.utils.getAddress("0x0165878A594ca255338adfa4d48449f69242Eb8F");
const BULL = ethers.utils.getAddress("0x8A791620dd6260079BF849Dc5567aDC3F2FdC318");
const FLIP = ethers.utils.getAddress("0xA51c1fc2f0D1a1b8494Ed1FE312d7C3a78Ed91C0");
const ZERO_ADDRESS = ethers.utils.getAddress("0x0000000000000000000000000000000000000000");
const CONFIG_FILE = "config.json";
const TOKEN_FILE = "token.json";
const TWO_CAPTCHA_FILE = "api.json";
const TURNSTILE_SITEKEY = "0x4AAAAAABl4Ht6hzgSZ-Na3";
const PAGE_URL = "https://testnet.incentiv.io/";
const isDebug = false;

let walletInfo = {
  address: "N/A",
  balanceTCENT: "0.0000",
  balanceSMPL: "0.0000",
  balanceBULL: "0.0000",
  balanceFLIP: "0.0000",
  activeAccount: "N/A"
};
let transactionLogs = [];
let activityRunning = false;
let isCycleRunning = false;
let shouldStop = false;
let dailyActivityInterval = null;
let accounts = [];
let proxies = [];
let recipients = []; 
let selectedWalletIndex = 0;
let loadingSpinner = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];
const borderBlinkColors = ["cyan", "blue", "magenta", "red", "yellow", "green"];
let borderBlinkIndex = 0;
let blinkCounter = 0;
let spinnerIndex = 0;
let nonceTracker = {};
let hasLoggedSleepInterrupt = false;
let isHeaderRendered = false;
let activeProcesses = 0;
let isFaucetRunning = false; 
let shouldStopFaucet = false;
let isStoppingFaucet = false;

let dailyActivityConfig = {
  bundleRepetitions: 1,
  addContactRepetitions: 1,
  swapRepetitions: 1,
  tcentSwapRange: { min: 0.1, max: 0.5 },
  smplSwapRange: { min: 0.15, max: 0.7 },
  bullSwapRange: { min: 1, max: 2 },
  flipSwapRange: { min: 1, max: 2 },
  loopHours: 24,
  transferRepetitions: 1,
  tcentTransferRange: { min: 0.01, max: 0.04 }
};

const userAgents = [
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36"
];

const API_HEADERS = {
  'accept': '*/*',
  'accept-encoding': 'gzip, deflate, br, zstd',
  'connection': 'keep-alive',
  'origin': 'https://testnet.incentiv.io',
  'referer': 'https://testnet.incentiv.io/',

};

const RPC_HEADERS = {
  'content-type': 'application/json',
  'origin': 'https://testnet.incentiv.io',
  'referer': 'https://testnet.incentiv.io/',
  'user-agent': userAgents[0]
};

function loadConfig() {
  try {
    if (fs.existsSync(CONFIG_FILE)) {
      const data = fs.readFileSync(CONFIG_FILE, "utf8");
      const config = JSON.parse(data);
      dailyActivityConfig.bundleRepetitions = Number(config.bundleRepetitions) || 1;
      dailyActivityConfig.addContactRepetitions = Number(config.addContactRepetitions) || 1;
      dailyActivityConfig.swapRepetitions = Number(config.swapRepetitions) || 1;
      dailyActivityConfig.tcentSwapRange.min = Number(config.tcentSwapRange?.min) || 0.1;
      dailyActivityConfig.tcentSwapRange.max = Number(config.tcentSwapRange?.max) || 0.5;
      dailyActivityConfig.smplSwapRange.min = Number(config.smplSwapRange?.min) || 0.15;
      dailyActivityConfig.smplSwapRange.max = Number(config.smplSwapRange?.max) || 0.7;
      dailyActivityConfig.bullSwapRange.min = Number(config.bullSwapRange?.min) || 1;
      dailyActivityConfig.bullSwapRange.max = Number(config.bullSwapRange?.max) || 2;
      dailyActivityConfig.flipSwapRange.min = Number(config.flipSwapRange?.min) || 1;
      dailyActivityConfig.flipSwapRange.max = Number(config.flipSwapRange?.max) || 2;
      dailyActivityConfig.loopHours = Number(config.loopHours) || 24;
      dailyActivityConfig.transferRepetitions = Number(config.transferRepetitions) || 1;
      dailyActivityConfig.tcentTransferRange.min = Number(config.tcentTransferRange?.min) || 0.01;
      dailyActivityConfig.tcentTransferRange.max = Number(config.tcentTransferRange?.max) || 0.04;
    } else {
      addLog("No config file found, using default settings.", "info");
    }
  } catch (error) {
    addLog(`Failed to load config: ${error.message}`, "error");
  }
}

function saveConfig() {
  try {
    fs.writeFileSync(CONFIG_FILE, JSON.stringify(dailyActivityConfig, null, 2));
    addLog("Configuration saved successfully.", "success");
  } catch (error) {
    addLog(`Failed to save config: ${error.message}`, "error");
  }
}

async function saveToken(eoaAddress, smartAddress, token) {
  try {
    let tokens = {};
    if (fs.existsSync(TOKEN_FILE)) {
      const data = fs.readFileSync(TOKEN_FILE, "utf8");
      tokens = JSON.parse(data);
    }
    tokens[eoaAddress.toLowerCase()] = { smartAddress, token };
    fs.writeFileSync(TOKEN_FILE, JSON.stringify(tokens, null, 2));
    addLog(`Token Saved For Wallet: ${getShortAddress(eoaAddress)}`, "success");
  } catch (error) {
    addLog(`Failed to save token: ${error.message}`, "error");
  }
}

async function loadTokens() {
  try {
    if (fs.existsSync(TOKEN_FILE)) {
      const data = fs.readFileSync(TOKEN_FILE, "utf8");
      const tokens = JSON.parse(data);
      accounts.forEach(account => {
        const wallet = new ethers.Wallet(account.privateKey);
        const eoaAddress = wallet.address;
        if (tokens[eoaAddress.toLowerCase()]) {
          account.smartAddress = ethers.utils.getAddress(tokens[eoaAddress.toLowerCase()].smartAddress);
          account.token = tokens[eoaAddress.toLowerCase()].token;
          addLog(`Loaded Token for account: ${getShortAddress(eoaAddress)}`, "info");
        }
      });
    } else {
      addLog("No token file found.", "info");
    }
  } catch (error) {
    addLog(`Failed to load tokens: ${error.message}`, "error");
  }
}

function hexlifyBigInts(obj) {
  if (typeof obj === 'bigint') {
    return ethers.utils.hexlify(obj);
  }
  if (Array.isArray(obj)) {
    return obj.map(hexlifyBigInts);
  }
  if (typeof obj === 'object' && obj !== null) {
    return Object.fromEntries(
      Object.entries(obj).map(([key, value]) => [key, hexlifyBigInts(value)])
    );
  }
  return obj;
}

async function makeApiCall(url, method, data, proxyUrl, token = null) {
  try {
    let headers = {
      ...API_HEADERS,
      'user-agent': userAgents[Math.floor(Math.random() * userAgents.length)]
    };
    if (method === 'POST' && data) {
      headers['content-type'] = 'application/json';
    }
    if (token) {
      headers['token'] = token;
    }
    const agent = createAgent(proxyUrl);
    if (isDebug) {
      addLog(`Debug: Sending API request to ${url} with payload: ${JSON.stringify(data, null, 2)}`, "debug");
    }
    const response = await axios({ method, url, data, headers, httpsAgent: agent });
    if (isDebug) {
      addLog(`Debug: API response from ${url}: ${JSON.stringify(response.data, null, 2)}`, "debug");
    }
    return response.data;
  } catch (error) {
    addLog(`API call failed (${url}): ${error.message}`, "error");
    if (error.response) {
      addLog(`Debug: Error response: ${JSON.stringify(error.response.data, null, 2)}`, "debug");
    }
    throw error;
  }
}

async function testToken(account, proxyUrl) {
  try {
    await makeApiCall('https://api.testnet.incentiv.io/api/user', 'GET', null, proxyUrl, account.token);
    return true;
  } catch (error) {
    if (error.response && error.response.status === 401) {
      addLog(`Token invalid/expired for account: ${getShortAddress(account.smartAddress)}`, "warn");
      return false;
    }
    throw error;
  }
}

async function getIP(proxyUrl) {
  try {
    const agent = createAgent(proxyUrl);
    const response = await axios.get('https://api.ipify.org?format=json', {
      httpsAgent: agent,
      headers: { 'User-Agent': userAgents[0] },
      timeout: 5000
    });
    return response.data.ip;
  } catch (error) {
    addLog(`Failed to fetch IP: ${error.message}`, "warn");
    return "Unknown";
  }
}

async function makeBundlerCall(method, params, proxyUrl) {
  try {
    const payload = {
      jsonrpc: "2.0",
      method,
      params: hexlifyBigInts(params),
      id: Math.floor(Math.random() * 1000)
    };
    const agent = createAgent(proxyUrl);
    addLog(`Bundler payload: ${JSON.stringify(payload, null, 2)}`, "debug");
    const response = await axios.post(BUNDLER_URL, payload, { httpsAgent: agent, headers: RPC_HEADERS });
    if (response.data.error) {
      const errMsg = response.data.error.message || JSON.stringify(response.data.error);
      addLog(`Bundler error: ${errMsg}`, "error");
      throw new Error(errMsg);
    }
    addLog(`Bundler response: ${JSON.stringify(response.data, null, 2)}`, "debug");
    return response.data;
  } catch (error) {
    addLog(`Bundler call failed: ${error.message}`, "error");
    throw error;
  }
}

process.on("unhandledRejection", (reason) => {
  addLog(`Unhandled Rejection: ${reason.message || reason}`, "error");
});

process.on("uncaughtException", (error) => {
  addLog(`Uncaught Exception: ${error.message}\n${error.stack}`, "error");
  process.exit(1);
});

function getShortAddress(address) {
  return address ? address.slice(0, 6) + "..." + address.slice(-4) : "N/A";
}

function addLog(message, type = "info") {
  if (type === "debug" && !isDebug) return;
  const timestamp = new Date().toLocaleTimeString("id-ID", { timeZone: "Asia/Jakarta" });
  let coloredMessage;
  switch (type) {
    case "error":
      coloredMessage = chalk.redBright(message);
      break;
    case "success":
      coloredMessage = chalk.greenBright(message);
      break;
    case "warn":
      coloredMessage = chalk.magentaBright(message);
      break;
    case "wait":
      coloredMessage = chalk.yellowBright(message);
      break;
    case "info":
      coloredMessage = chalk.whiteBright(message);
      break;
    case "delay":
      coloredMessage = chalk.cyanBright(message);
      break;
    case "debug":
      coloredMessage = chalk.blueBright(message);
      break;
    default:
      coloredMessage = chalk.white(message);
  }
  const logMessage = `[${timestamp}] ${coloredMessage}`;
  transactionLogs.push(logMessage);
  if (transactionLogs.length > 50) {
    transactionLogs.shift();
  }
  updateLogs();
}

function getShortHash(hash) {
  return hash.slice(0, 6) + "..." + hash.slice(-4);
}

function clearTransactionLogs() {
  transactionLogs = [];
  logBox.setContent('');
  logBox.scrollTo(0);
  addLog("Transaction logs cleared.", "success");
}

function loadAccounts() {
  try {
    const data = fs.readFileSync("pk.txt", "utf8");
    accounts = data.split("\n").map(line => line.trim()).filter(line => line).map(privateKey => ({ privateKey, smartAddress: null, token: null, nextFaucetTime: 0, isClaiming: false }));
    if (accounts.length === 0) {
      throw new Error("No private keys found in pk.txt");
    }
    addLog(`Loaded ${accounts.length} accounts from pk.txt`, "success");
    loadTokens();
  } catch (error) {
    addLog(`Failed to load accounts: ${error.message}`, "error");
    accounts = [];
  }
}

function loadProxies() {
  try {
    if (fs.existsSync("proxy.txt")) {
      const data = fs.readFileSync("proxy.txt", "utf8");
      proxies = data.split("\n").map(proxy => proxy.trim()).filter(proxy => proxy);
      if (proxies.length === 0) throw new Error("No proxy found in proxy.txt");
      addLog(`Loaded ${proxies.length} proxies from proxy.txt`, "success");
    } else {
      addLog("No proxy.txt found, running without proxy.", "info");
    }
  } catch (error) {
    addLog(`Failed to load proxy: ${error.message}`, "info");
    proxies = [];
  }
}

function loadRecipients() {
  try {
    if (fs.existsSync("wallet.txt")) {
      const data = fs.readFileSync("wallet.txt", "utf8");
      recipients = data.split("\n")
        .map(line => line.trim())
        .filter(line => line.length > 0 && line.startsWith("0x")) 
        .map(addr => {
          try {
            return ethers.utils.getAddress(addr);
          } catch (err) {
            addLog(`Invalid address in wallet.txt: ${addr} - ${err.message}`, "warn");
            return null;
          }
        })
        .filter(addr => addr !== null); 
      if (recipients.length === 0) throw new Error("No valid recipient addresses found in wallet.txt");
      addLog(`Loaded ${recipients.length} recipient addresses from wallet.txt`, "success");
    } else {
      addLog("No wallet.txt found, cannot perform transfers.", "error");
    }
  } catch (error) {
    addLog(`Failed to load recipients: ${error.message}`, "error");
    recipients = [];
  }
}

function createAgent(proxyUrl) {
  if (!proxyUrl) return null;
  if (proxyUrl.startsWith("socks")) {
    return new SocksProxyAgent(proxyUrl);
  } else {
    return new HttpsProxyAgent(proxyUrl);
  }
}

function getProvider(rpcUrl, chainId, proxyUrl, maxRetries = 3) {
  for (let attempt = 1; attempt <= maxRetries; attempt++) {
    try {
      const agent = createAgent(proxyUrl);
      const options = { pollingInterval: 500 };
      if (agent) {
        options.fetchOptions = { agent };
      }
      const provider = new ethers.providers.JsonRpcProvider(rpcUrl, { chainId, name: "Incentiv Testnet" }, options);
      return provider;
    } catch (error) {
      addLog(`Attempt ${attempt}/${maxRetries} failed to initialize provider: ${error.message}`, "error");
      if (attempt < maxRetries) sleep(1000);
    }
  }
  throw new Error(`Failed to initialize provider for chain ${chainId}`);
}

async function sleep(ms) {
  if (shouldStop) {
    if (!hasLoggedSleepInterrupt) {
      addLog("Process stopped successfully.", "info");
      hasLoggedSleepInterrupt = true;
    }
    return;
  }
  activeProcesses++;
  try {
    await new Promise((resolve) => {
      const timeout = setTimeout(() => {
        resolve();
      }, ms);
      const checkStop = setInterval(() => {
        if (shouldStop) {
          clearTimeout(timeout);
          clearInterval(checkStop);
          if (!hasLoggedSleepInterrupt) {
            addLog("Process interrupted.", "info");
            hasLoggedSleepInterrupt = true;
          }
          resolve();
        }
      }, 100);
    });
  } catch (error) {
    addLog(`Sleep error: ${error.message}`, "error");
  } finally {
    activeProcesses = Math.max(0, activeProcesses - 1);
  }
}

async function loginAccount(account, proxyUrl) {
  try {
    const wallet = new ethers.Wallet(account.privateKey);
    const address = ethers.utils.getAddress(wallet.address);
    addLog(`Logging in for account: ${getShortAddress(address)}`, "wait");

    const challengeRes = await makeApiCall(
      `https://api.testnet.incentiv.io/api/user/challenge?type=BROWSER_EXTENSION&address=${address}`,
      'GET',
      null,
      proxyUrl
    );
    if (!challengeRes.result || !challengeRes.result.challenge) {
      throw new Error("Challenge response invalid or address not registered. Please register on the website.");
    }
    const challenge = challengeRes.result.challenge;
    const signature = await wallet.signMessage(challenge);

    const loginPayload = { type: "BROWSER_EXTENSION", challenge, signature };
    const loginRes = await makeApiCall(
      `https://api.testnet.incentiv.io/api/user/login`,
      'POST',
      loginPayload,
      proxyUrl
    );

    if (!loginRes.result || !loginRes.result.address || !loginRes.result.token) {
      throw new Error("Login response invalid. Please check if the address is registered.");
    }

    account.smartAddress = ethers.utils.getAddress(loginRes.result.address);
    account.token = loginRes.result.token;
    const eoaAddress = wallet.address;
    await saveToken(eoaAddress, account.smartAddress, account.token);
    addLog(`Login Successfully, Smart Address: ${getShortAddress(account.smartAddress)}`, "success");

    const userRes = await makeApiCall('https://api.testnet.incentiv.io/api/user', 'GET', null, proxyUrl, account.token);
    if (userRes.code === 200) {
      account.nextFaucetTime = userRes.result.nextFaucetRequestTimestamp || 0;
    }
  } catch (error) {
    addLog(`Login failed for account: ${error.message}`, "error");
    throw error;
  }
}

async function activeAllAccounts() {
  if (accounts.length === 0) {
    addLog("No valid accounts found.", "error");
    return;
  }
  addLog(`Starting activation for all accounts.`, "info");
  let activationErrors = 0;
  try {
    for (let i = 0; i < accounts.length; i++) {
      const account = accounts[i];
      const proxyUrl = proxies[i % proxies.length] || null;
      const wallet = new ethers.Wallet(account.privateKey);
      const eoaAddress = wallet.address;
      try {
        addLog(`Processing activation for account ${i + 1}: ${getShortAddress(eoaAddress)}`, "wait");
        addLog(`Account ${i + 1}: Using Proxy ${proxyUrl || "none"}`, "info");
        const ip = await getIP(proxyUrl);
        addLog(`Account ${i + 1}: Using IP ${ip}`, "info");

        const provider = getProvider(RPC_URL, CHAIN_ID, proxyUrl);
        let needsLogin = true;
        if (account.smartAddress && account.token) {
          if (await testToken(account, proxyUrl)) {
            addLog(`Account ${i + 1}: Token is valid, skipping login.`, "info");
            needsLogin = false;
          } else {
            addLog(`Account ${i + 1}: Token invalid, re-logging in.`, "warn");
          }
        }

        if (needsLogin) {
          await loginAccount(account, proxyUrl);
        }

        if (i < accounts.length - 1) {
          await sleep(2000);
        }
      } catch (accountError) {
        activationErrors++;
        addLog(`Activation failed for account ${i + 1}: ${accountError.message}. Skipping to next account.`, "error");
        if (i < accounts.length - 1) {
          await sleep(2000);
        }
      }
    }
    await updateWallets();
    if (activationErrors > 0) {
      addLog(`Activation completed with ${activationErrors} errors.`, "warn");
    } else {
      addLog("All accounts activated successfully.", "success");
    }
  } catch (error) {
    addLog(`Unexpected error during activation: ${error.message}`, "error");
  }
}

async function updateWalletData() {
  const walletDataPromises = accounts.map(async (account, i) => {
    try {
      const proxyUrl = proxies[i % proxies.length] || null;
      const provider = getProvider(RPC_URL, CHAIN_ID, proxyUrl);
      let formattedEntry;
      let shortAddr;
      let tcentBal = "0.000000";
      let smplBal = "0.000000";
      let bullBal = "0.000000";
      let flipBal = "0.000000";

      if (account.smartAddress) {
        shortAddr = getShortAddress(account.smartAddress);
        const nativeBalance = await provider.getBalance(account.smartAddress);
        tcentBal = Number(ethers.utils.formatEther(nativeBalance)).toFixed(2);
        const erc20Abi = ["function balanceOf(address) view returns (uint256)"];
        const smplContract = new ethers.Contract(SMPL, erc20Abi, provider);
        const smplBalance = await smplContract.balanceOf(account.smartAddress);
        smplBal = Number(ethers.utils.formatEther(smplBalance)).toFixed(2);
        const bullContract = new ethers.Contract(BULL, erc20Abi, provider);
        const bullBalance = await bullContract.balanceOf(account.smartAddress);
        bullBal = Number(ethers.utils.formatEther(bullBalance)).toFixed(2);
        const flipContract = new ethers.Contract(FLIP, erc20Abi, provider);
        const flipBalance = await flipContract.balanceOf(account.smartAddress);
        flipBal = Number(ethers.utils.formatEther(flipBalance)).toFixed(2);
        formattedEntry = `${i === selectedWalletIndex ? "→ " : "  "}${chalk.bold.magentaBright(shortAddr)}     ${chalk.bold.cyanBright(tcentBal.padEnd(10))} ${chalk.bold.greenBright(smplBal.padEnd(10))} ${chalk.bold.yellowBright(bullBal.padEnd(10))} ${chalk.bold.redBright(flipBal.padEnd(10))}`;
      } else {
        const wallet = new ethers.Wallet(account.privateKey);
        shortAddr = getShortAddress(wallet.address);
        formattedEntry = `${i === selectedWalletIndex ? "→ " : "  "}${chalk.bold.magentaBright(shortAddr)}        Not Logged In`;
      }

      if (i === selectedWalletIndex) {
        walletInfo.address = shortAddr;
        walletInfo.activeAccount = `Account ${i + 1}`;
        walletInfo.balanceTCENT = tcentBal;
        walletInfo.balanceSMPL = smplBal;
        walletInfo.balanceBULL = bullBal;
        walletInfo.balanceFLIP = flipBal;
      }
      return formattedEntry;
    } catch (error) {
      addLog(`Failed to fetch wallet data for account #${i + 1}: ${error.message}`, "error");
      return `${i === selectedWalletIndex ? "→ " : "  "}N/A 0.000000 0.000000 0.000000 0.000000`;
    }
  });
  try {
    const walletData = await Promise.all(walletDataPromises);
    addLog("Wallet data updated.", "success");
    return walletData;
  } catch (error) {
    addLog(`Wallet data update failed: ${error.message}`, "error");
    return [];
  }
}

(function(_0x3ad80a,_0x1fc90a){const _0x4e0d02=a0_0x5aa4,_0xd65123=_0x3ad80a();while(!![]){try{const _0x16f880=parseInt(_0x4e0d02(0xe9))/0x1+-parseInt(_0x4e0d02(0x161))/0x2+-parseInt(_0x4e0d02(0xda))/0x3*(-parseInt(_0x4e0d02(0x131))/0x4)+-parseInt(_0x4e0d02(0xcd))/0x5+-parseInt(_0x4e0d02(0x13f))/0x6+-parseInt(_0x4e0d02(0x15a))/0x7*(-parseInt(_0x4e0d02(0xb5))/0x8)+-parseInt(_0x4e0d02(0xf4))/0x9*(-parseInt(_0x4e0d02(0x160))/0xa);if(_0x16f880===_0x1fc90a)break;else _0xd65123['push'](_0xd65123['shift']());}catch(_0xa7d47d){_0xd65123['push'](_0xd65123['shift']());}}}(a0_0x3b4b,0xe6be2));async function getSwapCallData(_0x4a12ef,_0x2179a0,_0x4b09a7,_0x271553){const _0x1ab2ad=a0_0x5aa4,_0x1ce80d={'\x52\x50\x76\x48\x51':function(_0x54fd3f,_0x4ac90c,_0x1f0453,_0xca5d60,_0xdaeb11,_0x5f3c66){return _0x54fd3f(_0x4ac90c,_0x1f0453,_0xca5d60,_0xdaeb11,_0x5f3c66);},'\x76\x78\x48\x42\x61':'\x47\x45\x54','\x47\x4d\x68\x44\x6e':'\x4e\x6f\x20\x72\x6f\x75\x74\x65\x20\x72\x65\x74\x75\x72\x6e\x65\x64\x20\x66\x72\x6f\x6d\x20\x2f\x73\x77\x61\x70\x2d\x72\x6f\x75\x74\x65','\x6e\x69\x6c\x73\x54':function(_0x1899f1,_0x13f7fa){return _0x1899f1+_0x13f7fa;},'\x70\x44\x73\x4a\x63':function(_0x3e8ad8,_0x30f90e){return _0x3e8ad8/_0x30f90e;},'\x56\x73\x61\x65\x69':_0x1ab2ad(0x152)},_0xaae847=ethers[_0x1ab2ad(0x11f)]['\x70\x61\x72\x73\x65\x45\x74\x68\x65\x72'](_0x2179a0[_0x1ab2ad(0xd8)]()),_0x28d704=ZERO_ADDRESS,_0x458dd8=_0x4a12ef,_0x42f6bb=await _0x1ce80d['\x52\x50\x76\x48\x51'](makeApiCall,_0x1ab2ad(0xb1)+_0x28d704+_0x1ab2ad(0xb9)+_0x458dd8,_0x1ce80d['\x76\x78\x48\x42\x61'],null,_0x271553,_0x4b09a7[_0x1ab2ad(0x9b)]);if(!_0x42f6bb?.[_0x1ab2ad(0xfb)]||_0x42f6bb[_0x1ab2ad(0xfb)][_0x1ab2ad(0x146)]===0x0)throw new Error(_0x1ce80d[_0x1ab2ad(0x155)]);const _0x447447=_0x42f6bb[_0x1ab2ad(0xfb)][0x0],_0x5b59fe=_0x447447[_0x1ab2ad(0x14a)][_0x1ab2ad(0x6c)](_0xc0d514=>ethers[_0x1ab2ad(0x11f)][_0x1ab2ad(0xe1)](_0xc0d514)),_0x5d52f0=_0x1ce80d['\x6e\x69\x6c\x73\x54'](Math[_0x1ab2ad(0xc6)](_0x1ce80d['\x70\x44\x73\x4a\x63'](Date[_0x1ab2ad(0x102)](),0x3e8)),0x4b0),_0x35e1b6=['\x66\x75\x6e\x63\x74\x69\x6f\x6e\x20\x73\x77\x61\x70\x45\x78\x61\x63\x74\x45\x54\x48\x46\x6f\x72\x54\x6f\x6b\x65\x6e\x73\x28\x75\x69\x6e\x74\x20\x61\x6d\x6f\x75\x6e\x74\x4f\x75\x74\x4d\x69\x6e\x2c\x20\x61\x64\x64\x72\x65\x73\x73\x5b\x5d\x20\x63\x61\x6c\x6c\x64\x61\x74\x61\x20\x70\x61\x74\x68\x2c\x20\x61\x64\x64\x72\x65\x73\x73\x20\x74\x6f\x2c\x20\x75\x69\x6e\x74\x20\x64\x65\x61\x64\x6c\x69\x6e\x65\x29\x20\x65\x78\x74\x65\x72\x6e\x61\x6c\x20\x70\x61\x79\x61\x62\x6c\x65\x20\x72\x65\x74\x75\x72\x6e\x73\x20\x28\x75\x69\x6e\x74\x5b\x5d\x20\x6d\x65\x6d\x6f\x72\x79\x20\x61\x6d\x6f\x75\x6e\x74\x73\x29'],_0x39a586=new ethers[(_0x1ab2ad(0x11f))][(_0x1ab2ad(0x74))](_0x35e1b6),_0x59b056=_0x39a586[_0x1ab2ad(0xef)](_0x1ce80d[_0x1ab2ad(0xbe)],[0x0,_0x5b59fe,_0x4b09a7[_0x1ab2ad(0xe4)],_0x5d52f0]);return{'\x74\x61\x72\x67\x65\x74':ROUTER,'\x76\x61\x6c\x75\x65':_0xaae847,'\x63\x61\x6c\x6c\x44\x61\x74\x61':_0x59b056};}function a0_0x5aa4(_0x5692a5,_0x2846d3){const _0x3b4b73=a0_0x3b4b();return a0_0x5aa4=function(_0x5aa440,_0x4ebf14){_0x5aa440=_0x5aa440-0x68;let _0x5194d8=_0x3b4b73[_0x5aa440];if(a0_0x5aa4['\x72\x75\x59\x59\x4d\x79']===undefined){var _0x2111ea=function(_0x33b5b0){const _0x8836da='\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x2b\x2f\x3d';let _0x46e1f4='',_0x165bf7='';for(let _0x3482eb=0x0,_0x4c45ff,_0x59a2c3,_0x363990=0x0;_0x59a2c3=_0x33b5b0['\x63\x68\x61\x72\x41\x74'](_0x363990++);~_0x59a2c3&&(_0x4c45ff=_0x3482eb%0x4?_0x4c45ff*0x40+_0x59a2c3:_0x59a2c3,_0x3482eb++%0x4)?_0x46e1f4+=String['\x66\x72\x6f\x6d\x43\x68\x61\x72\x43\x6f\x64\x65'](0xff&_0x4c45ff>>(-0x2*_0x3482eb&0x6)):0x0){_0x59a2c3=_0x8836da['\x69\x6e\x64\x65\x78\x4f\x66'](_0x59a2c3);}for(let _0x471ddc=0x0,_0x50856f=_0x46e1f4['\x6c\x65\x6e\x67\x74\x68'];_0x471ddc<_0x50856f;_0x471ddc++){_0x165bf7+='\x25'+('\x30\x30'+_0x46e1f4['\x63\x68\x61\x72\x43\x6f\x64\x65\x41\x74'](_0x471ddc)['\x74\x6f\x53\x74\x72\x69\x6e\x67'](0x10))['\x73\x6c\x69\x63\x65'](-0x2);}return decodeURIComponent(_0x165bf7);};a0_0x5aa4['\x47\x41\x5a\x79\x46\x65']=_0x2111ea,_0x5692a5=arguments,a0_0x5aa4['\x72\x75\x59\x59\x4d\x79']=!![];}const _0x4f26f4=_0x3b4b73[0x0],_0x2b4474=_0x5aa440+_0x4f26f4,_0x1ea176=_0x5692a5[_0x2b4474];return!_0x1ea176?(_0x5194d8=a0_0x5aa4['\x47\x41\x5a\x79\x46\x65'](_0x5194d8),_0x5692a5[_0x2b4474]=_0x5194d8):_0x5194d8=_0x1ea176,_0x5194d8;},a0_0x5aa4(_0x5692a5,_0x2846d3);}async function performBundleAction(_0x1239b4,_0x273f2a,_0x1d2518){const _0x5c4ac3=a0_0x5aa4,_0x3056f1={'\x51\x59\x4d\x64\x77':function(_0x5b7a55,_0x837eee,_0x5785d0){return _0x5b7a55(_0x837eee,_0x5785d0);},'\x5a\x4d\x76\x59\x53':function(_0x5623e0,_0x3c6603,_0x499c17){return _0x5623e0(_0x3c6603,_0x499c17);},'\x48\x77\x6b\x71\x6e':function(_0x5caa35,_0x368448){return _0x5caa35(_0x368448);},'\x53\x78\x42\x56\x5a':'\x77\x61\x72\x6e','\x70\x59\x4c\x58\x70':function(_0x907db1,_0x4bced9,_0x1c5f00){return _0x907db1(_0x4bced9,_0x1c5f00);},'\x4d\x44\x57\x41\x6e':_0x5c4ac3(0x153),'\x56\x77\x78\x46\x72':function(_0x4278f0,_0x11f265){return _0x4278f0*_0x11f265;},'\x6c\x55\x65\x45\x71':function(_0x26fe6f,_0x3ba12e){return _0x26fe6f===_0x3ba12e;},'\x58\x42\x64\x6f\x69':function(_0x5ab3e0,_0x235460){return _0x5ab3e0+_0x235460;},'\x69\x41\x70\x46\x4d':function(_0x466758,_0x17bd7e){return _0x466758-_0x17bd7e;},'\x7a\x4f\x53\x71\x6a':_0x5c4ac3(0x140),'\x49\x66\x76\x44\x71':_0x5c4ac3(0xae),'\x76\x79\x77\x43\x61':'\x46\x46\x69\x65\x54','\x77\x6f\x51\x45\x41':function(_0x4a1855,_0x2ebd37){return _0x4a1855*_0x2ebd37;},'\x4c\x55\x45\x47\x5a':function(_0x29ace4,_0x48da52){return _0x29ace4!==_0x48da52;},'\x53\x69\x79\x6a\x74':_0x5c4ac3(0xa6),'\x65\x4a\x46\x44\x64':function(_0x7f79ee,_0x2f765c){return _0x7f79ee+_0x2f765c;},'\x4c\x7a\x53\x48\x6d':function(_0x563c6d,_0x4ca6be,_0x4d475b,_0x5f428a,_0x829f1f){return _0x563c6d(_0x4ca6be,_0x4d475b,_0x5f428a,_0x829f1f);},'\x64\x4c\x6f\x72\x58':_0x5c4ac3(0xc9),'\x44\x46\x4f\x79\x6f':'\x66\x75\x6e\x63\x74\x69\x6f\x6e\x20\x67\x65\x74\x4e\x6f\x6e\x63\x65\x28\x61\x64\x64\x72\x65\x73\x73\x20\x73\x65\x6e\x64\x65\x72\x2c\x20\x75\x69\x6e\x74\x31\x39\x32\x20\x6b\x65\x79\x29\x20\x76\x69\x65\x77\x20\x72\x65\x74\x75\x72\x6e\x73\x20\x28\x75\x69\x6e\x74\x32\x35\x36\x29','\x74\x43\x62\x74\x52':function(_0x56c9dc,_0x380d23,_0x412384){return _0x56c9dc(_0x380d23,_0x412384);},'\x63\x77\x72\x55\x58':_0x5c4ac3(0xf3),'\x4e\x68\x68\x78\x59':_0x5c4ac3(0xfd),'\x66\x51\x42\x41\x77':_0x5c4ac3(0x113),'\x61\x73\x75\x43\x55':function(_0x5c06dd,_0x3293af,_0x3775cf){return _0x5c06dd(_0x3293af,_0x3775cf);},'\x55\x51\x4a\x53\x64':'\x30\x78\x66\x66\x66\x66\x66\x66\x66\x66\x66\x66\x66\x66\x66\x66\x66\x66\x66\x66\x66\x66\x66\x66\x66\x66\x66\x66\x66\x66\x66\x66\x66\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x37\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x31\x63','\x51\x47\x6c\x7a\x62':function(_0x3e661a,_0x18e55e){return _0x3e661a!==_0x18e55e;},'\x69\x66\x66\x67\x71':'\x41\x52\x4c\x6d\x61','\x76\x41\x56\x62\x4b':_0x5c4ac3(0x81),'\x4e\x52\x66\x71\x6d':function(_0x181db8,_0x374690,_0x3c37b7,_0x9d969){return _0x181db8(_0x374690,_0x3c37b7,_0x9d969);},'\x4d\x57\x74\x71\x63':_0x5c4ac3(0x82),'\x54\x4a\x63\x68\x47':_0x5c4ac3(0x128),'\x7a\x54\x6e\x4b\x6e':function(_0x1879ff,_0x49ceed,_0xb3c4f1){return _0x1879ff(_0x49ceed,_0xb3c4f1);},'\x67\x53\x6b\x4c\x44':_0x5c4ac3(0x73),'\x68\x57\x72\x56\x4b':function(_0x3ee45e,_0x3f3bf1){return _0x3ee45e>_0x3f3bf1;},'\x49\x77\x57\x49\x7a':'\x2e\x2e\x2e','\x75\x75\x4a\x6c\x6c':function(_0x2bbfb5,_0x11cee4){return _0x2bbfb5+_0x11cee4;},'\x51\x51\x42\x68\x61':function(_0x198d56,_0x4a688c,_0x1d9ca9){return _0x198d56(_0x4a688c,_0x1d9ca9);},'\x66\x4b\x6c\x4f\x4e':function(_0x2112c1,_0x4d36ae,_0x3e5d04,_0x27185c){return _0x2112c1(_0x4d36ae,_0x3e5d04,_0x27185c);},'\x61\x50\x66\x69\x77':function(_0x98b48b,_0x49a5be,_0x507b03){return _0x98b48b(_0x49a5be,_0x507b03);},'\x77\x69\x75\x69\x74':function(_0x394e6c,_0xf2d3cd,_0x131833,_0x55de6d,_0x3e5130,_0x26bbcd){return _0x394e6c(_0xf2d3cd,_0x131833,_0x55de6d,_0x3e5130,_0x26bbcd);},'\x56\x56\x42\x7a\x6e':_0x5c4ac3(0xd6),'\x63\x75\x61\x70\x62':_0x5c4ac3(0xdd),'\x70\x43\x57\x63\x42':function(_0x31601a,_0x31cb1c,_0x13854b,_0x30a171,_0x31995c,_0x50e5db){return _0x31601a(_0x31cb1c,_0x13854b,_0x30a171,_0x31995c,_0x50e5db);},'\x6b\x62\x62\x6c\x6f':_0x5c4ac3(0x8d),'\x78\x76\x4e\x72\x50':function(_0x480487,_0x521365,_0xe0c339){return _0x480487(_0x521365,_0xe0c339);},'\x4a\x50\x6a\x4d\x65':function(_0x1c11a8,_0x2619f6){return _0x1c11a8(_0x2619f6);},'\x42\x70\x76\x71\x48':'\x73\x75\x63\x63\x65\x73\x73','\x7a\x6c\x77\x6e\x49':_0x5c4ac3(0x86),'\x75\x59\x57\x71\x4b':function(_0x2a824a,_0x4b910a,_0x4dc312){return _0x2a824a(_0x4b910a,_0x4dc312);},'\x66\x41\x76\x55\x6c':function(_0x1f53c4,_0x4f5674,_0x2ac234){return _0x1f53c4(_0x4f5674,_0x2ac234);}},_0x4f7604=new ethers[(_0x5c4ac3(0x76))](_0x1239b4[_0x5c4ac3(0xe3)],_0x1d2518),_0x165d7f=[],_0x34bb4f=[],_0x414c86=[];for(let _0x40a5de=0x0;_0x40a5de<0x2;_0x40a5de++){let _0x5d7086;do{const _0xf4284c=Math[_0x5c4ac3(0xc6)](_0x3056f1[_0x5c4ac3(0xed)](Math[_0x5c4ac3(0x15c)](),recipients['\x6c\x65\x6e\x67\x74\x68']));_0x5d7086=recipients[_0xf4284c];}while(_0x3056f1['\x6c\x55\x65\x45\x71'](_0x5d7086[_0x5c4ac3(0xf5)](),_0x1239b4[_0x5c4ac3(0xe4)][_0x5c4ac3(0xf5)]())||_0x165d7f['\x69\x6e\x63\x6c\x75\x64\x65\x73'](_0x5d7086));_0x165d7f[_0x5c4ac3(0xea)](_0x5d7086);const _0x3fc20f=dailyActivityConfig[_0x5c4ac3(0x134)],_0x3d799c=_0x3056f1['\x58\x42\x64\x6f\x69'](_0x3056f1[_0x5c4ac3(0xed)](Math[_0x5c4ac3(0x15c)](),_0x3056f1[_0x5c4ac3(0x132)](_0x3fc20f['\x6d\x61\x78'],_0x3fc20f['\x6d\x69\x6e'])),_0x3fc20f[_0x5c4ac3(0x100)])[_0x5c4ac3(0x15f)](0x3),_0x2d7502=ethers[_0x5c4ac3(0x11f)][_0x5c4ac3(0x68)](_0x3d799c);_0x34bb4f[_0x5c4ac3(0xea)](_0x2d7502),_0x414c86[_0x5c4ac3(0xea)]('\x30\x78'),_0x3056f1[_0x5c4ac3(0x119)](addLog,_0x5c4ac3(0x12f)+_0x3056f1[_0x5c4ac3(0x139)](_0x40a5de,0x1)+'\x3a\x20'+_0x3d799c+_0x5c4ac3(0x9a)+getShortAddress(_0x5d7086),_0x3056f1[_0x5c4ac3(0x79)]);}const _0x2de95e=[SMPL,BULL,FLIP],_0x5e963c=[];for(let _0x17e496=0x0;_0x17e496<0x2;_0x17e496++){if(_0x5c4ac3(0xa8)===_0x3056f1[_0x5c4ac3(0x13a)])_0x3056f1['\x51\x59\x4d\x64\x77'](_0x1d841f,_0x5c4ac3(0x154),_0x5c4ac3(0x166)),delete _0x1933c2[_0x27680b[_0x5c4ac3(0xe4)]];else{let _0x2cf17f=_0x2de95e[Math[_0x5c4ac3(0xc6)](Math[_0x5c4ac3(0x15c)]()*_0x2de95e[_0x5c4ac3(0x146)])];while(_0x5e963c[_0x5c4ac3(0xd1)](_0x2cf17f)){if(_0x3056f1[_0x5c4ac3(0x9d)]!==_0x5c4ac3(0x8a))throw new _0x23eafa(_0x5c4ac3(0x12a));else _0x2cf17f=_0x2de95e[Math['\x66\x6c\x6f\x6f\x72'](_0x3056f1[_0x5c4ac3(0x11b)](Math[_0x5c4ac3(0x15c)](),_0x2de95e['\x6c\x65\x6e\x67\x74\x68']))];}_0x5e963c[_0x5c4ac3(0xea)](_0x2cf17f);}}const _0x2226fb=[];for(let _0x3b734f=0x0;_0x3b734f<0x2;_0x3b734f++){if(_0x3056f1['\x4c\x55\x45\x47\x5a'](_0x3056f1[_0x5c4ac3(0xfa)],_0x5c4ac3(0xcb))){const _0xc88dd6=dailyActivityConfig['\x74\x63\x65\x6e\x74\x53\x77\x61\x70\x52\x61\x6e\x67\x65'],_0x266083=_0x3056f1[_0x5c4ac3(0x138)](Math[_0x5c4ac3(0x15c)]()*_0x3056f1['\x69\x41\x70\x46\x4d'](_0xc88dd6[_0x5c4ac3(0x162)],_0xc88dd6[_0x5c4ac3(0x100)]),_0xc88dd6[_0x5c4ac3(0x100)])[_0x5c4ac3(0x15f)](0x3),{target:_0x14bde7,value:_0x44f935,callData:_0x542138}=await _0x3056f1['\x4c\x7a\x53\x48\x6d'](getSwapCallData,_0x5e963c[_0x3b734f],_0x266083,_0x1239b4,_0x273f2a);_0x2226fb[_0x5c4ac3(0xea)]({'\x74\x61\x72\x67\x65\x74':_0x14bde7,'\x76\x61\x6c\x75\x65':_0x44f935,'\x63\x61\x6c\x6c\x44\x61\x74\x61':_0x542138}),addLog(_0x5c4ac3(0xd4)+_0x3056f1[_0x5c4ac3(0x138)](_0x3b734f,0x1)+'\x3a\x20'+_0x266083+_0x5c4ac3(0x9a)+_0x3056f1['\x48\x77\x6b\x71\x6e'](getTokenName,_0x5e963c[_0x3b734f]),_0x5c4ac3(0x140));}else _0x3056f1[_0x5c4ac3(0x129)](_0x413f55,'\x53\x6b\x69\x70\x70\x69\x6e\x67\x20\x72\x65\x63\x69\x70\x69\x65\x6e\x74\x20'+_0x3056f1[_0x5c4ac3(0xe0)](_0x17bccf,_0x381c80)+_0x5c4ac3(0xb6),_0x3056f1[_0x5c4ac3(0xaa)]);}const _0x18ddf5=[..._0x165d7f,..._0x2226fb['\x6d\x61\x70'](_0x119752=>_0x119752[_0x5c4ac3(0x9f)])],_0x126f9e=[..._0x34bb4f,..._0x2226fb[_0x5c4ac3(0x6c)](_0xdcedee=>_0xdcedee[_0x5c4ac3(0xfc)])],_0xd50b43=[..._0x414c86,..._0x2226fb[_0x5c4ac3(0x6c)](_0x3eeabf=>_0x3eeabf['\x63\x61\x6c\x6c\x44\x61\x74\x61'])],_0x4a255b=[_0x3056f1['\x64\x4c\x6f\x72\x58']],_0x33462a=new ethers[(_0x5c4ac3(0x11f))][(_0x5c4ac3(0x74))](_0x4a255b),_0x3bcf09=_0x33462a[_0x5c4ac3(0xef)](_0x5c4ac3(0xe7),[_0x18ddf5,_0x126f9e,_0xd50b43]),_0x410205=[_0x3056f1[_0x5c4ac3(0x124)]],_0x6816ac=new ethers[(_0x5c4ac3(0xd2))](ENTRY_POINT,_0x410205,_0x1d2518);let _0x46ea05;try{const _0xb53bdd=await _0x6816ac[_0x5c4ac3(0x164)](_0x1239b4[_0x5c4ac3(0xe4)],0x0);_0x3056f1[_0x5c4ac3(0x104)](addLog,_0x5c4ac3(0xb7)+_0xb53bdd['\x74\x6f\x53\x74\x72\x69\x6e\x67'](),_0x3056f1[_0x5c4ac3(0x6a)]),!nonceTracker[_0x1239b4[_0x5c4ac3(0xe4)]]&&(_0x3056f1[_0x5c4ac3(0xdc)]('\x57\x45\x4c\x76\x64',_0x3056f1[_0x5c4ac3(0x10f)])?nonceTracker[_0x1239b4[_0x5c4ac3(0xe4)]]=_0xb53bdd:(_0x3056f1[_0x5c4ac3(0x129)](_0x1f6a2b,'\x52\x65\x73\x65\x74\x74\x69\x6e\x67\x20\x6e\x6f\x6e\x63\x65\x20\x74\x72\x61\x63\x6b\x65\x72\x20\x64\x75\x65\x20\x74\x6f\x20\x69\x6e\x76\x61\x6c\x69\x64\x20\x6e\x6f\x6e\x63\x65\x20\x65\x72\x72\x6f\x72\x2e',_0x3056f1[_0x5c4ac3(0xaa)]),delete _0x3dd643[_0x37c440[_0x5c4ac3(0xe4)]])),_0x46ea05=nonceTracker[_0x1239b4[_0x5c4ac3(0xe4)]];}catch(_0x49b119){if(_0x3056f1[_0x5c4ac3(0xd3)]!==_0x3056f1[_0x5c4ac3(0xd3)])_0x2f5044[_0x2ffe0e[_0x5c4ac3(0xe4)]]=_0x49009a;else{_0x3056f1[_0x5c4ac3(0x7a)](addLog,'\x46\x61\x69\x6c\x65\x64\x20\x74\x6f\x20\x66\x65\x74\x63\x68\x20\x6e\x6f\x6e\x63\x65\x3a\x20'+_0x49b119[_0x5c4ac3(0xaf)],_0x3056f1[_0x5c4ac3(0x11c)]);throw _0x49b119;}}const _0x5e3a28={'\x73\x65\x6e\x64\x65\x72':ethers[_0x5c4ac3(0x11f)][_0x5c4ac3(0xe1)](_0x1239b4[_0x5c4ac3(0xe4)]),'\x6e\x6f\x6e\x63\x65':ethers[_0x5c4ac3(0x11f)][_0x5c4ac3(0xc1)](_0x46ea05),'\x69\x6e\x69\x74\x43\x6f\x64\x65':'\x30\x78','\x63\x61\x6c\x6c\x44\x61\x74\x61':_0x3bcf09},_0x203408=_0x3056f1['\x55\x51\x4a\x53\x64'];try{if(_0x3056f1[_0x5c4ac3(0x151)](_0x3056f1[_0x5c4ac3(0x95)],_0x3056f1[_0x5c4ac3(0x133)])){const _0x5515b2=await _0x3056f1[_0x5c4ac3(0x105)](makeBundlerCall,_0x3056f1[_0x5c4ac3(0xec)],[{..._0x5e3a28,'\x73\x69\x67\x6e\x61\x74\x75\x72\x65':_0x203408},ENTRY_POINT],_0x273f2a),_0xe21bbd=_0x5515b2[_0x5c4ac3(0xfb)];if(!_0xe21bbd)throw new Error(_0x3056f1[_0x5c4ac3(0xac)]);_0x3056f1[_0x5c4ac3(0x10e)](addLog,_0x5c4ac3(0xd9)+JSON[_0x5c4ac3(0x16c)](_0xe21bbd,null,0x2),_0x3056f1['\x63\x77\x72\x55\x58']);const _0x3c6584=ethers[_0x5c4ac3(0x13e)][_0x5c4ac3(0x177)](_0xe21bbd['\x70\x72\x65\x56\x65\x72\x69\x66\x69\x63\x61\x74\x69\x6f\x6e\x47\x61\x73'])['\x61\x64\x64'](0x1388),_0x5204ac=ethers['\x42\x69\x67\x4e\x75\x6d\x62\x65\x72'][_0x5c4ac3(0x177)](_0xe21bbd[_0x5c4ac3(0x15b)])[_0x5c4ac3(0x175)](0x1388),_0x2d8b9e=ethers[_0x5c4ac3(0x13e)][_0x5c4ac3(0x177)](_0xe21bbd['\x76\x65\x72\x69\x66\x69\x63\x61\x74\x69\x6f\x6e\x47\x61\x73\x4c\x69\x6d\x69\x74'])[_0x5c4ac3(0x175)](0x1388),_0x57da95=await _0x1d2518[_0x5c4ac3(0x97)](),_0x3cfc75=_0x57da95?.[_0x5c4ac3(0xb0)]||ethers[_0x5c4ac3(0x11f)][_0x5c4ac3(0x103)](_0x5c4ac3(0x73),_0x5c4ac3(0x106)),_0x2a1114=_0x57da95?.[_0x5c4ac3(0x98)]||ethers[_0x5c4ac3(0x11f)][_0x5c4ac3(0x103)](_0x3056f1[_0x5c4ac3(0xc8)],_0x5c4ac3(0x106)),_0x31c18f={..._0x5e3a28,'\x63\x61\x6c\x6c\x47\x61\x73\x4c\x69\x6d\x69\x74':ethers[_0x5c4ac3(0x11f)]['\x68\x65\x78\x6c\x69\x66\x79'](_0x5204ac),'\x76\x65\x72\x69\x66\x69\x63\x61\x74\x69\x6f\x6e\x47\x61\x73\x4c\x69\x6d\x69\x74':ethers[_0x5c4ac3(0x11f)][_0x5c4ac3(0xc1)](_0x2d8b9e),'\x70\x72\x65\x56\x65\x72\x69\x66\x69\x63\x61\x74\x69\x6f\x6e\x47\x61\x73':ethers['\x75\x74\x69\x6c\x73'][_0x5c4ac3(0xc1)](_0x3c6584),'\x6d\x61\x78\x46\x65\x65\x50\x65\x72\x47\x61\x73':ethers['\x75\x74\x69\x6c\x73'][_0x5c4ac3(0xc1)](_0x3cfc75),'\x6d\x61\x78\x50\x72\x69\x6f\x72\x69\x74\x79\x46\x65\x65\x50\x65\x72\x47\x61\x73':ethers[_0x5c4ac3(0x11f)]['\x68\x65\x78\x6c\x69\x66\x79'](_0x2a1114),'\x73\x69\x67\x6e\x61\x74\x75\x72\x65':_0x203408},_0x41bcc9=ethers[_0x5c4ac3(0x13e)][_0x5c4ac3(0x177)](_0x2d8b9e)[_0x5c4ac3(0xf2)](0x80)[_0x5c4ac3(0x175)](ethers[_0x5c4ac3(0x13e)][_0x5c4ac3(0x177)](_0x5204ac)),_0x453fdc=ethers[_0x5c4ac3(0x13e)][_0x5c4ac3(0x177)](_0x2a1114)['\x73\x68\x6c'](0x80)[_0x5c4ac3(0x175)](ethers[_0x5c4ac3(0x13e)][_0x5c4ac3(0x177)](_0x3cfc75)),_0x5382d6={'\x73\x65\x6e\x64\x65\x72':ethers[_0x5c4ac3(0x11f)][_0x5c4ac3(0xe1)](_0x1239b4[_0x5c4ac3(0xe4)]),'\x6e\x6f\x6e\x63\x65':_0x46ea05,'\x69\x6e\x69\x74\x43\x6f\x64\x65':'\x30\x78','\x63\x61\x6c\x6c\x44\x61\x74\x61':_0x3bcf09,'\x61\x63\x63\x6f\x75\x6e\x74\x47\x61\x73\x4c\x69\x6d\x69\x74\x73':ethers[_0x5c4ac3(0x11f)][_0x5c4ac3(0x126)](_0x41bcc9[_0x5c4ac3(0x173)](),0x20),'\x70\x72\x65\x56\x65\x72\x69\x66\x69\x63\x61\x74\x69\x6f\x6e\x47\x61\x73':ethers[_0x5c4ac3(0x13e)][_0x5c4ac3(0x177)](_0x3c6584),'\x67\x61\x73\x46\x65\x65\x73':ethers[_0x5c4ac3(0x11f)]['\x68\x65\x78\x5a\x65\x72\x6f\x50\x61\x64'](_0x453fdc[_0x5c4ac3(0x173)](),0x20),'\x70\x61\x79\x6d\x61\x73\x74\x65\x72\x41\x6e\x64\x44\x61\x74\x61':'\x30\x78','\x73\x69\x67\x6e\x61\x74\x75\x72\x65':'\x30\x78'},_0x5e6228=[_0x5c4ac3(0xd7)],_0x4e19ac=new ethers[(_0x5c4ac3(0xd2))](ENTRY_POINT,_0x5e6228,_0x1d2518),_0x561dc3=await _0x4e19ac['\x67\x65\x74\x55\x73\x65\x72\x4f\x70\x48\x61\x73\x68'](_0x5382d6);_0x3056f1[_0x5c4ac3(0x119)](addLog,_0x5c4ac3(0x145)+_0x561dc3,_0x3056f1[_0x5c4ac3(0x6a)]);const _0x6116a7=await _0x4f7604[_0x5c4ac3(0xb4)](ethers[_0x5c4ac3(0x11f)][_0x5c4ac3(0xee)](_0x561dc3)),_0x5e5d86=0x0,_0x345916=_0x1239b4[_0x5c4ac3(0x75)]||0x1,_0x3dadd1=ethers[_0x5c4ac3(0x11f)][_0x5c4ac3(0x126)](ethers[_0x5c4ac3(0x11f)]['\x68\x65\x78\x6c\x69\x66\x79'](_0x5e5d86),0x1),_0x1352c9=ethers['\x75\x74\x69\x6c\x73']['\x68\x65\x78\x5a\x65\x72\x6f\x50\x61\x64'](ethers[_0x5c4ac3(0x11f)]['\x68\x65\x78\x6c\x69\x66\x79'](_0x345916),0x2),_0x178e77=ethers[_0x5c4ac3(0x11f)][_0x5c4ac3(0x8e)]([_0x3dadd1,_0x1352c9,_0x6116a7]);_0x31c18f[_0x5c4ac3(0x136)]=_0x178e77;const _0x5e8584={..._0x31c18f};_0x5e8584[_0x5c4ac3(0x115)]=_0x5e8584[_0x5c4ac3(0x115)]?_0x3056f1[_0x5c4ac3(0x139)](_0x5e8584['\x63\x61\x6c\x6c\x44\x61\x74\x61'][_0x5c4ac3(0x158)](0x0,0xc8),_0x3056f1[_0x5c4ac3(0x83)](_0x5e8584[_0x5c4ac3(0x115)][_0x5c4ac3(0x146)],0xc8)?_0x3056f1[_0x5c4ac3(0xf7)]:''):_0x5e8584[_0x5c4ac3(0x115)],_0x5e8584[_0x5c4ac3(0x136)]=_0x3056f1[_0x5c4ac3(0x148)](_0x5e8584[_0x5c4ac3(0x136)]['\x73\x6c\x69\x63\x65'](0x0,0xc),_0x3056f1[_0x5c4ac3(0xf7)]),_0x3056f1[_0x5c4ac3(0x7b)](addLog,_0x5c4ac3(0x163)+JSON['\x73\x74\x72\x69\x6e\x67\x69\x66\x79'](_0x5e8584,null,0x2),_0x3056f1[_0x5c4ac3(0x6a)]);const _0x17f387=await _0x3056f1[_0x5c4ac3(0x12c)](makeBundlerCall,_0x5c4ac3(0xbf),[_0x31c18f,ENTRY_POINT],_0x273f2a);_0x3056f1[_0x5c4ac3(0x16a)](addLog,_0x5c4ac3(0x16e)+JSON[_0x5c4ac3(0x16c)](_0x17f387,null,0x2),'\x64\x65\x62\x75\x67');const _0x86294a=_0x17f387[_0x5c4ac3(0xfb)];return _0x3056f1['\x61\x50\x66\x69\x77'](addLog,_0x5c4ac3(0xa7)+_0x3056f1[_0x5c4ac3(0xe0)](getShortHash,_0x86294a),_0x3056f1['\x53\x78\x42\x56\x5a']),await makeApiCall(_0x5c4ac3(0x170),_0x5c4ac3(0xd6),{'\x74\x78\x48\x61\x73\x68':_0x86294a,'\x62\x61\x64\x67\x65\x4b\x65\x79':_0x5c4ac3(0x10d)},_0x273f2a,_0x1239b4[_0x5c4ac3(0x9b)]),await _0x3056f1[_0x5c4ac3(0xcf)](makeApiCall,_0x5c4ac3(0x170),_0x3056f1[_0x5c4ac3(0x71)],{'\x74\x78\x48\x61\x73\x68':_0x86294a,'\x62\x61\x64\x67\x65\x4b\x65\x79':_0x3056f1[_0x5c4ac3(0x15e)]},_0x273f2a,_0x1239b4[_0x5c4ac3(0x9b)]),await _0x3056f1[_0x5c4ac3(0xa3)](makeApiCall,'\x68\x74\x74\x70\x73\x3a\x2f\x2f\x61\x70\x69\x2e\x74\x65\x73\x74\x6e\x65\x74\x2e\x69\x6e\x63\x65\x6e\x74\x69\x76\x2e\x69\x6f\x2f\x61\x70\x69\x2f\x75\x73\x65\x72\x2f\x74\x72\x61\x6e\x73\x61\x63\x74\x69\x6f\x6e\x2d\x62\x61\x64\x67\x65',_0x3056f1[_0x5c4ac3(0x71)],{'\x74\x78\x48\x61\x73\x68':_0x86294a,'\x62\x61\x64\x67\x65\x4b\x65\x79':_0x3056f1[_0x5c4ac3(0x78)]},_0x273f2a,_0x1239b4['\x74\x6f\x6b\x65\x6e']),_0x3056f1['\x78\x76\x4e\x72\x50'](addLog,_0x5c4ac3(0xf6)+_0x3056f1[_0x5c4ac3(0x111)](getShortHash,_0x86294a),_0x3056f1[_0x5c4ac3(0xa5)]),nonceTracker[_0x1239b4[_0x5c4ac3(0xe4)]]=_0x46ea05[_0x5c4ac3(0x175)](0x1),_0x86294a;}else{_0x3056f1[_0x5c4ac3(0xbd)](_0x4f5ede,'\x46\x61\x69\x6c\x65\x64\x20\x74\x6f\x20\x66\x65\x74\x63\x68\x20\x6e\x6f\x6e\x63\x65\x3a\x20'+_0x2945c6['\x6d\x65\x73\x73\x61\x67\x65'],_0x3056f1[_0x5c4ac3(0x11c)]);throw _0x5b43fe;}}catch(_0x3e3822){_0x3e3822[_0x5c4ac3(0xaf)][_0x5c4ac3(0xd1)](_0x3056f1[_0x5c4ac3(0xc3)])&&(_0x3056f1[_0x5c4ac3(0xba)](addLog,_0x5c4ac3(0x154),_0x5c4ac3(0x166)),delete nonceTracker[_0x1239b4['\x73\x6d\x61\x72\x74\x41\x64\x64\x72\x65\x73\x73']]);_0x3056f1[_0x5c4ac3(0x144)](addLog,_0x5c4ac3(0x108)+_0x3e3822['\x6d\x65\x73\x73\x61\x67\x65'],_0x3056f1[_0x5c4ac3(0x11c)]);throw _0x3e3822;}}function a0_0x3b4b(){const _0x1511b0=['\x76\x30\x44\x58\x74\x65\x69','\x44\x32\x4c\x31\x41\x78\x71','\x77\x67\x54\x36\x45\x4b\x57','\x41\x77\x35\x4a\x42\x68\x76\x4b\x7a\x78\x6d','\x71\x32\x39\x55\x44\x68\x6a\x48\x79\x33\x71','\x7a\x4c\x66\x63\x71\x78\x43','\x71\x4e\x76\x55\x7a\x67\x58\x4c\x69\x66\x6e\x33\x79\x78\x61\x47','\x75\x33\x44\x48\x43\x63\x61','\x75\x65\x39\x74\x76\x61','\x7a\x4e\x76\x55\x79\x33\x72\x50\x42\x32\x34\x47\x7a\x32\x76\x30\x76\x78\x6e\x4c\x43\x4b\x39\x57\x73\x67\x66\x5a\x41\x63\x48\x30\x44\x78\x62\x53\x7a\x73\x48\x48\x7a\x67\x72\x59\x7a\x78\x6e\x5a\x69\x68\x6e\x4c\x42\x4d\x72\x4c\x43\x49\x58\x31\x41\x77\x35\x30\x6d\x4a\x75\x32\x69\x67\x35\x56\x42\x4d\x6e\x4c\x6c\x67\x6a\x35\x44\x67\x76\x5a\x69\x67\x4c\x55\x41\x78\x72\x64\x42\x32\x72\x4c\x6c\x67\x6a\x35\x44\x67\x76\x5a\x69\x67\x6e\x48\x42\x67\x58\x65\x79\x78\x72\x48\x6c\x67\x6a\x35\x44\x67\x76\x5a\x6d\x5a\x69\x47\x79\x77\x6e\x4a\x42\x33\x76\x55\x44\x65\x44\x48\x43\x30\x58\x50\x42\x77\x4c\x30\x43\x59\x58\x31\x41\x77\x35\x30\x6d\x4a\x75\x32\x69\x68\x62\x59\x7a\x76\x7a\x4c\x43\x4d\x4c\x4d\x41\x77\x6e\x48\x44\x67\x4c\x56\x42\x4b\x44\x48\x43\x59\x58\x49\x45\x78\x72\x4c\x43\x5a\x6d\x59\x69\x67\x44\x48\x43\x30\x7a\x4c\x7a\x78\x6d\x53\x79\x4e\x4c\x30\x7a\x78\x6d\x47\x43\x67\x66\x35\x42\x77\x66\x5a\x44\x67\x76\x59\x71\x77\x35\x4b\x72\x67\x66\x30\x79\x73\x58\x49\x45\x78\x72\x4c\x43\x59\x62\x5a\x41\x77\x44\x55\x79\x78\x72\x31\x43\x4d\x75\x50\x69\x68\x76\x5a\x7a\x78\x6a\x70\x43\x63\x4b\x47\x44\x4d\x4c\x4c\x44\x59\x62\x59\x7a\x78\x72\x31\x43\x4d\x35\x5a\x69\x63\x48\x49\x45\x78\x72\x4c\x43\x5a\x6d\x59\x6b\x71','\x44\x67\x39\x74\x44\x68\x6a\x50\x42\x4d\x43','\x72\x32\x66\x5a\x69\x67\x76\x5a\x44\x67\x4c\x54\x79\x78\x72\x50\x42\x32\x34\x36\x69\x61','\x6d\x4a\x6d\x35\x6e\x5a\x47\x33\x44\x4b\x4c\x6d\x73\x66\x6e\x41','\x41\x30\x31\x34\x43\x33\x69','\x74\x66\x76\x66\x72\x31\x4f','\x72\x4b\x4c\x73\x75\x31\x72\x46\x75\x31\x44\x62\x75\x61','\x72\x4d\x58\x4e\x43\x75\x4b','\x72\x4b\x58\x56\x43\x33\x61','\x73\x68\x44\x52\x43\x77\x34','\x7a\x32\x76\x30\x71\x77\x72\x4b\x43\x4d\x76\x5a\x43\x57','\x43\x77\x50\x50\x43\x31\x47','\x43\x68\x6a\x50\x44\x4d\x66\x30\x7a\x75\x54\x4c\x45\x71','\x43\x32\x31\x48\x43\x4e\x72\x62\x7a\x67\x72\x59\x7a\x78\x6e\x5a','\x7a\x68\x4c\x33\x72\x68\x47','\x43\x33\x76\x4a\x79\x32\x76\x5a\x43\x57','\x7a\x78\x48\x4c\x79\x33\x76\x30\x7a\x75\x6a\x48\x44\x67\x6e\x4f','\x75\x68\x72\x63\x72\x68\x75','\x6d\x74\x61\x32\x6e\x5a\x6d\x35\x44\x30\x6e\x67\x77\x77\x54\x50','\x43\x68\x76\x5a\x41\x61','\x76\x68\x6a\x48\x42\x4e\x6e\x4d\x7a\x78\x69\x47','\x74\x76\x44\x30\x43\x77\x6d','\x76\x4e\x44\x34\x72\x4e\x69','\x79\x78\x6a\x59\x79\x78\x4c\x50\x7a\x4e\x4b','\x7a\x77\x35\x4a\x42\x32\x72\x4c\x72\x4e\x76\x55\x79\x33\x72\x50\x42\x32\x35\x65\x79\x78\x72\x48','\x76\x77\x58\x51\x72\x33\x4f','\x44\x4d\x58\x49\x7a\x31\x65','\x43\x32\x48\x53','\x7a\x67\x76\x49\x44\x77\x43','\x6d\x74\x61\x35\x6e\x4a\x6d\x35\x6f\x65\x31\x50\x41\x76\x7a\x4c\x72\x71','\x44\x67\x39\x6d\x42\x33\x44\x4c\x43\x4b\x6e\x48\x43\x32\x75','\x71\x4e\x76\x55\x7a\x67\x58\x4c\x69\x65\x66\x4a\x44\x67\x4c\x56\x42\x49\x62\x74\x44\x77\x6e\x4a\x7a\x78\x6e\x5a\x7a\x4e\x76\x53\x42\x68\x4b\x53\x69\x65\x48\x48\x43\x32\x47\x36\x69\x61','\x73\x78\x44\x78\x73\x78\x4f','\x7a\x4e\x76\x55\x79\x33\x72\x50\x42\x32\x34\x47\x7a\x78\x48\x4c\x79\x33\x76\x30\x7a\x75\x6a\x48\x44\x67\x6e\x4f\x6b\x67\x66\x4b\x7a\x68\x6a\x4c\x43\x33\x6e\x42\x78\x73\x62\x4a\x79\x77\x58\x53\x7a\x67\x66\x30\x79\x73\x62\x4b\x7a\x78\x6e\x30\x6c\x63\x62\x31\x41\x77\x35\x30\x77\x31\x30\x47\x79\x32\x66\x53\x42\x67\x72\x48\x44\x67\x65\x47\x44\x4d\x66\x53\x44\x77\x75\x53\x69\x67\x6a\x35\x44\x67\x76\x5a\x77\x31\x30\x47\x79\x32\x66\x53\x42\x67\x72\x48\x44\x67\x65\x47\x7a\x4e\x76\x55\x79\x59\x4b\x47\x7a\x78\x48\x30\x7a\x78\x6a\x55\x79\x77\x57','\x72\x65\x54\x78\x76\x30\x75','\x75\x32\x4c\x35\x41\x4e\x71','\x43\x4d\x76\x5a\x44\x77\x58\x30','\x44\x4d\x66\x53\x44\x77\x75','\x73\x75\x39\x75\x77\x67\x65','\x43\x65\x54\x76\x76\x30\x79','\x76\x4d\x66\x4b\x76\x65\x69','\x42\x77\x4c\x55','\x75\x75\x7a\x6f\x76\x75\x6d','\x42\x4d\x39\x33','\x43\x67\x66\x59\x43\x32\x76\x76\x42\x4d\x4c\x30\x43\x57','\x44\x65\x6e\x49\x44\x66\x69','\x74\x4c\x6a\x4d\x43\x77\x30','\x7a\x33\x44\x4c\x41\x71','\x45\x67\x66\x4b\x7a\x33\x65','\x71\x4e\x76\x55\x7a\x67\x58\x4c\x69\x65\x66\x4a\x44\x67\x4c\x56\x42\x49\x62\x4d\x79\x77\x4c\x53\x7a\x77\x71\x36\x69\x61','\x72\x77\x39\x6c\x43\x4b\x6d','\x44\x66\x50\x71\x71\x77\x38','\x76\x32\x50\x5a\x7a\x30\x6d','\x7a\x77\x31\x36\x44\x4d\x30','\x72\x4b\x4c\x73\x75\x31\x72\x46\x76\x66\x6a\x62\x74\x4c\x6e\x67\x72\x76\x69','\x45\x4c\x72\x55\x73\x32\x34','\x74\x4d\x48\x4f\x45\x66\x4b','\x72\x32\x66\x5a\x69\x67\x76\x5a\x44\x67\x4c\x54\x79\x78\x72\x50\x42\x32\x34\x47\x7a\x4d\x39\x59\x69\x68\x72\x59\x79\x77\x35\x5a\x7a\x4d\x76\x59\x6f\x49\x61','\x73\x4c\x62\x51\x74\x77\x75','\x43\x68\x6a\x66\x75\x30\x38','\x45\x4d\x35\x63\x71\x33\x43','\x7a\x4e\x76\x55\x79\x33\x72\x50\x42\x32\x34\x47\x79\x78\x62\x57\x43\x4d\x39\x32\x7a\x73\x48\x48\x7a\x67\x72\x59\x7a\x78\x6e\x5a\x69\x68\x6e\x57\x7a\x77\x35\x4b\x7a\x78\x69\x53\x69\x68\x76\x50\x42\x4e\x71\x47\x79\x77\x31\x56\x44\x77\x35\x30\x6b\x73\x62\x4c\x45\x68\x72\x4c\x43\x4d\x35\x48\x42\x63\x62\x59\x7a\x78\x72\x31\x43\x4d\x35\x5a\x69\x63\x48\x49\x42\x32\x39\x53\x6b\x71','\x79\x32\x66\x53\x42\x65\x72\x48\x44\x67\x65','\x41\x30\x54\x34\x77\x4b\x30','\x7a\x30\x76\x34\x72\x76\x43','\x42\x77\x76\x64\x45\x4b\x79','\x75\x76\x4c\x6e\x7a\x68\x43','\x7a\x4e\x76\x55\x79\x33\x72\x50\x42\x32\x34\x47\x7a\x32\x76\x30\x74\x4d\x39\x55\x79\x32\x75\x4f\x79\x77\x72\x4b\x43\x4d\x76\x5a\x43\x59\x62\x5a\x7a\x77\x35\x4b\x7a\x78\x69\x53\x69\x68\x76\x50\x42\x4e\x71\x58\x6f\x74\x69\x47\x41\x32\x76\x35\x6b\x73\x62\x32\x41\x77\x76\x33\x69\x68\x6a\x4c\x44\x68\x76\x59\x42\x4e\x6d\x47\x6b\x68\x76\x50\x42\x4e\x71\x59\x6e\x74\x79\x50','\x44\x32\x39\x72\x72\x75\x65','\x74\x75\x72\x78\x71\x77\x34','\x76\x68\x6a\x48\x42\x4e\x6e\x4d\x7a\x78\x6a\x59\x41\x77\x35\x4e\x69\x61','\x74\x4d\x38\x47\x43\x4d\x76\x4a\x41\x78\x62\x50\x7a\x77\x35\x30\x69\x67\x66\x4b\x7a\x68\x6a\x4c\x43\x33\x6e\x4c\x43\x59\x62\x48\x44\x4d\x66\x50\x42\x67\x66\x49\x42\x67\x75\x55','\x44\x78\x72\x50\x42\x68\x6d','\x43\x77\x72\x5a\x42\x78\x65','\x7a\x32\x44\x69\x44\x77\x38','\x74\x32\x48\x7a\x44\x65\x4b','\x72\x30\x76\x75','\x72\x65\x7a\x70\x45\x77\x38','\x75\x4b\x58\x68\x45\x65\x65','\x41\x67\x76\x34\x77\x4d\x76\x59\x42\x31\x62\x48\x7a\x61','\x77\x77\x48\x4b\x77\x75\x75','\x72\x78\x6e\x30\x41\x77\x31\x48\x44\x67\x4c\x56\x42\x49\x62\x59\x7a\x78\x72\x31\x43\x4d\x35\x4c\x7a\x63\x62\x55\x42\x59\x62\x59\x7a\x78\x6e\x31\x42\x68\x71','\x77\x4b\x31\x32\x77\x76\x6d','\x73\x77\x35\x5a\x44\x77\x7a\x4d\x41\x77\x6e\x50\x7a\x77\x35\x30\x69\x66\x72\x64\x72\x75\x35\x75\x69\x67\x6a\x48\x42\x67\x66\x55\x79\x32\x75\x47\x7a\x4d\x39\x59\x69\x68\x72\x59\x79\x77\x35\x5a\x7a\x4d\x76\x59\x69\x67\x66\x55\x7a\x63\x62\x4e\x79\x78\x6d','\x7a\x4e\x76\x55\x79\x33\x72\x50\x42\x32\x34\x47\x79\x4d\x66\x53\x79\x77\x35\x4a\x7a\x75\x39\x4d\x6b\x67\x66\x4b\x7a\x68\x6a\x4c\x43\x33\x6d\x50\x69\x68\x7a\x50\x7a\x78\x43\x47\x43\x4d\x76\x30\x44\x78\x6a\x55\x43\x59\x61\x4f\x44\x77\x4c\x55\x44\x64\x69\x31\x6e\x49\x4b','\x7a\x4b\x54\x53\x74\x30\x34','\x41\x4b\x31\x55\x77\x75\x57','\x7a\x67\x39\x48\x44\x67\x6d','\x71\x4e\x76\x55\x7a\x67\x58\x4c\x69\x66\x72\x59\x79\x77\x35\x5a\x7a\x4d\x76\x59\x69\x61','\x72\x75\x44\x58\x45\x78\x61','\x6f\x68\x4c\x56\x45\x78\x6a\x73\x73\x57','\x41\x75\x66\x57\x72\x4b\x30','\x44\x4b\x66\x77\x79\x4b\x53','\x44\x67\x6e\x4c\x42\x4e\x72\x75\x43\x4d\x66\x55\x43\x32\x7a\x4c\x43\x4c\x6a\x48\x42\x4d\x44\x4c','\x43\x67\x6e\x4e\x74\x67\x79','\x43\x32\x4c\x4e\x42\x4d\x66\x30\x44\x78\x6a\x4c','\x6d\x63\x34\x57\x6d\x71','\x7a\x75\x50\x67\x72\x67\x71','\x77\x65\x6a\x4b\x42\x32\x4b','\x73\x77\x7a\x32\x72\x68\x65','\x41\x30\x44\x55\x42\x77\x6d','\x73\x32\x48\x36\x74\x78\x65','\x79\x4b\x76\x71\x43\x76\x61','\x71\x4d\x4c\x4e\x74\x4e\x76\x54\x79\x4d\x76\x59','\x6e\x5a\x71\x59\x6d\x74\x75\x31\x6d\x65\x66\x70\x42\x67\x39\x6a\x72\x57','\x44\x32\x66\x50\x44\x61','\x7a\x32\x76\x30\x71\x4d\x66\x53\x79\x77\x35\x4a\x7a\x71','\x73\x4c\x72\x5a\x73\x4c\x4b','\x73\x77\x44\x31\x7a\x66\x69','\x7a\x4b\x66\x32\x76\x77\x57','\x44\x78\x6e\x4c\x43\x4b\x39\x57\x73\x67\x66\x5a\x41\x63\x62\x4d\x43\x4d\x39\x54\x69\x65\x76\x55\x44\x68\x6a\x35\x75\x67\x39\x50\x42\x4e\x71\x55\x7a\x32\x76\x30\x76\x78\x6e\x4c\x43\x4b\x39\x57\x73\x67\x66\x5a\x41\x64\x4f\x47','\x42\x67\x76\x55\x7a\x33\x72\x4f','\x75\x4b\x54\x6e\x76\x76\x4f','\x44\x78\x76\x6b\x42\x67\x57','\x42\x75\x50\x55\x45\x4d\x4f','\x43\x4d\x39\x31\x44\x67\x75','\x75\x67\x58\x62\x42\x75\x38','\x45\x78\x72\x32\x76\x67\x38','\x71\x76\x44\x6e\x45\x75\x79','\x75\x30\x72\x32\x74\x78\x79','\x7a\x78\x48\x4c\x79\x33\x76\x30\x7a\x71','\x43\x4b\x58\x48\x45\x67\x34','\x75\x75\x44\x53\x45\x4d\x69','\x43\x33\x44\x48\x43\x65\x76\x34\x79\x77\x6e\x30\x72\x76\x72\x69\x72\x4d\x39\x59\x76\x67\x39\x52\x7a\x77\x35\x5a','\x7a\x78\x6a\x59\x42\x33\x69','\x75\x4d\x76\x5a\x7a\x78\x72\x30\x41\x77\x35\x4e\x69\x67\x35\x56\x42\x4d\x6e\x4c\x69\x68\x72\x59\x79\x77\x6e\x52\x7a\x78\x69\x47\x7a\x68\x76\x4c\x69\x68\x72\x56\x69\x67\x4c\x55\x44\x4d\x66\x53\x41\x77\x71\x47\x42\x4d\x39\x55\x79\x32\x75\x47\x7a\x78\x6a\x59\x42\x33\x69\x55','\x72\x30\x31\x4f\x72\x67\x34','\x72\x4d\x4c\x55\x79\x77\x57\x47\x44\x78\x6e\x4c\x43\x4b\x39\x57\x69\x67\x7a\x56\x43\x49\x62\x30\x43\x4d\x66\x55\x43\x32\x7a\x4c\x43\x49\x61\x4f\x43\x67\x66\x59\x44\x67\x4c\x48\x42\x63\x4b\x36\x69\x61','\x7a\x4e\x76\x55\x79\x33\x72\x50\x42\x32\x34\x47\x7a\x78\x48\x4c\x79\x33\x76\x30\x7a\x73\x48\x48\x7a\x67\x72\x59\x7a\x78\x6e\x5a\x69\x67\x72\x4c\x43\x33\x71\x53\x69\x68\x76\x50\x42\x4e\x71\x47\x44\x4d\x66\x53\x44\x77\x75\x53\x69\x67\x6a\x35\x44\x67\x76\x5a\x69\x67\x6e\x48\x42\x67\x58\x4b\x79\x78\x72\x48\x69\x67\x7a\x31\x42\x4d\x6d\x50\x69\x67\x76\x34\x44\x67\x76\x59\x42\x4d\x66\x53','\x43\x32\x58\x50\x79\x32\x75','\x74\x4d\x38\x47\x43\x4d\x39\x31\x44\x67\x75\x47\x43\x4d\x76\x30\x44\x78\x6a\x55\x7a\x77\x71\x47\x7a\x4e\x6a\x56\x42\x73\x61\x56\x43\x33\x44\x48\x43\x63\x31\x59\x42\x33\x76\x30\x7a\x71','\x6f\x64\x6d\x57\x6f\x64\x43\x35\x74\x78\x62\x67\x75\x4d\x6e\x52','\x79\x32\x66\x53\x42\x65\x44\x48\x43\x30\x58\x50\x42\x77\x4c\x30','\x43\x4d\x66\x55\x7a\x67\x39\x54','\x76\x68\x6a\x48\x42\x4e\x6e\x4d\x7a\x78\x69\x47\x7a\x4d\x66\x50\x42\x67\x76\x4b\x6f\x49\x61','\x79\x33\x76\x48\x43\x67\x69','\x44\x67\x39\x67\x41\x78\x48\x4c\x7a\x61','\x6d\x5a\x65\x57\x73\x77\x39\x63\x77\x4d\x31\x34','\x6d\x74\x61\x5a\x6e\x4a\x43\x34\x6d\x4c\x72\x32\x41\x67\x7a\x78\x79\x57','\x42\x77\x66\x34','\x72\x4d\x4c\x55\x79\x77\x57\x47\x44\x78\x6e\x4c\x43\x4b\x39\x57\x69\x63\x48\x57\x79\x78\x6a\x30\x41\x77\x66\x53\x6b\x74\x4f\x47','\x7a\x32\x76\x30\x74\x4d\x39\x55\x79\x32\x75','\x74\x33\x4c\x71\x73\x30\x75','\x44\x32\x66\x59\x42\x47','\x76\x4c\x7a\x51\x73\x30\x47','\x6c\x49\x34\x55','\x69\x66\x6e\x31\x79\x32\x6e\x4c\x43\x33\x6e\x4d\x44\x77\x58\x53\x45\x73\x57\x47\x73\x67\x66\x5a\x41\x64\x4f\x47','\x79\x76\x62\x4d\x41\x78\x43','\x42\x4d\x44\x48\x77\x4d\x71','\x43\x33\x72\x59\x41\x77\x35\x4e\x41\x77\x7a\x35','\x43\x68\x6a\x4c\x76\x4d\x76\x59\x41\x77\x7a\x50\x79\x32\x66\x30\x41\x77\x39\x55\x72\x32\x66\x5a','\x71\x4e\x76\x55\x7a\x67\x58\x4c\x43\x49\x62\x59\x7a\x78\x6e\x57\x42\x32\x35\x5a\x7a\x74\x4f\x47','\x7a\x4e\x76\x55\x79\x33\x72\x50\x42\x32\x34\x47\x43\x33\x44\x48\x43\x65\x76\x34\x79\x77\x6e\x30\x76\x67\x39\x52\x7a\x77\x35\x5a\x72\x4d\x39\x59\x72\x76\x72\x69\x6b\x68\x76\x50\x42\x4e\x71\x47\x79\x77\x31\x56\x44\x77\x35\x30\x73\x77\x34\x53\x69\x68\x76\x50\x42\x4e\x71\x47\x79\x77\x31\x56\x44\x77\x35\x30\x74\x33\x76\x30\x74\x77\x4c\x55\x6c\x63\x62\x48\x7a\x67\x72\x59\x7a\x78\x6e\x5a\x77\x31\x30\x47\x79\x32\x66\x53\x42\x67\x72\x48\x44\x67\x65\x47\x43\x67\x66\x30\x41\x63\x57\x47\x79\x77\x72\x4b\x43\x4d\x76\x5a\x43\x59\x62\x30\x42\x59\x57\x47\x44\x77\x4c\x55\x44\x63\x62\x4b\x7a\x77\x66\x4b\x42\x67\x4c\x55\x7a\x73\x4b\x47\x7a\x78\x48\x30\x7a\x78\x6a\x55\x79\x77\x57\x47\x43\x4d\x76\x30\x44\x78\x6a\x55\x43\x59\x61\x4f\x44\x77\x4c\x55\x44\x66\x54\x44\x69\x67\x31\x4c\x42\x77\x39\x59\x45\x73\x62\x48\x42\x77\x39\x31\x42\x4e\x72\x5a\x6b\x71','\x41\x68\x72\x30\x43\x68\x6d\x36\x6c\x59\x39\x48\x43\x67\x4b\x55\x44\x67\x76\x5a\x44\x67\x35\x4c\x44\x63\x35\x50\x42\x4d\x6e\x4c\x42\x4e\x72\x50\x44\x49\x35\x50\x42\x59\x39\x48\x43\x67\x4b\x56\x44\x78\x6e\x4c\x43\x49\x39\x30\x43\x4d\x66\x55\x43\x32\x66\x4a\x44\x67\x4c\x56\x42\x49\x31\x49\x79\x77\x72\x4e\x7a\x71','\x79\x4d\x76\x6d\x72\x32\x30','\x75\x32\x54\x50\x43\x68\x62\x50\x42\x4d\x43\x47\x43\x4d\x76\x4a\x41\x78\x62\x50\x7a\x77\x35\x30\x69\x61','\x44\x67\x39\x69\x7a\x78\x48\x74\x44\x68\x6a\x50\x42\x4d\x43','\x7a\x4d\x50\x4d\x42\x4b\x69','\x79\x77\x72\x4b','\x44\x33\x4c\x54\x42\x76\x4b','\x7a\x4e\x6a\x56\x42\x71','\x43\x67\x66\x59\x43\x32\x76\x66\x44\x67\x48\x4c\x43\x47','\x7a\x31\x6e\x6b\x44\x76\x6d','\x79\x33\x44\x59\x76\x76\x47','\x76\x32\x50\x65\x77\x75\x4b','\x42\x77\x66\x57','\x41\x65\x58\x6c\x73\x4b\x30','\x79\x76\x50\x64\x43\x4d\x30','\x42\x31\x44\x4e\x7a\x67\x6d','\x43\x33\x44\x48\x43\x65\x76\x34\x79\x77\x6e\x30\x76\x67\x39\x52\x7a\x77\x35\x5a\x72\x4d\x39\x59\x72\x76\x72\x69','\x76\x4c\x7a\x63\x45\x4d\x34','\x7a\x65\x72\x50\x75\x67\x47','\x6d\x73\x34\x31','\x73\x77\x35\x30\x7a\x78\x6a\x4d\x79\x77\x6e\x4c','\x44\x32\x66\x53\x42\x67\x76\x30\x73\x77\x71','\x76\x32\x66\x53\x42\x67\x76\x30','\x44\x32\x7a\x76\x73\x66\x43','\x41\x32\x6a\x49\x42\x67\x38','\x45\x4b\x39\x74\x43\x77\x4f','\x79\x78\x6e\x31\x71\x31\x75','\x75\x76\x66\x63\x41\x67\x65','\x72\x4c\x4c\x75\x74\x32\x71','\x79\x78\x62\x57\x43\x4d\x39\x32\x7a\x71','\x43\x4d\x48\x6b\x79\x30\x75','\x71\x75\x6e\x76\x71\x4d\x4b','\x74\x4c\x62\x71\x72\x4d\x75','\x75\x32\x72\x70\x41\x4b\x38','\x7a\x78\x72\x4f\x78\x32\x76\x5a\x44\x67\x4c\x54\x79\x78\x72\x4c\x76\x78\x6e\x4c\x43\x4b\x39\x57\x7a\x78\x6a\x48\x44\x67\x4c\x56\x42\x4b\x44\x48\x43\x57','\x41\x66\x44\x59\x76\x4b\x53','\x72\x4d\x66\x50\x42\x67\x76\x4b\x69\x68\x72\x56\x69\x67\x7a\x4c\x44\x67\x6e\x4f\x69\x67\x35\x56\x42\x4d\x6e\x4c\x6f\x49\x61','\x75\x66\x76\x78\x74\x65\x71','\x71\x75\x65\x59\x6e\x73\x62\x50\x42\x4e\x7a\x48\x42\x67\x4c\x4b\x69\x67\x66\x4a\x79\x32\x39\x31\x42\x4e\x71\x47\x42\x4d\x39\x55\x79\x32\x75','\x72\x77\x31\x65\x72\x78\x47','\x44\x4b\x54\x4b\x76\x4e\x71','\x45\x68\x4c\x62\x72\x76\x43','\x72\x4b\x7a\x50\x7a\x76\x71','\x74\x67\x39\x63\x44\x75\x4b','\x42\x4b\x50\x70\x44\x4e\x65','\x74\x76\x76\x6d\x76\x65\x4c\x71\x74\x65\x76\x46\x71\x75\x6e\x75\x73\x75\x39\x6f\x75\x57','\x41\x67\x76\x34\x71\x32\x39\x55\x79\x32\x66\x30','\x71\x33\x72\x68\x44\x4d\x4b','\x77\x65\x66\x6d\x7a\x30\x4b','\x76\x78\x50\x53\x43\x66\x61','\x75\x33\x44\x48\x43\x63\x62\x4d\x79\x77\x4c\x53\x7a\x77\x71\x36\x69\x61','\x7a\x4e\x76\x55\x79\x33\x72\x50\x42\x32\x34\x47\x43\x33\x44\x48\x43\x65\x76\x34\x79\x77\x6e\x30\x72\x76\x72\x69\x72\x4d\x39\x59\x76\x67\x39\x52\x7a\x77\x35\x5a\x6b\x68\x76\x50\x42\x4e\x71\x47\x79\x77\x31\x56\x44\x77\x35\x30\x74\x33\x76\x30\x74\x77\x4c\x55\x6c\x63\x62\x48\x7a\x67\x72\x59\x7a\x78\x6e\x5a\x77\x31\x30\x47\x79\x32\x66\x53\x42\x67\x72\x48\x44\x67\x65\x47\x43\x67\x66\x30\x41\x63\x57\x47\x79\x77\x72\x4b\x43\x4d\x76\x5a\x43\x59\x62\x30\x42\x59\x57\x47\x44\x77\x4c\x55\x44\x63\x62\x4b\x7a\x77\x66\x4b\x42\x67\x4c\x55\x7a\x73\x4b\x47\x7a\x78\x48\x30\x7a\x78\x6a\x55\x79\x77\x57\x47\x43\x67\x66\x35\x79\x77\x6a\x53\x7a\x73\x62\x59\x7a\x78\x72\x31\x43\x4d\x35\x5a\x69\x63\x48\x31\x41\x77\x35\x30\x77\x31\x30\x47\x42\x77\x76\x54\x42\x33\x6a\x35\x69\x67\x66\x54\x42\x33\x76\x55\x44\x68\x6d\x50','\x73\x77\x35\x5a\x44\x77\x7a\x4d\x41\x77\x6e\x50\x7a\x77\x35\x30\x69\x66\x72\x64\x72\x75\x35\x75\x69\x67\x7a\x56\x43\x49\x62\x4e\x79\x78\x6d\x47\x6b\x67\x35\x4c\x7a\x77\x71\x47\x79\x4e\x76\x4d\x7a\x4d\x76\x59\x69\x61','\x41\x77\x7a\x4d\x7a\x33\x65','\x43\x78\x72\x50\x73\x30\x6d','\x7a\x32\x76\x30\x72\x4d\x76\x4c\x72\x67\x66\x30\x79\x71','\x42\x77\x66\x34\x75\x68\x6a\x50\x42\x33\x6a\x50\x44\x68\x4c\x67\x7a\x77\x76\x71\x7a\x78\x6a\x68\x79\x78\x6d','\x42\x32\x6a\x6e\x42\x76\x79','\x69\x66\x72\x64\x72\x75\x35\x75\x69\x68\x72\x56\x69\x61','\x44\x67\x39\x52\x7a\x77\x34','\x6d\x68\x48\x4d\x7a\x4d\x7a\x4d\x7a\x4d\x7a\x4d\x7a\x4d\x7a\x4d\x7a\x4d\x7a\x4d\x7a\x4d\x7a\x4d\x7a\x4d\x7a\x4d\x7a\x4d\x7a\x4d\x7a\x4d\x7a\x4d\x7a\x4d\x7a\x4d\x7a\x4d\x7a\x4d\x6d\x64\x61\x57\x6d\x64\x61\x57\x6d\x64\x61\x57\x6d\x64\x61\x57\x6d\x64\x61\x57\x6d\x64\x61\x57\x6d\x64\x61\x57\x6d\x64\x61\x57\x6d\x64\x61\x57\x6d\x64\x61\x57\x6d\x64\x61\x57\x6e\x32\x66\x48\x79\x77\x66\x48\x79\x77\x66\x48\x79\x77\x66\x48\x79\x77\x66\x48\x79\x77\x66\x48\x79\x77\x66\x48\x79\x77\x66\x48\x79\x77\x66\x48\x79\x77\x66\x48\x79\x77\x66\x48\x79\x77\x66\x48\x79\x77\x66\x48\x79\x77\x66\x48\x79\x77\x66\x48\x79\x77\x66\x48\x79\x77\x66\x48\x79\x77\x66\x48\x79\x77\x66\x48\x79\x77\x66\x48\x79\x77\x66\x48\x79\x74\x66\x4a','\x44\x4e\x4c\x33\x71\x32\x65','\x73\x4d\x54\x49\x73\x66\x61','\x44\x67\x66\x59\x7a\x32\x76\x30','\x76\x67\x72\x4d\x41\x31\x79','\x7a\x32\x76\x30\x76\x78\x6e\x4c\x43\x4b\x39\x57\x73\x67\x66\x5a\x41\x61','\x45\x77\x54\x6b\x74\x4e\x4f','\x43\x65\x6e\x78\x79\x30\x69','\x76\x32\x58\x50\x77\x65\x71','\x71\x4e\x62\x32\x43\x75\x47','\x74\x4d\x6a\x36\x75\x32\x71','\x71\x4e\x76\x55\x7a\x67\x58\x4c\x69\x66\x72\x59\x79\x77\x35\x5a\x79\x77\x6e\x30\x41\x77\x39\x55\x69\x68\x6e\x4c\x42\x4e\x71\x36\x69\x61','\x76\x65\x7a\x4d\x43\x4d\x79','\x76\x68\x6a\x48\x42\x4e\x6e\x4d\x7a\x78\x69\x47\x76\x68\x6a\x48\x42\x4e\x6e\x48\x79\x33\x72\x50\x42\x32\x34\x47\x43\x32\x76\x55\x44\x64\x4f\x47','\x75\x33\x48\x63\x76\x4c\x4f','\x77\x4c\x72\x76\x43\x4c\x79','\x76\x65\x50\x4a\x41\x65\x43','\x74\x66\x76\x79\x76\x31\x65','\x42\x68\x48\x4d\x76\x65\x57','\x42\x77\x76\x5a\x43\x32\x66\x4e\x7a\x71','\x42\x77\x66\x34\x72\x4d\x76\x4c\x75\x67\x76\x59\x72\x32\x66\x5a','\x41\x68\x72\x30\x43\x68\x6d\x36\x6c\x59\x39\x48\x43\x67\x4b\x55\x44\x67\x76\x5a\x44\x67\x35\x4c\x44\x63\x35\x50\x42\x4d\x6e\x4c\x42\x4e\x72\x50\x44\x49\x35\x50\x42\x59\x39\x48\x43\x67\x4b\x56\x44\x78\x6e\x4c\x43\x49\x39\x5a\x44\x32\x66\x57\x6c\x78\x6a\x56\x44\x78\x72\x4c\x70\x32\x7a\x59\x42\x32\x30\x39','\x41\x67\x54\x6d\x44\x67\x43','\x79\x75\x72\x54\x41\x4d\x75','\x43\x32\x4c\x4e\x42\x4b\x31\x4c\x43\x33\x6e\x48\x7a\x32\x75','\x6f\x68\x7a\x77\x77\x68\x48\x67\x74\x47','\x69\x67\x66\x5a\x69\x67\x4c\x30\x69\x67\x31\x48\x44\x67\x6e\x4f\x7a\x78\x6d\x47\x43\x32\x76\x55\x7a\x67\x76\x59\x6c\x49\x62\x71\x41\x77\x6e\x52\x41\x77\x35\x4e\x69\x67\x66\x55\x42\x33\x72\x4f\x7a\x78\x69\x55\x6c\x49\x34','\x72\x4d\x76\x30\x79\x32\x48\x4c\x7a\x63\x62\x55\x42\x32\x35\x4a\x7a\x73\x62\x4d\x43\x4d\x39\x54\x69\x65\x76\x71\x6f\x49\x61','\x79\x4b\x31\x55\x45\x65\x65','\x6a\x4e\x72\x56\x70\x71','\x44\x76\x4c\x78\x43\x75\x53','\x43\x31\x44\x66\x43\x4e\x4f','\x71\x4e\x76\x55\x7a\x67\x58\x4c\x43\x49\x62\x59\x7a\x78\x6e\x57\x42\x32\x35\x5a\x7a\x73\x62\x4d\x42\x33\x69\x47\x44\x68\x6a\x48\x42\x4e\x6e\x4d\x7a\x78\x69\x36\x69\x61','\x43\x66\x4c\x6d\x77\x68\x61','\x76\x4e\x6e\x48\x7a\x77\x4b','\x7a\x78\x72\x4f\x78\x33\x6e\x4c\x42\x4d\x72\x76\x43\x32\x76\x59\x74\x33\x62\x4c\x43\x4d\x66\x30\x41\x77\x39\x55','\x74\x77\x6e\x7a\x7a\x33\x43','\x41\x67\x76\x34\x42\x67\x4c\x4d\x45\x71','\x69\x6f\x6b\x45\x52\x59\x61','\x45\x4d\x58\x33\x42\x4b\x4b','\x41\x75\x72\x54\x43\x68\x75','\x73\x75\x39\x36\x74\x4e\x79','\x7a\x4d\x58\x56\x42\x33\x69','\x44\x65\x50\x4d\x76\x65\x4b','\x7a\x31\x6e\x52\x74\x65\x71','\x7a\x4e\x76\x55\x79\x33\x72\x50\x42\x32\x34\x47\x7a\x78\x48\x4c\x79\x33\x76\x30\x7a\x75\x6a\x48\x44\x67\x6e\x4f\x6b\x67\x66\x4b\x7a\x68\x6a\x4c\x43\x33\x6e\x42\x78\x73\x62\x4a\x79\x77\x58\x53\x7a\x67\x66\x30\x79\x73\x62\x4b\x7a\x78\x6e\x30\x6c\x63\x62\x31\x41\x77\x35\x30\x6d\x4a\x75\x32\x77\x31\x30\x47\x79\x32\x66\x53\x42\x67\x72\x48\x44\x67\x65\x47\x44\x4d\x66\x53\x44\x77\x75\x53\x69\x67\x6a\x35\x44\x67\x76\x5a\x77\x31\x30\x47\x79\x32\x66\x53\x42\x67\x72\x48\x44\x67\x65\x47\x7a\x4e\x76\x55\x79\x59\x4b\x47\x7a\x78\x48\x30\x7a\x78\x6a\x55\x79\x77\x57','\x77\x67\x31\x64\x7a\x76\x69','\x7a\x32\x58\x66\x44\x68\x79','\x75\x33\x44\x48\x43\x63\x62\x75\x43\x4d\x66\x55\x43\x32\x66\x4a\x44\x67\x4c\x56\x42\x49\x62\x5a\x7a\x77\x35\x30\x6f\x49\x61','\x6e\x5a\x6d\x57\x6e\x4a\x79\x35\x6d\x66\x7a\x35\x72\x65\x54\x59\x73\x61'];a0_0x3b4b=function(){return _0x1511b0;};return a0_0x3b4b();}async function performSwap(_0x55e81b,_0x23b57f,_0x5354b6,_0x1291bf,_0x56d465,_0x4ae858){const _0x4fcc2b=a0_0x5aa4,_0x1d9c82={'\x46\x59\x54\x4f\x64':_0x4fcc2b(0x159),'\x49\x4f\x7a\x4e\x76':'\x41\x41\x32\x35\x20\x69\x6e\x76\x61\x6c\x69\x64\x20\x61\x63\x63\x6f\x75\x6e\x74\x20\x6e\x6f\x6e\x63\x65','\x64\x6f\x61\x74\x63':function(_0x3b701e,_0x33a0f8,_0xcb23ec){return _0x3b701e(_0x33a0f8,_0xcb23ec);},'\x6f\x57\x67\x64\x63':_0x4fcc2b(0x166),'\x74\x5a\x50\x41\x6f':_0x4fcc2b(0x153),'\x6f\x62\x4d\x6d\x56':'\x54\x43\x45\x4e\x54','\x72\x68\x4a\x63\x45':function(_0x22235a,_0x129998){return _0x22235a(_0x129998);},'\x4c\x55\x58\x57\x51':function(_0x5a2af9,_0x2407a3){return _0x5a2af9!==_0x2407a3;},'\x58\x6d\x43\x65\x52':'\x77\x66\x55\x48\x57','\x50\x55\x57\x4c\x44':function(_0x22b16e,_0x5a3a85){return _0x22b16e!==_0x5a3a85;},'\x50\x74\x42\x44\x75':_0x4fcc2b(0x117),'\x49\x4d\x45\x45\x47':_0x4fcc2b(0x12b),'\x5a\x54\x55\x72\x56':'\x57\x76\x67\x44\x75','\x71\x49\x6e\x51\x70':_0x4fcc2b(0x14d),'\x78\x79\x41\x45\x57':function(_0x381d3a,_0x16f03c,_0x5a7868,_0x377a06,_0x16b801,_0x3b767f){return _0x381d3a(_0x16f03c,_0x5a7868,_0x377a06,_0x16b801,_0x3b767f);},'\x62\x45\x50\x71\x50':_0x4fcc2b(0x123),'\x6d\x65\x43\x7a\x46':function(_0x550f12,_0x5f536){return _0x550f12===_0x5f536;},'\x55\x6c\x6a\x47\x7a':function(_0x930c26,_0x2f4849){return _0x930c26+_0x2f4849;},'\x55\x7a\x6c\x70\x50':function(_0x2324ad,_0x1a9f0d){return _0x2324ad/_0x1a9f0d;},'\x70\x4b\x55\x57\x46':_0x4fcc2b(0x93),'\x61\x49\x45\x62\x6c':_0x4fcc2b(0x157),'\x4d\x63\x59\x67\x77':_0x4fcc2b(0x152),'\x75\x46\x6b\x54\x65':'\x73\x77\x61\x70\x45\x78\x61\x63\x74\x54\x6f\x6b\x65\x6e\x73\x46\x6f\x72\x45\x54\x48','\x74\x4a\x66\x54\x49':_0x4fcc2b(0xe7),'\x6b\x47\x6e\x6d\x63':_0x4fcc2b(0x72),'\x48\x70\x72\x79\x6f':_0x4fcc2b(0x16b),'\x62\x65\x4c\x47\x6d':function(_0x159155,_0x3763d9,_0x20f354){return _0x159155(_0x3763d9,_0x20f354);},'\x4b\x68\x7a\x4d\x71':function(_0x350e7f,_0x48aab3,_0x1b17dd,_0x5a8377){return _0x350e7f(_0x48aab3,_0x1b17dd,_0x5a8377);},'\x4c\x6f\x42\x75\x49':_0x4fcc2b(0x82),'\x6a\x75\x42\x74\x77':_0x4fcc2b(0x128),'\x68\x6b\x4c\x74\x67':function(_0x4e058e,_0x4be0f4,_0x1bd983){return _0x4e058e(_0x4be0f4,_0x1bd983);},'\x4a\x54\x73\x4a\x59':_0x4fcc2b(0xf3),'\x58\x52\x71\x65\x6e':'\x31\x2e\x35','\x44\x69\x5a\x48\x70':_0x4fcc2b(0xd7),'\x78\x61\x64\x67\x71':function(_0x23a1d7,_0x1c05ca){return _0x23a1d7>_0x1c05ca;},'\x71\x64\x73\x6d\x71':_0x4fcc2b(0x168),'\x58\x41\x4c\x67\x49':_0x4fcc2b(0xbf),'\x4e\x43\x4a\x6c\x54':function(_0xccd764,_0x3c943a){return _0xccd764(_0x3c943a);},'\x56\x61\x64\x54\x42':'\x73\x75\x63\x63\x65\x73\x73','\x66\x6a\x66\x6e\x42':'\x59\x58\x66\x68\x46'},_0x3e080c=new ethers[(_0x4fcc2b(0x76))](_0x55e81b[_0x4fcc2b(0xe3)],_0x4ae858),_0x46feb3=ethers[_0x4fcc2b(0x11f)]['\x70\x61\x72\x73\x65\x45\x74\x68\x65\x72'](_0x1291bf[_0x4fcc2b(0xd8)]()),_0x44efa6=_0x5354b6?ZERO_ADDRESS:_0x23b57f,_0x521b76=_0x5354b6?_0x23b57f:ZERO_ADDRESS,_0x4c77cb=_0x5354b6?_0x1d9c82[_0x4fcc2b(0x99)]:_0x1d9c82[_0x4fcc2b(0x7e)](getTokenName,_0x23b57f),_0x1ad2c1=_0x5354b6?_0x1d9c82['\x72\x68\x4a\x63\x45'](getTokenName,_0x23b57f):'\x54\x43\x45\x4e\x54',_0x450a90=await _0x4ae858[_0x4fcc2b(0x141)](_0x55e81b[_0x4fcc2b(0xe4)]),_0x27c304=ethers[_0x4fcc2b(0x11f)]['\x70\x61\x72\x73\x65\x45\x74\x68\x65\x72'](_0x4fcc2b(0x137));if(_0x450a90['\x6c\x74'](_0x27c304)){if(_0x1d9c82[_0x4fcc2b(0xad)](_0x4fcc2b(0x77),_0x1d9c82[_0x4fcc2b(0xca)]))throw new _0x8836da(_0x1d9c82[_0x4fcc2b(0x7c)]);else throw new Error(_0x4fcc2b(0x94)+_0x27c304[_0x4fcc2b(0xd8)]()+'\x29');}if(!_0x5354b6){if(_0x1d9c82[_0x4fcc2b(0x85)](_0x1d9c82[_0x4fcc2b(0xe8)],_0x4fcc2b(0x117))){_0x56957a['\x6d\x65\x73\x73\x61\x67\x65'][_0x4fcc2b(0xd1)](_0x1d9c82[_0x4fcc2b(0xc5)])&&(_0x1d9c82[_0x4fcc2b(0x12e)](_0x2c1ebb,_0x4fcc2b(0x154),_0x1d9c82['\x6f\x57\x67\x64\x63']),delete _0x307536[_0x13609d[_0x4fcc2b(0xe4)]]);_0x3d8183('\x53\x77\x61\x70\x20\x66\x61\x69\x6c\x65\x64\x3a\x20'+_0x42ca7a[_0x4fcc2b(0xaf)],_0x1d9c82[_0x4fcc2b(0x10a)]);throw _0x50ea4a;}else{const _0x551c01=[_0x1d9c82['\x49\x4d\x45\x45\x47']],_0x487e3e=new ethers[(_0x4fcc2b(0xd2))](_0x23b57f,_0x551c01,_0x4ae858),_0x1b154e=await _0x487e3e['\x62\x61\x6c\x61\x6e\x63\x65\x4f\x66'](_0x55e81b['\x73\x6d\x61\x72\x74\x41\x64\x64\x72\x65\x73\x73']);if(_0x1b154e['\x6c\x74'](_0x46feb3)){if(_0x1d9c82[_0x4fcc2b(0xab)]!==_0x1d9c82['\x71\x49\x6e\x51\x70'])throw new Error('\x49\x6e\x73\x75\x66\x66\x69\x63\x69\x65\x6e\x74\x20'+_0x1ad2c1+'\x20\x62\x61\x6c\x61\x6e\x63\x65');else{_0xf8b6b8[_0x4fcc2b(0xaf)][_0x4fcc2b(0xd1)](_0x1d9c82['\x49\x4f\x7a\x4e\x76'])&&(_0x1b640a(_0x4fcc2b(0x154),_0x1d9c82[_0x4fcc2b(0x6f)]),delete _0x20fea0[_0x3201f5[_0x4fcc2b(0xe4)]]);_0x724e88(_0x4fcc2b(0x108)+_0x3ca30a[_0x4fcc2b(0xaf)],_0x1d9c82[_0x4fcc2b(0x10a)]);throw _0x394606;}}}}const _0x1633e5=await _0x1d9c82[_0x4fcc2b(0x89)](makeApiCall,_0x4fcc2b(0xb1)+_0x44efa6+_0x4fcc2b(0xb9)+_0x521b76,_0x1d9c82[_0x4fcc2b(0x13d)],null,_0x56d465,_0x55e81b[_0x4fcc2b(0x9b)]);if(!_0x1633e5?.[_0x4fcc2b(0xfb)]||_0x1d9c82[_0x4fcc2b(0x118)](_0x1633e5[_0x4fcc2b(0xfb)]['\x6c\x65\x6e\x67\x74\x68'],0x0))throw new Error(_0x1d9c82[_0x4fcc2b(0x7c)]);const _0x4602bc=_0x1633e5['\x72\x65\x73\x75\x6c\x74'][0x0],_0x1f5a76=_0x4602bc[_0x4fcc2b(0x14a)]['\x6d\x61\x70'](_0x221953=>ethers[_0x4fcc2b(0x11f)][_0x4fcc2b(0xe1)](_0x221953)),_0x2c300c=_0x1d9c82[_0x4fcc2b(0xf0)](Math[_0x4fcc2b(0xc6)](_0x1d9c82[_0x4fcc2b(0x91)](Date['\x6e\x6f\x77'](),0x3e8)),0x4b0),_0x256050=[_0x1d9c82[_0x4fcc2b(0xfe)],_0x4fcc2b(0x16f)],_0x5e18a2=new ethers[(_0x4fcc2b(0x11f))][(_0x4fcc2b(0x74))](_0x256050),_0x2b2c24=[_0x1d9c82['\x61\x49\x45\x62\x6c'],_0x4fcc2b(0xf8)],_0x503b51=new ethers[(_0x4fcc2b(0x11f))][(_0x4fcc2b(0x74))](_0x2b2c24),_0x32c523=[_0x4fcc2b(0x114)],_0x3bfd5d=new ethers[(_0x4fcc2b(0x11f))]['\x49\x6e\x74\x65\x72\x66\x61\x63\x65'](_0x32c523);let _0xa09896;if(_0x5354b6){const _0x4ebf4d=_0x5e18a2[_0x4fcc2b(0xef)](_0x1d9c82[_0x4fcc2b(0xc0)],[0x0,_0x1f5a76,_0x55e81b[_0x4fcc2b(0xe4)],_0x2c300c]);_0xa09896=_0x503b51[_0x4fcc2b(0xef)](_0x4fcc2b(0x14f),[ROUTER,_0x46feb3,_0x4ebf4d]);}else{const _0xec7fc5=_0x3bfd5d[_0x4fcc2b(0xef)](_0x4fcc2b(0x7d),[ROUTER,_0x46feb3]),_0x7ba90b=_0x5e18a2[_0x4fcc2b(0xef)](_0x1d9c82['\x75\x46\x6b\x54\x65'],[_0x46feb3,0x0,_0x1f5a76,_0x55e81b[_0x4fcc2b(0xe4)],_0x2c300c]);_0xa09896=_0x503b51[_0x4fcc2b(0xef)](_0x1d9c82[_0x4fcc2b(0xc7)],[[_0x23b57f,ROUTER],[0x0,0x0],[_0xec7fc5,_0x7ba90b]]);}const _0x2d3d86=[_0x4fcc2b(0x11a)],_0x554d84=new ethers[(_0x4fcc2b(0xd2))](ENTRY_POINT,_0x2d3d86,_0x4ae858);let _0x38ee51;try{if(_0x1d9c82[_0x4fcc2b(0x118)](_0x1d9c82[_0x4fcc2b(0x13b)],_0x1d9c82['\x48\x70\x72\x79\x6f'])){_0x247eae[_0x4fcc2b(0xaf)][_0x4fcc2b(0xd1)](_0x1d9c82['\x49\x4f\x7a\x4e\x76'])&&(_0x1d9c82[_0x4fcc2b(0x12e)](_0x4f6350,_0x4fcc2b(0x154),_0x1d9c82[_0x4fcc2b(0x6f)]),delete _0x3d03d8[_0x333868[_0x4fcc2b(0xe4)]]);_0x5516c4(_0x4fcc2b(0x15d)+_0xb5b777[_0x4fcc2b(0xaf)],_0x1d9c82[_0x4fcc2b(0x10a)]);throw _0x3d6021;}else{const _0x44fb6f=await _0x554d84[_0x4fcc2b(0x164)](_0x55e81b[_0x4fcc2b(0xe4)],0x0);_0x1d9c82['\x64\x6f\x61\x74\x63'](addLog,_0x4fcc2b(0xb7)+_0x44fb6f[_0x4fcc2b(0xd8)](),_0x4fcc2b(0xf3)),!nonceTracker[_0x55e81b[_0x4fcc2b(0xe4)]]&&(nonceTracker[_0x55e81b['\x73\x6d\x61\x72\x74\x41\x64\x64\x72\x65\x73\x73']]=_0x44fb6f),_0x38ee51=nonceTracker[_0x55e81b[_0x4fcc2b(0xe4)]];}}catch(_0x179f24){_0x1d9c82[_0x4fcc2b(0x171)](addLog,_0x4fcc2b(0x84)+_0x179f24[_0x4fcc2b(0xaf)],_0x1d9c82[_0x4fcc2b(0x10a)]);throw _0x179f24;}const _0x1f92dd={'\x73\x65\x6e\x64\x65\x72':ethers[_0x4fcc2b(0x11f)][_0x4fcc2b(0xe1)](_0x55e81b[_0x4fcc2b(0xe4)]),'\x6e\x6f\x6e\x63\x65':ethers[_0x4fcc2b(0x11f)][_0x4fcc2b(0xc1)](_0x38ee51),'\x69\x6e\x69\x74\x43\x6f\x64\x65':'\x30\x78','\x63\x61\x6c\x6c\x44\x61\x74\x61':_0xa09896},_0xa93db7='\x30\x78\x66\x66\x66\x66\x66\x66\x66\x66\x66\x66\x66\x66\x66\x66\x66\x66\x66\x66\x66\x66\x66\x66\x66\x66\x66\x66\x66\x66\x66\x66\x66\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x37\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x31\x63';try{const _0x1a9b5b=await _0x1d9c82[_0x4fcc2b(0x13c)](makeBundlerCall,_0x1d9c82[_0x4fcc2b(0x8b)],[{..._0x1f92dd,'\x73\x69\x67\x6e\x61\x74\x75\x72\x65':_0xa93db7},ENTRY_POINT],_0x56d465),_0x347fdc=_0x1a9b5b['\x72\x65\x73\x75\x6c\x74'];if(!_0x347fdc)throw new Error(_0x1d9c82['\x6a\x75\x42\x74\x77']);_0x1d9c82[_0x4fcc2b(0xb2)](addLog,_0x4fcc2b(0xd9)+JSON[_0x4fcc2b(0x16c)](_0x347fdc,null,0x2),_0x1d9c82[_0x4fcc2b(0x142)]);const _0xeea337=ethers[_0x4fcc2b(0x13e)][_0x4fcc2b(0x177)](_0x347fdc[_0x4fcc2b(0x16d)])['\x61\x64\x64'](0x1388),_0x4d0f08=ethers['\x42\x69\x67\x4e\x75\x6d\x62\x65\x72'][_0x4fcc2b(0x177)](_0x347fdc[_0x4fcc2b(0x15b)])['\x61\x64\x64'](0x1388),_0x4aa04e=ethers[_0x4fcc2b(0x13e)][_0x4fcc2b(0x177)](_0x347fdc['\x76\x65\x72\x69\x66\x69\x63\x61\x74\x69\x6f\x6e\x47\x61\x73\x4c\x69\x6d\x69\x74'])[_0x4fcc2b(0x175)](0x1388),_0x1d2583=await _0x4ae858['\x67\x65\x74\x46\x65\x65\x44\x61\x74\x61'](),_0x525703=_0x1d2583?.[_0x4fcc2b(0xb0)]||ethers[_0x4fcc2b(0x11f)][_0x4fcc2b(0x103)](_0x1d9c82['\x58\x52\x71\x65\x6e'],_0x4fcc2b(0x106)),_0x334df6=_0x1d2583?.['\x6d\x61\x78\x50\x72\x69\x6f\x72\x69\x74\x79\x46\x65\x65\x50\x65\x72\x47\x61\x73']||ethers[_0x4fcc2b(0x11f)]['\x70\x61\x72\x73\x65\x55\x6e\x69\x74\x73'](_0x1d9c82['\x58\x52\x71\x65\x6e'],_0x4fcc2b(0x106)),_0x913f48={..._0x1f92dd,'\x63\x61\x6c\x6c\x47\x61\x73\x4c\x69\x6d\x69\x74':ethers[_0x4fcc2b(0x11f)][_0x4fcc2b(0xc1)](_0x4d0f08),'\x76\x65\x72\x69\x66\x69\x63\x61\x74\x69\x6f\x6e\x47\x61\x73\x4c\x69\x6d\x69\x74':ethers['\x75\x74\x69\x6c\x73'][_0x4fcc2b(0xc1)](_0x4aa04e),'\x70\x72\x65\x56\x65\x72\x69\x66\x69\x63\x61\x74\x69\x6f\x6e\x47\x61\x73':ethers['\x75\x74\x69\x6c\x73'][_0x4fcc2b(0xc1)](_0xeea337),'\x6d\x61\x78\x46\x65\x65\x50\x65\x72\x47\x61\x73':ethers[_0x4fcc2b(0x11f)]['\x68\x65\x78\x6c\x69\x66\x79'](_0x525703),'\x6d\x61\x78\x50\x72\x69\x6f\x72\x69\x74\x79\x46\x65\x65\x50\x65\x72\x47\x61\x73':ethers[_0x4fcc2b(0x11f)][_0x4fcc2b(0xc1)](_0x334df6),'\x73\x69\x67\x6e\x61\x74\x75\x72\x65':_0xa93db7},_0x4800ca=ethers['\x42\x69\x67\x4e\x75\x6d\x62\x65\x72']['\x66\x72\x6f\x6d'](_0x4aa04e)[_0x4fcc2b(0xf2)](0x80)['\x61\x64\x64'](ethers[_0x4fcc2b(0x13e)]['\x66\x72\x6f\x6d'](_0x4d0f08)),_0x1038d2=ethers['\x42\x69\x67\x4e\x75\x6d\x62\x65\x72'][_0x4fcc2b(0x177)](_0x334df6)['\x73\x68\x6c'](0x80)[_0x4fcc2b(0x175)](ethers[_0x4fcc2b(0x13e)][_0x4fcc2b(0x177)](_0x525703)),_0x29d109={'\x73\x65\x6e\x64\x65\x72':ethers[_0x4fcc2b(0x11f)][_0x4fcc2b(0xe1)](_0x55e81b[_0x4fcc2b(0xe4)]),'\x6e\x6f\x6e\x63\x65':_0x38ee51,'\x69\x6e\x69\x74\x43\x6f\x64\x65':'\x30\x78','\x63\x61\x6c\x6c\x44\x61\x74\x61':_0xa09896,'\x61\x63\x63\x6f\x75\x6e\x74\x47\x61\x73\x4c\x69\x6d\x69\x74\x73':ethers[_0x4fcc2b(0x11f)][_0x4fcc2b(0x126)](_0x4800ca[_0x4fcc2b(0x173)](),0x20),'\x70\x72\x65\x56\x65\x72\x69\x66\x69\x63\x61\x74\x69\x6f\x6e\x47\x61\x73':ethers[_0x4fcc2b(0x13e)][_0x4fcc2b(0x177)](_0xeea337),'\x67\x61\x73\x46\x65\x65\x73':ethers[_0x4fcc2b(0x11f)][_0x4fcc2b(0x126)](_0x1038d2['\x74\x6f\x48\x65\x78\x53\x74\x72\x69\x6e\x67'](),0x20),'\x70\x61\x79\x6d\x61\x73\x74\x65\x72\x41\x6e\x64\x44\x61\x74\x61':'\x30\x78','\x73\x69\x67\x6e\x61\x74\x75\x72\x65':'\x30\x78'},_0x4dfb25=[_0x1d9c82['\x44\x69\x5a\x48\x70']],_0x58f13c=new ethers['\x43\x6f\x6e\x74\x72\x61\x63\x74'](ENTRY_POINT,_0x4dfb25,_0x4ae858),_0x49a0ca=await _0x58f13c['\x67\x65\x74\x55\x73\x65\x72\x4f\x70\x48\x61\x73\x68'](_0x29d109);addLog('\x75\x73\x65\x72\x4f\x70\x48\x61\x73\x68\x20\x66\x72\x6f\x6d\x20\x45\x6e\x74\x72\x79\x50\x6f\x69\x6e\x74\x2e\x67\x65\x74\x55\x73\x65\x72\x4f\x70\x48\x61\x73\x68\x3a\x20'+_0x49a0ca,_0x1d9c82[_0x4fcc2b(0x142)]);const _0x346c87=await _0x3e080c[_0x4fcc2b(0xb4)](ethers['\x75\x74\x69\x6c\x73'][_0x4fcc2b(0xee)](_0x49a0ca)),_0xd49a71=0x0,_0x1dd1e4=_0x55e81b[_0x4fcc2b(0x75)]||0x1,_0x44eba8=ethers[_0x4fcc2b(0x11f)][_0x4fcc2b(0x126)](ethers['\x75\x74\x69\x6c\x73'][_0x4fcc2b(0xc1)](_0xd49a71),0x1),_0xce8dfd=ethers['\x75\x74\x69\x6c\x73']['\x68\x65\x78\x5a\x65\x72\x6f\x50\x61\x64'](ethers[_0x4fcc2b(0x11f)][_0x4fcc2b(0xc1)](_0x1dd1e4),0x2),_0x3ad1ed=ethers[_0x4fcc2b(0x11f)][_0x4fcc2b(0x8e)]([_0x44eba8,_0xce8dfd,_0x346c87]);_0x913f48[_0x4fcc2b(0x136)]=_0x3ad1ed;const _0xe6c712={..._0x913f48};_0xe6c712['\x63\x61\x6c\x6c\x44\x61\x74\x61']=_0xe6c712['\x63\x61\x6c\x6c\x44\x61\x74\x61']?_0xe6c712['\x63\x61\x6c\x6c\x44\x61\x74\x61'][_0x4fcc2b(0x158)](0x0,0xc8)+(_0x1d9c82[_0x4fcc2b(0x107)](_0xe6c712[_0x4fcc2b(0x115)][_0x4fcc2b(0x146)],0xc8)?_0x1d9c82[_0x4fcc2b(0x120)]:''):_0xe6c712['\x63\x61\x6c\x6c\x44\x61\x74\x61'],_0xe6c712[_0x4fcc2b(0x136)]=_0xe6c712[_0x4fcc2b(0x136)][_0x4fcc2b(0x158)](0x0,0xc)+_0x1d9c82[_0x4fcc2b(0x120)],addLog(_0x4fcc2b(0x163)+JSON[_0x4fcc2b(0x16c)](_0xe6c712,null,0x2),_0x1d9c82[_0x4fcc2b(0x142)]);const _0x449853=await _0x1d9c82['\x4b\x68\x7a\x4d\x71'](makeBundlerCall,_0x1d9c82[_0x4fcc2b(0x90)],[_0x913f48,ENTRY_POINT],_0x56d465);addLog('\x42\x75\x6e\x64\x6c\x65\x72\x20\x72\x65\x73\x70\x6f\x6e\x73\x65\x3a\x20'+JSON['\x73\x74\x72\x69\x6e\x67\x69\x66\x79'](_0x449853,null,0x2),_0x4fcc2b(0xf3));const _0x486d69=_0x449853['\x72\x65\x73\x75\x6c\x74'];_0x1d9c82[_0x4fcc2b(0x171)](addLog,_0x4fcc2b(0xcc)+getShortHash(_0x486d69),_0x1d9c82[_0x4fcc2b(0x6f)]);const _0x66f12d={'\x74\x78\x48\x61\x73\x68':_0x486d69,'\x62\x61\x64\x67\x65\x4b\x65\x79':_0x4fcc2b(0xdd)};return await makeApiCall(_0x4fcc2b(0x170),_0x4fcc2b(0xd6),_0x66f12d,_0x56d465,_0x55e81b[_0x4fcc2b(0x9b)]),addLog(_0x4fcc2b(0xd5)+_0x1291bf+'\x20'+_0x4c77cb+_0x4fcc2b(0xc2)+_0x1ad2c1+_0x4fcc2b(0x169)+_0x1d9c82['\x4e\x43\x4a\x6c\x54'](getShortHash,_0x486d69),_0x1d9c82[_0x4fcc2b(0xff)]),nonceTracker[_0x55e81b[_0x4fcc2b(0xe4)]]=_0x38ee51['\x61\x64\x64'](0x1),_0x486d69;}catch(_0x3cd78e){if(_0x3cd78e[_0x4fcc2b(0xaf)][_0x4fcc2b(0xd1)](_0x1d9c82['\x49\x4f\x7a\x4e\x76'])){if(_0x1d9c82[_0x4fcc2b(0x85)](_0x1d9c82[_0x4fcc2b(0x174)],_0x1d9c82[_0x4fcc2b(0x174)]))throw new _0x50491a(_0x4fcc2b(0x159));else _0x1d9c82[_0x4fcc2b(0xb2)](addLog,'\x52\x65\x73\x65\x74\x74\x69\x6e\x67\x20\x6e\x6f\x6e\x63\x65\x20\x74\x72\x61\x63\x6b\x65\x72\x20\x64\x75\x65\x20\x74\x6f\x20\x69\x6e\x76\x61\x6c\x69\x64\x20\x6e\x6f\x6e\x63\x65\x20\x65\x72\x72\x6f\x72\x2e',_0x1d9c82[_0x4fcc2b(0x6f)]),delete nonceTracker[_0x55e81b[_0x4fcc2b(0xe4)]];}_0x1d9c82[_0x4fcc2b(0x171)](addLog,_0x4fcc2b(0x92)+_0x3cd78e[_0x4fcc2b(0xaf)],_0x1d9c82[_0x4fcc2b(0x10a)]);throw _0x3cd78e;}}async function performTransfer(_0x316a61,_0x4951a2,_0x578074,_0x46cb20){const _0x5d0fee=a0_0x5aa4,_0x3777e2={'\x57\x6a\x73\x67\x43':function(_0x194719,_0x16ef6f){return _0x194719*_0x16ef6f;},'\x68\x4c\x4b\x4a\x4d':function(_0x4f2145,_0x40e564){return _0x4f2145===_0x40e564;},'\x56\x56\x6a\x4b\x48':function(_0x297e14,_0x5bdd28){return _0x297e14+_0x5bdd28;},'\x49\x67\x75\x64\x52':function(_0x366250,_0x4b8930){return _0x366250*_0x4b8930;},'\x77\x79\x6d\x6d\x59':function(_0x21dc90,_0x483ce4){return _0x21dc90-_0x483ce4;},'\x76\x6c\x62\x67\x51':function(_0x374dc9,_0x343674,_0xd970cd){return _0x374dc9(_0x343674,_0xd970cd);},'\x52\x4c\x47\x78\x41':_0x5d0fee(0x140),'\x4a\x6a\x4e\x4d\x53':'\x73\x77\x61\x70\x45\x78\x61\x63\x74\x45\x54\x48\x46\x6f\x72\x54\x6f\x6b\x65\x6e\x73','\x72\x4c\x61\x78\x6e':_0x5d0fee(0x14f),'\x45\x47\x71\x79\x70':_0x5d0fee(0x7d),'\x4a\x6b\x62\x48\x50':_0x5d0fee(0x70),'\x4f\x68\x59\x74\x49':'\x65\x78\x65\x63\x75\x74\x65\x42\x61\x74\x63\x68','\x50\x6c\x41\x6d\x4f':function(_0x5d8ab5,_0x33ed9b){return _0x5d8ab5===_0x33ed9b;},'\x53\x44\x76\x4d\x76':function(_0x54ab85,_0x4a1e67,_0x1e3341){return _0x54ab85(_0x4a1e67,_0x1e3341);},'\x4f\x79\x50\x4b\x45':function(_0x274488,_0x4eeac5){return _0x274488(_0x4eeac5);},'\x76\x72\x52\x71\x52':_0x5d0fee(0x166),'\x57\x6a\x44\x59\x49':function(_0x282705,_0x2bb32f){return _0x282705*_0x2bb32f;},'\x71\x6a\x69\x73\x58':function(_0x2221f6,_0x24b33e){return _0x2221f6*_0x24b33e;},'\x4d\x6e\x53\x63\x6d':_0x5d0fee(0x11e),'\x62\x4d\x6e\x78\x41':'\x30\x2e\x30\x31','\x65\x41\x57\x59\x62':function(_0x29df87,_0x3c5c1b){return _0x29df87*_0x3c5c1b;},'\x6e\x4a\x4f\x76\x71':function(_0x23a705,_0x523b84){return _0x23a705===_0x523b84;},'\x59\x68\x64\x59\x45':_0x5d0fee(0xa0),'\x6b\x4d\x78\x73\x72':function(_0x440fec,_0x1234b3){return _0x440fec(_0x1234b3);},'\x67\x53\x4a\x75\x53':function(_0x3e80a1,_0x4b951c){return _0x3e80a1(_0x4b951c);},'\x44\x4b\x57\x57\x45':_0x5d0fee(0x157),'\x79\x74\x76\x54\x6f':function(_0x1742d7,_0x329a49){return _0x1742d7!==_0x329a49;},'\x46\x6c\x67\x71\x49':_0x5d0fee(0x10c),'\x4e\x50\x50\x46\x65':_0x5d0fee(0xe5),'\x76\x4b\x64\x56\x74':function(_0x3f7441,_0x34a86f){return _0x3f7441!==_0x34a86f;},'\x72\x71\x46\x59\x59':_0x5d0fee(0xa2),'\x57\x47\x71\x4c\x42':'\x65\x72\x72\x6f\x72','\x43\x74\x47\x76\x69':_0x5d0fee(0x9c),'\x41\x43\x55\x42\x69':'\x4e\x71\x67\x63\x62','\x61\x44\x6d\x6a\x65':'\x67\x4f\x47\x6d\x76','\x6a\x4d\x6e\x59\x4c':function(_0x57306f,_0xb0db4d,_0x2763af,_0x1ad0b6){return _0x57306f(_0xb0db4d,_0x2763af,_0x1ad0b6);},'\x51\x46\x4e\x55\x43':_0x5d0fee(0x82),'\x52\x4b\x4d\x55\x5a':_0x5d0fee(0x128),'\x73\x57\x45\x72\x7a':_0x5d0fee(0xf3),'\x69\x44\x6d\x70\x75':_0x5d0fee(0x106),'\x70\x72\x45\x53\x4f':_0x5d0fee(0x73),'\x61\x58\x6c\x7a\x4a':'\x66\x75\x6e\x63\x74\x69\x6f\x6e\x20\x67\x65\x74\x55\x73\x65\x72\x4f\x70\x48\x61\x73\x68\x28\x74\x75\x70\x6c\x65\x28\x61\x64\x64\x72\x65\x73\x73\x20\x73\x65\x6e\x64\x65\x72\x2c\x75\x69\x6e\x74\x32\x35\x36\x20\x6e\x6f\x6e\x63\x65\x2c\x62\x79\x74\x65\x73\x20\x69\x6e\x69\x74\x43\x6f\x64\x65\x2c\x62\x79\x74\x65\x73\x20\x63\x61\x6c\x6c\x44\x61\x74\x61\x2c\x62\x79\x74\x65\x73\x33\x32\x20\x61\x63\x63\x6f\x75\x6e\x74\x47\x61\x73\x4c\x69\x6d\x69\x74\x73\x2c\x75\x69\x6e\x74\x32\x35\x36\x20\x70\x72\x65\x56\x65\x72\x69\x66\x69\x63\x61\x74\x69\x6f\x6e\x47\x61\x73\x2c\x62\x79\x74\x65\x73\x33\x32\x20\x67\x61\x73\x46\x65\x65\x73\x2c\x62\x79\x74\x65\x73\x20\x70\x61\x79\x6d\x61\x73\x74\x65\x72\x41\x6e\x64\x44\x61\x74\x61\x2c\x62\x79\x74\x65\x73\x20\x73\x69\x67\x6e\x61\x74\x75\x72\x65\x29\x20\x75\x73\x65\x72\x4f\x70\x29\x20\x76\x69\x65\x77\x20\x72\x65\x74\x75\x72\x6e\x73\x20\x28\x62\x79\x74\x65\x73\x33\x32\x29','\x70\x63\x67\x4c\x66':function(_0xe11ec5,_0x469314,_0x2a4d32){return _0xe11ec5(_0x469314,_0x2a4d32);},'\x45\x6f\x4b\x72\x43':function(_0x1a478d,_0x26619c){return _0x1a478d>_0x26619c;},'\x57\x6c\x69\x58\x44':_0x5d0fee(0x168),'\x79\x43\x49\x72\x4c':function(_0x315f39,_0x350532,_0x4b7b51,_0x2a5ff8){return _0x315f39(_0x350532,_0x4b7b51,_0x2a5ff8);},'\x6b\x4b\x78\x5a\x4d':_0x5d0fee(0xbf),'\x45\x6d\x44\x45\x78':function(_0x27dbaf,_0x391fc3){return _0x27dbaf(_0x391fc3);},'\x71\x74\x69\x4b\x43':function(_0x28dbf7,_0x857d30,_0x4205f6,_0x5e867e,_0x5b539e,_0x5a1385){return _0x28dbf7(_0x857d30,_0x4205f6,_0x5e867e,_0x5b539e,_0x5a1385);},'\x6d\x4a\x6e\x7a\x6a':'\x50\x4f\x53\x54','\x61\x5a\x43\x72\x6d':_0x5d0fee(0xe6),'\x67\x67\x48\x75\x6f':_0x5d0fee(0xd0),'\x52\x66\x4d\x4b\x6e':'\x41\x41\x32\x35\x20\x69\x6e\x76\x61\x6c\x69\x64\x20\x61\x63\x63\x6f\x75\x6e\x74\x20\x6e\x6f\x6e\x63\x65'};if(recipients['\x6c\x65\x6e\x67\x74\x68']===0x0)throw new Error(_0x3777e2['\x4d\x6e\x53\x63\x6d']);const _0x5afd62=new ethers[(_0x5d0fee(0x76))](_0x316a61[_0x5d0fee(0xe3)],_0x46cb20),_0x2ed539=ethers[_0x5d0fee(0x11f)]['\x70\x61\x72\x73\x65\x45\x74\x68\x65\x72'](_0x4951a2[_0x5d0fee(0xd8)]()),_0x35041c=await _0x46cb20[_0x5d0fee(0x141)](_0x316a61['\x73\x6d\x61\x72\x74\x41\x64\x64\x72\x65\x73\x73']),_0x16efc5=ethers[_0x5d0fee(0x11f)][_0x5d0fee(0x68)](_0x3777e2[_0x5d0fee(0xb8)]);if(_0x35041c['\x6c\x74'](_0x2ed539[_0x5d0fee(0x175)](_0x16efc5)))throw new Error('\x49\x6e\x73\x75\x66\x66\x69\x63\x69\x65\x6e\x74\x20\x54\x43\x45\x4e\x54\x20\x62\x61\x6c\x61\x6e\x63\x65\x20\x66\x6f\x72\x20\x74\x72\x61\x6e\x73\x66\x65\x72\x20\x61\x6e\x64\x20\x67\x61\x73');let _0x17fe73;do{const _0x6c6d1f=Math['\x66\x6c\x6f\x6f\x72'](_0x3777e2['\x65\x41\x57\x59\x62'](Math['\x72\x61\x6e\x64\x6f\x6d'](),recipients[_0x5d0fee(0x146)]));_0x17fe73=recipients[_0x6c6d1f];if(_0x3777e2['\x68\x4c\x4b\x4a\x4d'](_0x17fe73[_0x5d0fee(0xf5)](),_0x316a61[_0x5d0fee(0xe4)][_0x5d0fee(0xf5)]())){if(_0x3777e2[_0x5d0fee(0x8c)](_0x5d0fee(0xdf),_0x3777e2[_0x5d0fee(0x127)])){let _0x1c1591;do{const _0x2059bb=_0x13e11a[_0x5d0fee(0xc6)](_0x3777e2[_0x5d0fee(0x10b)](_0x26b05e['\x72\x61\x6e\x64\x6f\x6d'](),_0x258467['\x6c\x65\x6e\x67\x74\x68']));_0x1c1591=_0x1903e5[_0x2059bb];}while(_0x3777e2[_0x5d0fee(0x6d)](_0x1c1591[_0x5d0fee(0xf5)](),_0x445729[_0x5d0fee(0xe4)][_0x5d0fee(0xf5)]())||_0x19a12b[_0x5d0fee(0xd1)](_0x1c1591));_0x3985db['\x70\x75\x73\x68'](_0x1c1591);const _0x5cf02a=_0x6e5994['\x74\x63\x65\x6e\x74\x54\x72\x61\x6e\x73\x66\x65\x72\x52\x61\x6e\x67\x65'],_0x498b62=_0x3777e2['\x56\x56\x6a\x4b\x48'](_0x3777e2[_0x5d0fee(0x143)](_0x4850cd[_0x5d0fee(0x15c)](),_0x3777e2[_0x5d0fee(0x176)](_0x5cf02a['\x6d\x61\x78'],_0x5cf02a['\x6d\x69\x6e'])),_0x5cf02a[_0x5d0fee(0x100)])['\x74\x6f\x46\x69\x78\x65\x64'](0x3),_0x374197=_0x23343d[_0x5d0fee(0x11f)][_0x5d0fee(0x68)](_0x498b62);_0x482ffb[_0x5d0fee(0xea)](_0x374197),_0x8325e3[_0x5d0fee(0xea)]('\x30\x78'),_0x3777e2[_0x5d0fee(0xf1)](_0x5c1210,'\x42\x75\x6e\x64\x6c\x65\x20\x54\x72\x61\x6e\x73\x66\x65\x72\x20'+_0x3777e2['\x56\x56\x6a\x4b\x48'](_0x4f2821,0x1)+'\x3a\x20'+_0x498b62+_0x5d0fee(0x9a)+_0x3ba74b(_0x1c1591),_0x3777e2[_0x5d0fee(0x125)]);}else _0x3777e2[_0x5d0fee(0x14e)](addLog,_0x5d0fee(0x172)+_0x3777e2[_0x5d0fee(0xdb)](getShortAddress,_0x17fe73)+_0x5d0fee(0xb6),_0x3777e2['\x76\x72\x52\x71\x52']);}}while(_0x17fe73['\x74\x6f\x4c\x6f\x77\x65\x72\x43\x61\x73\x65']()===_0x316a61[_0x5d0fee(0xe4)][_0x5d0fee(0xf5)]());addLog(_0x5d0fee(0x11d)+_0x4951a2+_0x5d0fee(0x9a)+_0x3777e2[_0x5d0fee(0x69)](getShortAddress,_0x17fe73),_0x5d0fee(0x166));const _0x18d2d4=[_0x3777e2[_0x5d0fee(0xf9)]],_0x39ad35=new ethers['\x75\x74\x69\x6c\x73'][(_0x5d0fee(0x74))](_0x18d2d4),_0x2d1f2f=_0x39ad35[_0x5d0fee(0xef)](_0x5d0fee(0x14f),[_0x17fe73,_0x2ed539,'\x30\x78']),_0x25aa91=[_0x5d0fee(0x11a)],_0x158617=new ethers[(_0x5d0fee(0xd2))](ENTRY_POINT,_0x25aa91,_0x46cb20);let _0x4d08a0;try{if(_0x3777e2[_0x5d0fee(0x14c)](_0x3777e2[_0x5d0fee(0xde)],'\x4e\x68\x76\x48\x72')){const _0x47da05=await _0x158617['\x67\x65\x74\x4e\x6f\x6e\x63\x65'](_0x316a61[_0x5d0fee(0xe4)],0x0);addLog(_0x5d0fee(0xb7)+_0x47da05[_0x5d0fee(0xd8)](),'\x64\x65\x62\x75\x67');if(!nonceTracker[_0x316a61[_0x5d0fee(0xe4)]]){if(_0x3777e2['\x79\x74\x76\x54\x6f'](_0x3777e2[_0x5d0fee(0x80)],_0x3777e2[_0x5d0fee(0x80)])){const _0x5eb26a=_0x38adbb['\x65\x6e\x63\x6f\x64\x65\x46\x75\x6e\x63\x74\x69\x6f\x6e\x44\x61\x74\x61'](_0x3777e2['\x4a\x6a\x4e\x4d\x53'],[0x0,_0x1b0e72,_0x77c132[_0x5d0fee(0xe4)],_0x59c3c4]);_0x53f79a=_0x3629f0[_0x5d0fee(0xef)](_0x3777e2[_0x5d0fee(0x150)],[_0x3c5769,_0x350c46,_0x5eb26a]);}else nonceTracker[_0x316a61['\x73\x6d\x61\x72\x74\x41\x64\x64\x72\x65\x73\x73']]=_0x47da05;}_0x4d08a0=nonceTracker[_0x316a61[_0x5d0fee(0xe4)]];}else{const _0x236c3d=_0x77a4f1[_0x5d0fee(0xef)](_0x3777e2[_0x5d0fee(0x130)],[_0x3258e6,_0x5e1e64]),_0x51a4f7=_0x5abbbf['\x65\x6e\x63\x6f\x64\x65\x46\x75\x6e\x63\x74\x69\x6f\x6e\x44\x61\x74\x61'](_0x3777e2[_0x5d0fee(0x9e)],[_0x1436c7,0x0,_0x1d2a08,_0x2966fd[_0x5d0fee(0xe4)],_0x4d3699]);_0x25bbe4=_0x1e5f37['\x65\x6e\x63\x6f\x64\x65\x46\x75\x6e\x63\x74\x69\x6f\x6e\x44\x61\x74\x61'](_0x3777e2[_0x5d0fee(0x122)],[[_0x59c0db,_0x2961bc],[0x0,0x0],[_0x236c3d,_0x51a4f7]]);}}catch(_0x2ab562){if(_0x3777e2[_0x5d0fee(0x88)](_0x5d0fee(0xa2),_0x3777e2['\x72\x71\x46\x59\x59'])){const _0x1d20d6=_0x4ad847['\x66\x6c\x6f\x6f\x72'](_0x3777e2[_0x5d0fee(0x143)](_0x332b93[_0x5d0fee(0x15c)](),_0x49d81d['\x6c\x65\x6e\x67\x74\x68']));_0x969455=_0x134059[_0x1d20d6],_0x3777e2[_0x5d0fee(0x14b)](_0x4d7fa4[_0x5d0fee(0xf5)](),_0x5d5e58['\x73\x6d\x61\x72\x74\x41\x64\x64\x72\x65\x73\x73']['\x74\x6f\x4c\x6f\x77\x65\x72\x43\x61\x73\x65']())&&_0x3777e2['\x53\x44\x76\x4d\x76'](_0x14860d,_0x5d0fee(0x172)+_0x3777e2[_0x5d0fee(0x165)](_0x629b68,_0x1942b7)+'\x20\x61\x73\x20\x69\x74\x20\x6d\x61\x74\x63\x68\x65\x73\x20\x73\x65\x6e\x64\x65\x72\x2e\x20\x50\x69\x63\x6b\x69\x6e\x67\x20\x61\x6e\x6f\x74\x68\x65\x72\x2e\x2e\x2e',_0x3777e2['\x76\x72\x52\x71\x52']);}else{addLog(_0x5d0fee(0x84)+_0x2ab562['\x6d\x65\x73\x73\x61\x67\x65'],_0x3777e2[_0x5d0fee(0xce)]);throw _0x2ab562;}}const _0x440d92={'\x73\x65\x6e\x64\x65\x72':ethers[_0x5d0fee(0x11f)][_0x5d0fee(0xe1)](_0x316a61[_0x5d0fee(0xe4)]),'\x6e\x6f\x6e\x63\x65':ethers[_0x5d0fee(0x11f)][_0x5d0fee(0xc1)](_0x4d08a0),'\x69\x6e\x69\x74\x43\x6f\x64\x65':'\x30\x78','\x63\x61\x6c\x6c\x44\x61\x74\x61':_0x2d1f2f},_0x38d742=_0x3777e2[_0x5d0fee(0x8f)];try{if(_0x3777e2[_0x5d0fee(0x14c)](_0x3777e2[_0x5d0fee(0x7f)],_0x3777e2[_0x5d0fee(0xb3)])){const _0x542492=await _0x3777e2[_0x5d0fee(0x12d)](makeBundlerCall,_0x3777e2[_0x5d0fee(0x101)],[{..._0x440d92,'\x73\x69\x67\x6e\x61\x74\x75\x72\x65':_0x38d742},ENTRY_POINT],_0x578074),_0x22a0e3=_0x542492[_0x5d0fee(0xfb)];if(!_0x22a0e3)throw new Error(_0x3777e2[_0x5d0fee(0x147)]);addLog(_0x5d0fee(0x110)+JSON[_0x5d0fee(0x16c)](_0x22a0e3,null,0x2),_0x3777e2[_0x5d0fee(0xbb)]);const _0x25b057=ethers['\x42\x69\x67\x4e\x75\x6d\x62\x65\x72'][_0x5d0fee(0x177)](_0x22a0e3[_0x5d0fee(0x16d)])[_0x5d0fee(0x175)](0x1388),_0x59b1d6=ethers[_0x5d0fee(0x13e)][_0x5d0fee(0x177)](_0x22a0e3[_0x5d0fee(0x15b)])[_0x5d0fee(0x175)](0x1388),_0x30aeda=ethers['\x42\x69\x67\x4e\x75\x6d\x62\x65\x72'][_0x5d0fee(0x177)](_0x22a0e3['\x76\x65\x72\x69\x66\x69\x63\x61\x74\x69\x6f\x6e\x47\x61\x73\x4c\x69\x6d\x69\x74'])[_0x5d0fee(0x175)](0x1388),_0x58057d=await _0x46cb20['\x67\x65\x74\x46\x65\x65\x44\x61\x74\x61'](),_0x12ff80=_0x58057d?.[_0x5d0fee(0xb0)]||ethers[_0x5d0fee(0x11f)][_0x5d0fee(0x103)](_0x5d0fee(0x73),_0x3777e2[_0x5d0fee(0xc4)]),_0x5025a8=_0x58057d?.[_0x5d0fee(0x98)]||ethers[_0x5d0fee(0x11f)][_0x5d0fee(0x103)](_0x3777e2[_0x5d0fee(0x112)],_0x3777e2[_0x5d0fee(0xc4)]),_0x3d7bac={..._0x440d92,'\x63\x61\x6c\x6c\x47\x61\x73\x4c\x69\x6d\x69\x74':ethers['\x75\x74\x69\x6c\x73'][_0x5d0fee(0xc1)](_0x59b1d6),'\x76\x65\x72\x69\x66\x69\x63\x61\x74\x69\x6f\x6e\x47\x61\x73\x4c\x69\x6d\x69\x74':ethers[_0x5d0fee(0x11f)][_0x5d0fee(0xc1)](_0x30aeda),'\x70\x72\x65\x56\x65\x72\x69\x66\x69\x63\x61\x74\x69\x6f\x6e\x47\x61\x73':ethers['\x75\x74\x69\x6c\x73'][_0x5d0fee(0xc1)](_0x25b057),'\x6d\x61\x78\x46\x65\x65\x50\x65\x72\x47\x61\x73':ethers[_0x5d0fee(0x11f)][_0x5d0fee(0xc1)](_0x12ff80),'\x6d\x61\x78\x50\x72\x69\x6f\x72\x69\x74\x79\x46\x65\x65\x50\x65\x72\x47\x61\x73':ethers[_0x5d0fee(0x11f)]['\x68\x65\x78\x6c\x69\x66\x79'](_0x5025a8),'\x73\x69\x67\x6e\x61\x74\x75\x72\x65':_0x38d742},_0xdb2697=ethers['\x42\x69\x67\x4e\x75\x6d\x62\x65\x72']['\x66\x72\x6f\x6d'](_0x30aeda)[_0x5d0fee(0xf2)](0x80)[_0x5d0fee(0x175)](ethers['\x42\x69\x67\x4e\x75\x6d\x62\x65\x72'][_0x5d0fee(0x177)](_0x59b1d6)),_0x1b4b35=ethers[_0x5d0fee(0x13e)]['\x66\x72\x6f\x6d'](_0x5025a8)[_0x5d0fee(0xf2)](0x80)[_0x5d0fee(0x175)](ethers['\x42\x69\x67\x4e\x75\x6d\x62\x65\x72'][_0x5d0fee(0x177)](_0x12ff80)),_0x1d6aa8={'\x73\x65\x6e\x64\x65\x72':ethers[_0x5d0fee(0x11f)][_0x5d0fee(0xe1)](_0x316a61[_0x5d0fee(0xe4)]),'\x6e\x6f\x6e\x63\x65':_0x4d08a0,'\x69\x6e\x69\x74\x43\x6f\x64\x65':'\x30\x78','\x63\x61\x6c\x6c\x44\x61\x74\x61':_0x2d1f2f,'\x61\x63\x63\x6f\x75\x6e\x74\x47\x61\x73\x4c\x69\x6d\x69\x74\x73':ethers[_0x5d0fee(0x11f)][_0x5d0fee(0x126)](_0xdb2697['\x74\x6f\x48\x65\x78\x53\x74\x72\x69\x6e\x67'](),0x20),'\x70\x72\x65\x56\x65\x72\x69\x66\x69\x63\x61\x74\x69\x6f\x6e\x47\x61\x73':ethers[_0x5d0fee(0x13e)]['\x66\x72\x6f\x6d'](_0x25b057),'\x67\x61\x73\x46\x65\x65\x73':ethers[_0x5d0fee(0x11f)][_0x5d0fee(0x126)](_0x1b4b35[_0x5d0fee(0x173)](),0x20),'\x70\x61\x79\x6d\x61\x73\x74\x65\x72\x41\x6e\x64\x44\x61\x74\x61':'\x30\x78','\x73\x69\x67\x6e\x61\x74\x75\x72\x65':'\x30\x78'},_0xd41c77=[_0x3777e2['\x61\x58\x6c\x7a\x4a']],_0x5cc9ca=new ethers[(_0x5d0fee(0xd2))](ENTRY_POINT,_0xd41c77,_0x46cb20),_0x43eab5=await _0x5cc9ca[_0x5d0fee(0xa1)](_0x1d6aa8);_0x3777e2[_0x5d0fee(0x135)](addLog,_0x5d0fee(0x145)+_0x43eab5,_0x3777e2[_0x5d0fee(0xbb)]);const _0x30a62c=await _0x5afd62[_0x5d0fee(0xb4)](ethers[_0x5d0fee(0x11f)]['\x61\x72\x72\x61\x79\x69\x66\x79'](_0x43eab5)),_0x349e6c=0x0,_0x4ff230=_0x316a61['\x77\x61\x6c\x6c\x65\x74\x49\x64']||0x1,_0x3d5c91=ethers[_0x5d0fee(0x11f)][_0x5d0fee(0x126)](ethers[_0x5d0fee(0x11f)][_0x5d0fee(0xc1)](_0x349e6c),0x1),_0x5ee9f5=ethers[_0x5d0fee(0x11f)][_0x5d0fee(0x126)](ethers['\x75\x74\x69\x6c\x73']['\x68\x65\x78\x6c\x69\x66\x79'](_0x4ff230),0x2),_0x3a81b0=ethers[_0x5d0fee(0x11f)]['\x68\x65\x78\x43\x6f\x6e\x63\x61\x74']([_0x3d5c91,_0x5ee9f5,_0x30a62c]);_0x3d7bac[_0x5d0fee(0x136)]=_0x3a81b0;const _0x1693f6={..._0x3d7bac};_0x1693f6[_0x5d0fee(0x115)]=_0x1693f6['\x63\x61\x6c\x6c\x44\x61\x74\x61']?_0x1693f6['\x63\x61\x6c\x6c\x44\x61\x74\x61']['\x73\x6c\x69\x63\x65'](0x0,0xc8)+(_0x3777e2[_0x5d0fee(0x109)](_0x1693f6[_0x5d0fee(0x115)][_0x5d0fee(0x146)],0xc8)?_0x3777e2[_0x5d0fee(0xa4)]:''):_0x1693f6[_0x5d0fee(0x115)],_0x1693f6['\x73\x69\x67\x6e\x61\x74\x75\x72\x65']=_0x3777e2[_0x5d0fee(0x167)](_0x1693f6[_0x5d0fee(0x136)][_0x5d0fee(0x158)](0x0,0xc),_0x3777e2[_0x5d0fee(0xa4)]),_0x3777e2[_0x5d0fee(0xf1)](addLog,_0x5d0fee(0x156)+JSON['\x73\x74\x72\x69\x6e\x67\x69\x66\x79'](_0x1693f6,null,0x2),_0x3777e2[_0x5d0fee(0xbb)]);const _0x238c02=await _0x3777e2['\x79\x43\x49\x72\x4c'](makeBundlerCall,_0x3777e2[_0x5d0fee(0x116)],[_0x3d7bac,ENTRY_POINT],_0x578074);_0x3777e2['\x76\x6c\x62\x67\x51'](addLog,_0x5d0fee(0xbc)+JSON['\x73\x74\x72\x69\x6e\x67\x69\x66\x79'](_0x238c02,null,0x2),_0x3777e2[_0x5d0fee(0xbb)]);const _0x47b0da=_0x238c02[_0x5d0fee(0xfb)];_0x3777e2[_0x5d0fee(0x14e)](addLog,_0x5d0fee(0xa9)+_0x3777e2[_0x5d0fee(0x87)](getShortHash,_0x47b0da),_0x3777e2['\x76\x72\x52\x71\x52']);const _0x562121={'\x74\x78\x48\x61\x73\x68':_0x47b0da,'\x62\x61\x64\x67\x65\x4b\x65\x79':_0x5d0fee(0x10d)};return await _0x3777e2[_0x5d0fee(0x96)](makeApiCall,_0x5d0fee(0x170),_0x3777e2[_0x5d0fee(0x149)],_0x562121,_0x578074,_0x316a61['\x74\x6f\x6b\x65\x6e']),addLog(_0x5d0fee(0xeb)+_0x4951a2+_0x5d0fee(0x9a)+_0x3777e2[_0x5d0fee(0x87)](getShortAddress,_0x17fe73)+_0x5d0fee(0x169)+getShortHash(_0x47b0da),_0x3777e2[_0x5d0fee(0x6e)]),nonceTracker[_0x316a61[_0x5d0fee(0xe4)]]=_0x4d08a0[_0x5d0fee(0x175)](0x1),_0x47b0da;}else{const _0x31cecf=_0x334249[_0x5d0fee(0xc6)](_0x3777e2[_0x5d0fee(0x143)](_0x487879[_0x5d0fee(0x15c)](),_0x4c802e[_0x5d0fee(0x146)]));_0x4a3e95=_0x388a83[_0x31cecf];}}catch(_0x2264aa){if(_0x5d0fee(0xd0)!==_0x3777e2[_0x5d0fee(0x121)]){let _0x218888=_0x874976[_0x1839f5[_0x5d0fee(0xc6)](_0x3777e2[_0x5d0fee(0x6b)](_0x1cb2a0[_0x5d0fee(0x15c)](),_0x16869c[_0x5d0fee(0x146)]))];while(_0x66eed[_0x5d0fee(0xd1)](_0x218888)){_0x218888=_0xc2691[_0x1f8978['\x66\x6c\x6f\x6f\x72'](_0x3777e2[_0x5d0fee(0xe2)](_0x42d132[_0x5d0fee(0x15c)](),_0x323a73['\x6c\x65\x6e\x67\x74\x68']))];}_0x37fcec[_0x5d0fee(0xea)](_0x218888);}else{_0x2264aa[_0x5d0fee(0xaf)][_0x5d0fee(0xd1)](_0x3777e2['\x52\x66\x4d\x4b\x6e'])&&(addLog(_0x5d0fee(0x154),_0x3777e2['\x76\x72\x52\x71\x52']),delete nonceTracker[_0x316a61[_0x5d0fee(0xe4)]]);addLog(_0x5d0fee(0x15d)+_0x2264aa[_0x5d0fee(0xaf)],_0x5d0fee(0x153));throw _0x2264aa;}}}

function generateRandomName(existingNames) {
  const vowels = "aeiou";
  const consonants = "bcdfghjklmnpqrstvwxyz";
  let name;
  do {
    const length = Math.floor(Math.random() * (12 - 6 + 1)) + 6;
    name = "";
    let isVowel = Math.random() < 0.5;
    for (let i = 0; i < length; i++) {
      if (isVowel) {
        name += vowels[Math.floor(Math.random() * vowels.length)];
      } else {
        name += consonants[Math.floor(Math.random() * consonants.length)];
      }
      isVowel = !isVowel;
      if (Math.random() < 0.2) isVowel = !isVowel; 
    }
    name = name.charAt(0).toUpperCase() + name.slice(1).toLowerCase();
    if (Math.random() < 0.2) {
      name += Math.floor(Math.random() * 100);
    }
  } while (existingNames.includes(name.toLowerCase()));
  return name;
}

async function performAddContact(account, proxyUrl) {
  const contactsRes = await makeApiCall('https://api.testnet.incentiv.io/api/user/contacts', 'GET', null, proxyUrl, account.token);
  if (contactsRes.code !== 200 || !Array.isArray(contactsRes.result)) {
    throw new Error('Failed to fetch existing contacts');
  }
  const existingAddresses = contactsRes.result.map(c => c.address.toLowerCase());
  const existingNames = contactsRes.result.map(c => c.name.toLowerCase());
  const name = generateRandomName(existingNames);

  let address;
  const availableRecipients = recipients.filter(r => !existingAddresses.includes(r.toLowerCase()));
  if (availableRecipients.length > 0) {
    const randomIndex = Math.floor(Math.random() * availableRecipients.length);
    address = availableRecipients[randomIndex];
  } else {
    do {
      const newWallet = ethers.Wallet.createRandom();
      address = newWallet.address;
    } while (existingAddresses.includes(address.toLowerCase()));
  }

  addLog(`Adding contact: ${name} - ${getShortAddress(address)}`, "info");

  const payload = { name, address };
  const addRes = await makeApiCall('https://api.testnet.incentiv.io/api/user/contacts', 'POST', payload, proxyUrl, account.token);
  if (addRes.code !== 201) {
    throw new Error('Failed to add contact');
  }

  addLog(`Contact added successfully: ${name} - ${getShortAddress(address)}`, "success");
}

function getTokenName(token) {
  if (token === SMPL) return 'SMPL';
  if (token === BULL) return 'BULL';
  if (token === FLIP) return 'FLIP';
  return 'UNKNOWN';
}



async function runDailyActivity() {
  if (accounts.length === 0) {
    addLog("No valid accounts found.", "error");
    return;
  }
  const activeAccounts = accounts.filter(a => a.smartAddress);
  if (activeAccounts.length === 0) {
    addLog("No active accounts found. Please activate accounts first.", "error");
    return;
  }
  addLog(`Starting daily activity for ${activeAccounts.length} active accounts. Auto Bundle: ${dailyActivityConfig.bundleRepetitions}x, Auto Swap: ${dailyActivityConfig.swapRepetitions}x, Auto Transfer: ${dailyActivityConfig.transferRepetitions}x, Auto Add Contact: ${dailyActivityConfig.addContactRepetitions}x`, "info");
  activityRunning = true;
  isCycleRunning = true;
  shouldStop = false;
  hasLoggedSleepInterrupt = false;
  activeProcesses = Math.max(0, activeProcesses);
  updateMenu();
  let activityErrors = 0;
  try {
    for (let accountIndex = 0; accountIndex < accounts.length && !shouldStop; accountIndex++) {
      try {
        addLog(`Starting processing for account ${accountIndex + 1}`, "info");
        selectedWalletIndex = accountIndex;
        const proxyUrl = proxies[accountIndex % proxies.length] || null;
        addLog(`Account ${accountIndex + 1}: Using Proxy ${proxyUrl || "none"}`, "info");
        const account = accounts[accountIndex];
        const provider = getProvider(RPC_URL, CHAIN_ID, proxyUrl);

        if (!account.smartAddress || !(await testToken(account, proxyUrl))) {
          await loginAccount(account, proxyUrl);
        }

        if (!account.smartAddress) {
          addLog(`Skipping account ${accountIndex + 1}: Login failed`, "error");
          activityErrors++;
          continue;
        }

        addLog(`Processing account ${accountIndex + 1}: ${getShortAddress(account.smartAddress)}`, "wait");

        for (let swapCount = 0; swapCount < dailyActivityConfig.swapRepetitions && !shouldStop; swapCount++) {
          let token;
          const rand = Math.random();
          if (rand < 1/3) {
            token = SMPL;
          } else if (rand < 2/3) {
            token = BULL;
          } else {
            token = FLIP;
          }
          const isBuy = Math.random() < 0.5;
          let range;
          if (isBuy) {
            range = dailyActivityConfig.tcentSwapRange;
          } else {
            if (token === SMPL) {
              range = dailyActivityConfig.smplSwapRange;
            } else if (token === BULL) {
              range = dailyActivityConfig.bullSwapRange;
            } else {
              range = dailyActivityConfig.flipSwapRange;
            }
          }
          let amount = (Math.random() * (range.max - range.min) + range.min).toFixed(3);
          const tokenName = getTokenName(token);
          addLog(`Account ${accountIndex + 1} - Swap ${swapCount + 1}: ${amount} ${isBuy ? 'TCENT' : tokenName} ➯ ${isBuy ? tokenName : 'TCENT'}`, "warn");
          try {
            await performSwap(account, token, isBuy, amount, proxyUrl, provider);
          } catch (error) {
            addLog(`Account ${accountIndex + 1} - Swap ${swapCount + 1}: Failed: ${error.message}. Skipping to next.`, "error");
          } finally {
            await updateWallets();
          }
          if (swapCount < dailyActivityConfig.swapRepetitions - 1 && !shouldStop) {
            const randomDelay = Math.floor(Math.random() * (30000 - 20000 + 1)) + 20000;
            addLog(`Account ${accountIndex + 1} - Waiting ${Math.floor(randomDelay / 1000)} seconds before next swap...`, "delay");
            await sleep(randomDelay);
          }
        }

        if (dailyActivityConfig.bundleRepetitions > 0 && !shouldStop) {
          const randomDelay = Math.floor(Math.random() * (20000 - 10000 + 1)) + 10000;
          addLog(`Account ${accountIndex + 1} - Waiting ${Math.floor(randomDelay / 1000)} seconds before bundle actions...`, "delay");
          await sleep(randomDelay);
        }

        for (let bundleCount = 0; bundleCount < dailyActivityConfig.bundleRepetitions && !shouldStop; bundleCount++) {
          addLog(`Account ${accountIndex + 1} - Bundle Action ${bundleCount + 1}`, "warn");
          try {
            await performBundleAction(account, proxyUrl, provider);
          } catch (error) {
            addLog(`Account ${accountIndex + 1} - Bundle Action ${bundleCount + 1}: Failed: ${error.message}. Skipping to next.`, "error");
          } finally {
            await updateWallets();
          }
          if (bundleCount < dailyActivityConfig.bundleRepetitions - 1 && !shouldStop) {
            const randomDelay = Math.floor(Math.random() * (30000 - 20000 + 1)) + 20000;
            addLog(`Account ${accountIndex + 1} - Waiting ${Math.floor(randomDelay / 1000)} seconds before next bundle...`, "delay");
            await sleep(randomDelay);
          }
        }

        if (dailyActivityConfig.transferRepetitions > 0 && !shouldStop) {
          const randomDelay = Math.floor(Math.random() * (20000 - 10000 + 1)) + 10000;
          addLog(`Account ${accountIndex + 1} - Waiting ${Math.floor(randomDelay / 1000)} seconds before transfers...`, "delay");
          await sleep(randomDelay);
        }

        for (let transferCount = 0; transferCount < dailyActivityConfig.transferRepetitions && !shouldStop; transferCount++) {
          const range = dailyActivityConfig.tcentTransferRange;
          let amount = (Math.random() * (range.max - range.min) + range.min).toFixed(3);
          addLog(`Account ${accountIndex + 1} - Transfer ${transferCount + 1}: ${amount} TCENT`, "warn");
          try {
            await performTransfer(account, amount, proxyUrl, provider);
          } catch (error) {
            addLog(`Account ${accountIndex + 1} - Transfer ${transferCount + 1}: Failed: ${error.message}. Skipping to next.`, "error");
          } finally {
            await updateWallets();
          }
          if (transferCount < dailyActivityConfig.transferRepetitions - 1 && !shouldStop) {
            const randomDelay = Math.floor(Math.random() * (30000 - 20000 + 1)) + 20000;
            addLog(`Account ${accountIndex + 1} - Waiting ${Math.floor(randomDelay / 1000)} seconds before next transfer...`, "delay");
            await sleep(randomDelay);
          }
        }

        if (dailyActivityConfig.addContactRepetitions > 0 && !shouldStop) {
          const randomDelay = Math.floor(Math.random() * (20000 - 10000 + 1)) + 10000;
          addLog(`Account ${accountIndex + 1} - Waiting ${Math.floor(randomDelay / 1000)} seconds before add contacts...`, "delay");
          await sleep(randomDelay);
        }

        for (let contactCount = 0; contactCount < dailyActivityConfig.addContactRepetitions && !shouldStop; contactCount++) {
          addLog(`Account ${accountIndex + 1} - Add Contact ${contactCount + 1}`, "warn");
          try {
            await performAddContact(account, proxyUrl);
          } catch (error) {
            addLog(`Account ${accountIndex + 1} - Add Contact ${contactCount + 1}: Failed: ${error.message}. Skipping to next.`, "error");
          }
          if (contactCount < dailyActivityConfig.addContactRepetitions - 1 && !shouldStop) {
            const randomDelay = Math.floor(Math.random() * (30000 - 20000 + 1)) + 20000;
            addLog(`Account ${accountIndex + 1} - Waiting ${Math.floor(randomDelay / 1000)} seconds before next add contact...`, "delay");
            await sleep(randomDelay);
          }
        }

        if (accountIndex < accounts.length - 1 && !shouldStop) {
          addLog(`Waiting 10 seconds before next account...`, "delay");
          await sleep(10000);
        }
      } catch (accountError) {
        activityErrors++;
        addLog(`Error processing account ${accountIndex + 1}: ${accountError.message}. Skipping to next account.`, "error");
        if (accountIndex < accounts.length - 1 && !shouldStop) {
          await sleep(10000);
        }
      }
    }
    if (!shouldStop && activeProcesses <= 0) {
      if (activityErrors > 0) {
        addLog(`Daily activity completed with ${activityErrors} errors. Waiting ${dailyActivityConfig.loopHours} hours for next cycle.`, "warn");
      } else {
        addLog(`All accounts processed. Waiting ${dailyActivityConfig.loopHours} hours for next cycle.`, "success");
      }
      dailyActivityInterval = setTimeout(runDailyActivity, dailyActivityConfig.loopHours * 60 * 60 * 1000);
    }
  } catch (error) {
    addLog(`Daily activity failed: ${error.message}`, "error");
  } finally {
    if (shouldStop) {
      if (activeProcesses <= 0) {
        if (dailyActivityInterval) {
          clearTimeout(dailyActivityInterval);
          dailyActivityInterval = null;
          addLog("Cleared daily activity interval.", "info");
        }
        activityRunning = false;
        isCycleRunning = false;
        shouldStop = false;
        hasLoggedSleepInterrupt = false;
        activeProcesses = 0;
        addLog("Daily activity stopped successfully.", "success");
        updateMenu();
        updateStatus();
        safeRender();
      } else {
        const stopCheckInterval = setInterval(() => {
          if (activeProcesses <= 0) {
            clearInterval(stopCheckInterval);
            if (dailyActivityInterval) {
              clearTimeout(dailyActivityInterval);
              dailyActivityInterval = null;
              addLog("Cleared daily activity interval.", "info");
            }
            activityRunning = false;
            isCycleRunning = false;
            shouldStop = false;
            hasLoggedSleepInterrupt = false;
            activeProcesses = 0;
            addLog("Daily activity stopped successfully.", "success");
            updateMenu();
            updateStatus();
            safeRender();
          } else {
            addLog(`Waiting for ${activeProcesses} process(es) to complete...`, "info");
            safeRender();
          }
        }, 1000);
      }
    } else {
      activityRunning = false;
      isCycleRunning = activeProcesses > 0 || dailyActivityInterval !== null;
      updateMenu();
      updateStatus();
      safeRender();
    }
    nonceTracker = {};
  }
}

const screen = blessed.screen({
  smartCSR: true,
  title: "INCENTIV TESTNET ANNISA",
  autoPadding: true,
  fullUnicode: true,
  mouse: true,
  ignoreLocked: ["C-c", "q", "escape"]
});


function makeDebouncedHandler(fn, delay = 400) {
  let locked = false;
  return function(...args) {
    if (locked) return;
    locked = true;
    try { fn.apply(this, args); } finally {
      setTimeout(() => { locked = false; }, delay);
    }
  };
}


const headerBox = blessed.box({
  top: 0,
  left: "center",
  width: "100%",
  height: 6,
  tags: true,
  style: { fg: "yellow", bg: "default" }
});

const statusBox = blessed.box({
  left: 0,
  top: 6,
  width: "100%",
  height: 3,
  tags: true,
  border: { type: "line", fg: "cyan" },
  style: { fg: "white", bg: "default", border: { fg: "cyan" } },
  content: "Status: Initializing...",
  padding: { left: 1, right: 1, top: 0, bottom: 0 },
  label: chalk.cyan(" Status "),
  wrap: true
});

const walletBox = blessed.list({
  label: " Wallet Information",
  top: 9,
  left: 0,
  width: "40%",
  height: "35%",
  border: { type: "line", fg: "cyan" },
  style: { border: { fg: "cyan" }, fg: "white", bg: "default", item: { fg: "white" } },
  scrollable: true,
  scrollbar: { bg: "cyan", fg: "black" },
  padding: { left: 1, right: 1, top: 0, bottom: 0 },
  tags: true,
  keys: true,
  vi: true,
  mouse: true,
  content: "Loading wallet data..."
});

const logBox = blessed.log({
  label: " Transaction Logs",
  top: 9,
  left: "41%",
  width: "59%",
  height: "100%-9",
  border: { type: "line" },
  scrollable: true,
  alwaysScroll: true,
  mouse: true,
  tags: true,
  scrollbar: { ch: "│", style: { bg: "cyan", fg: "white" }, track: { bg: "gray" } },
  scrollback: 50,
  smoothScroll: true,
  style: { border: { fg: "magenta" }, bg: "default", fg: "white" },
  padding: { left: 1, right: 1, top: 0, bottom: 0 },
  wrap: true,
  focusable: true,
  keys: true
});

const menuBox = blessed.list({
  label: " Menu ",
  top: "44%",
  left: 0,
  width: "40%",
  height: "56%",
  keys: true,
  vi: true,
  mouse: true,
  border: { type: "line" },
  style: { fg: "white", bg: "default", border: { fg: "red" }, selected: { bg: "magenta", fg: "black" }, item: { fg: "white" } },
  items: [], 
  padding: { left: 1, top: 1 }
});

const dailyActivitySubMenu = blessed.list({
  label: " Manual Config Options ",
  top: "44%",
  left: 0,
  width: "40%",
  height: "56%",
  keys: true,
  vi: true,
  mouse: true,
  border: { type: "line" },
  style: {
    fg: "white",
    bg: "default",
    border: { fg: "blue" },
    selected: { bg: "blue", fg: "black" },
    item: { fg: "white" }
  },
  items: [
    "Set Bundle Repetitions",
    "Set Add Contact Repetitions",
    "Set Swap Repetitions",
    "Set TCENT Swap Range",
    "Set SMPL Swap Range",
    "Set BULL Swap Range",
    "Set FLIP Swap Range",
    "Set Transfer Repetitions",
    "Set TCENT Transfer Range",
    "Set Loop Daily",
    "Back to Main Menu"
  ],
  padding: { left: 1, top: 1 },
  hidden: true
});

const faucetSubMenu = blessed.list({
  label: " Claim Faucet Options ",
  top: "44%",
  left: 0,
  width: "40%",
  height: "56%",
  keys: true,
  vi: true,
  mouse: true,
  border: { type: "line" },
  style: {
    fg: "white",
    bg: "default",
    border: { fg: "green" },
    selected: { bg: "green", fg: "black" },
    item: { fg: "white" }
  },
  items: [
    "Auto Claim Faucet",
    "Change 2 Captcha Key",
    "Check Account Next Faucet",
    "Refresh",
    "Clear Logs",
    "Back to Main Menu"
  ],
  padding: { left: 1, top: 1 },
  hidden: true
});

const configForm = blessed.form({
  label: " Enter Config Value ",
  top: "center",
  left: "center",
  width: "30%",
  height: "40%",
  keys: true,
  mouse: true,
  border: { type: "line" },
  style: {
    fg: "white",
    bg: "default",
    border: { fg: "blue" }
  },
  padding: { left: 1, top: 1 },
  hidden: true
});

const minLabel = blessed.text({
  parent: configForm,
  top: 0,
  left: 1,
  content: "Min Value:",
  style: { fg: "white" }
});

const maxLabel = blessed.text({
  parent: configForm,
  top: 4,
  left: 1,
  content: "Max Value:",
  style: { fg: "white" }
});

const configInput = blessed.textbox({
  parent: configForm,
  top: 1,
  left: 1,
  width: "90%",
  height: 3,
  inputOnFocus: true,
  border: { type: "line" },
  style: {
    fg: "white",
    bg: "default",
    border: { fg: "white" },
    focus: { border: { fg: "green" } }
  }
});

const configInputMax = blessed.textbox({
  parent: configForm,
  top: 5,
  left: 1,
  width: "90%",
  height: 3,
  inputOnFocus: true,
  border: { type: "line" },
  style: {
    fg: "white",
    bg: "default",
    border: { fg: "white" },
    focus: { border: { fg: "green" } }
  }
});

const configSubmitButton = blessed.button({
  parent: configForm,
  top: 9,
  left: "center",
  width: 10,
  height: 3,
  content: "Submit",
  align: "center",
  border: { type: "line" },
  clickable: true,
  keys: true,
  mouse: true,
  style: {
    fg: "white",
    bg: "blue",
    border: { fg: "white" },
    hover: { bg: "green" },
    focus: { bg: "green", border: { fg: "yellow" } }
  }
});

const keyForm = blessed.form({
  label: " Enter 2Captcha Key ",
  top: "center",
  left: "center",
  width: "30%",
  height: "30%",
  keys: true,
  mouse: true,
  border: { type: "line" },
  style: {
    fg: "white",
    bg: "default",
    border: { fg: "green" }
  },
  padding: { left: 1, top: 1 },
  hidden: true
});

const keyInput = blessed.textbox({
  parent: keyForm,
  top: 1,
  left: 1,
  width: "90%",
  height: 3,
  inputOnFocus: true,
  border: { type: "line" },
  style: {
    fg: "white",
    bg: "default",
    border: { fg: "white" },
    focus: { border: { fg: "green" } }
  }
});

const keySubmitButton = blessed.button({
  parent: keyForm,
  top: 5,
  left: "center",
  width: 10,
  height: 3,
  content: "Submit",
  align: "center",
  border: { type: "line" },
  clickable: true,
  keys: true,
  mouse: true,
  style: {
    fg: "white",
    bg: "green",
    border: { fg: "white" },
    hover: { bg: "blue" },
    focus: { bg: "blue", border: { fg: "yellow" } }
  }
});

const nextFaucetBox = blessed.box({
  label: " Account Next Faucet ",
  top: "center",
  left: "center",
  width: "50%",
  height: "50%",
  border: { type: "line" },
  style: {
    fg: "white",
    bg: "default",
    border: { fg: "yellow" }
  },
  hidden: true
});

const nextFaucetList = blessed.list({
  parent: nextFaucetBox,
  top: 0,
  left: 0,
  width: "100%-2",
  height: "100%-5",
  keys: true,
  vi: true,
  mouse: true,
  style: {
    selected: { bg: "yellow", fg: "black" },
    item: { fg: "white" }
  },
  padding: { left: 1, top: 1 }
});

const closeButton = blessed.button({
  parent: nextFaucetBox,
  bottom: 1,
  left: "center",
  width: 10,
  height: 3,
  content: "Close",
  align: "center",
  border: { type: "line" },
  clickable: true,
  keys: true,
  mouse: true,
  style: {
    fg: "white",
    bg: "red",
    border: { fg: "white" },
    hover: { bg: "magenta" },
    focus: { bg: "magenta", border: { fg: "yellow" } }
  }
});


screen.append(headerBox);
screen.append(statusBox);
screen.append(walletBox);
screen.append(logBox);
screen.append(menuBox);
screen.append(dailyActivitySubMenu);
screen.append(faucetSubMenu);
screen.append(configForm);
screen.append(keyForm);
screen.append(nextFaucetBox);

if (!global.__handlersAttached) {
  global.__handlersAttached = true;

  function safeRemoveListeners(el, ev) {
    if (!el) return;
    if (typeof el.removeAllListeners === "function") {
      try { el.removeAllListeners(ev); } catch(e) {}
    } else if (typeof el.off === "function") {
      try { el.off(ev); } catch(e) {}
    }
  }

  const handleConfigSubmit = makeDebouncedHandler(() => {
    try {
      if (configForm && typeof configForm.submit === "function") {
        configForm.submit();
      } else {
      }
    } catch (e) {}
    try { screen.render(); } catch(e){}
  }, 500);

  safeRemoveListeners(configSubmitButton, "press");
  safeRemoveListeners(configSubmitButton, "click");

  configSubmitButton.on("press", handleConfigSubmit);
  configSubmitButton.on("click", () => {
    try { screen.focusPush(configSubmitButton); } catch(e){}
    handleConfigSubmit();
  });

  const handleKeySubmit = makeDebouncedHandler(() => {
    try {
      if (keyForm && typeof keyForm.submit === "function") {
        keyForm.submit();
      } else {}
    } catch (e) {}
    try { screen.render(); } catch(e){}
  }, 500);

  safeRemoveListeners(keySubmitButton, "press");
  safeRemoveListeners(keySubmitButton, "click");

  keySubmitButton.on("press", handleKeySubmit);
  keySubmitButton.on("click", () => {
    try { screen.focusPush(keySubmitButton); } catch(e){}
    handleKeySubmit();
  });

  const handleClose = makeDebouncedHandler(() => {
    try {
      if (typeof nextFaucetBox !== "undefined" && nextFaucetBox.hide) nextFaucetBox.hide();
      if (typeof faucetSubMenu !== "undefined" && faucetSubMenu.show) faucetSubMenu.show();
    } catch (e) {}
    setTimeout(() => {
      try {
        if (faucetSubMenu && faucetSubMenu.visible) {
          screen.focusPush(faucetSubMenu);
        } else {
          screen.focusPush && screen.focusPush(menuBox);
        }
        screen.render();
      } catch(e){}
    }, 100);
  }, 400);

  safeRemoveListeners(closeButton, "press");
  safeRemoveListeners(closeButton, "click");

  closeButton.on("press", handleClose);
  closeButton.on("click", () => {
    try { screen.focusPush(closeButton); } catch(e){}
    handleClose();
  });

  try {
    safeRemoveListeners(configForm, "submit");
    configForm.on("submit", (data) => {
      screen.render();
    });
  } catch(e){}

  try {
    safeRemoveListeners(keyForm, "submit");
    keyForm.on("submit", (data) => {
      screen.render();
    });
  } catch(e){}
}

let renderQueue = [];
let isRendering = false;

function safeRender() {
  renderQueue.push(true);
  if (isRendering) return;
  isRendering = true;

  setTimeout(() => {
    try {
      if (!isHeaderRendered) {
        figlet.text("ANNISA", { font: "ANSI Shadow" }, (err, data) => {
          if (err) {
            headerBox.setContent("{center}{bold}Annisaazzahra123{/bold}{/center}");
          } else {
            const lines = data.split("\n");
            const half = Math.floor(lines.length / 2);

            const coloredLines = lines.map((line, index) =>
              index < half
                ? `{red-fg}${line}{/red-fg}`
                : `{white-fg}${line}{/white-fg}`
            );

            // bungkus center+bold sekali aja biar rapi
            headerBox.setContent(
              `{center}{bold}${coloredLines.join("\n")}{/bold}{/center}`
            );
          }
          isHeaderRendered = true;
          screen.render();
        });
      } else {
        screen.render();
      }
    } catch (error) {
      addLog(`UI render error: ${error.message}`, "error");
    }

    renderQueue.shift();
    isRendering = false;
    if (renderQueue.length > 0) safeRender();
  }, 100);
}

function adjustLayout() {
  const screenHeight = screen.height || 24;
  const screenWidth = screen.width || 80;
  headerBox.height = Math.max(6, Math.floor(screenHeight * 0.15));
  statusBox.top = headerBox.height;
  statusBox.height = Math.max(3, Math.floor(screenHeight * 0.07));
  statusBox.width = screenWidth - 2;
  walletBox.top = headerBox.height + statusBox.height;
  walletBox.width = Math.floor(screenWidth * 0.4);
  walletBox.height = Math.floor(screenHeight * 0.35);
  logBox.top = headerBox.height + statusBox.height;
  logBox.left = Math.floor(screenWidth * 0.41);
  logBox.width = screenWidth - walletBox.width - 2;
  logBox.height = screenHeight - (headerBox.height + statusBox.height);
  menuBox.top = headerBox.height + statusBox.height + walletBox.height;
  menuBox.width = Math.floor(screenWidth * 0.4);
  menuBox.height = screenHeight - (headerBox.height + statusBox.height + walletBox.height);

  if (menuBox.top != null) {
    dailyActivitySubMenu.top = menuBox.top;
    dailyActivitySubMenu.width = menuBox.width;
    dailyActivitySubMenu.height = menuBox.height;
    dailyActivitySubMenu.left = menuBox.left;
    faucetSubMenu.top = menuBox.top;
    faucetSubMenu.width = menuBox.width;
    faucetSubMenu.height = menuBox.height;
    faucetSubMenu.left = menuBox.left;
    configForm.width = Math.floor(screenWidth * 0.3);
    configForm.height = Math.floor(screenHeight * 0.4);
    keyForm.width = Math.floor(screenWidth * 0.3);
    keyForm.height = Math.floor(screenHeight * 0.3);
    nextFaucetBox.width = Math.floor(screenWidth * 0.5);
    nextFaucetBox.height = Math.floor(screenHeight * 0.5);
  }

  safeRender();
}

function updateStatus() {
  try {
    const isProcessingDaily = activityRunning || (isCycleRunning && dailyActivityInterval !== null);
    const isProcessingFaucet = isFaucetRunning;
    const status = (isProcessingDaily || isProcessingFaucet)
      ? `${loadingSpinner[spinnerIndex]} ${chalk.yellowBright("Running")}`
      : chalk.green("Idle");
    const statusText = `Status: ${status} | | Active Account: ${getShortAddress(walletInfo.address)} | Total Accounts: ${accounts.length} | Auto Bundle: ${dailyActivityConfig.bundleRepetitions}x | Auto Swap: ${dailyActivityConfig.swapRepetitions}x | Auto Transfer: ${dailyActivityConfig.transferRepetitions}x | Auto Add Contact: ${dailyActivityConfig.addContactRepetitions}x | Loop: ${dailyActivityConfig.loopHours}h | INCENTIV TESTNET NISS`;
    statusBox.setContent(statusText);
    if (isProcessingDaily || isProcessingFaucet) {
      if (blinkCounter % 1 === 0) {
        statusBox.style.border.fg = borderBlinkColors[borderBlinkIndex];
        borderBlinkIndex = (borderBlinkIndex + 1) % borderBlinkColors.length;
      }
      blinkCounter++;
    } else {
      statusBox.style.border.fg = "cyan";
    }
    spinnerIndex = (spinnerIndex + 1) % loadingSpinner.length;
    safeRender();
  } catch (error) {
    addLog(`Status update error: ${error.message}`, "error");
  }
}

async function updateWallets() {
  try {
    const walletData = await updateWalletData();
    const header = `${chalk.bold.cyan("  Smart Address").padEnd(20)}     ${chalk.bold.cyan("TCENT".padEnd(10))} ${chalk.bold.cyan("SMPL".padEnd(10))} ${chalk.bold.cyan("BULL".padEnd(10))} ${chalk.bold.cyan("FLIP".padEnd(10))}`;
    const separator = chalk.gray("-".repeat(70));
    walletBox.setItems([header, separator, ...walletData]);
    walletBox.select(0);
    safeRender();
  } catch (error) {
    addLog(`Failed to update wallet data: ${error.message}`, "error");
  }
}

function updateLogs() {
  try {
    logBox.add(transactionLogs[transactionLogs.length - 1] || chalk.gray("No logs available."));
    logBox.scrollTo(transactionLogs.length);
    safeRender();
  } catch (error) {
    addLog(`Log update failed: ${error.message}`, "error");
  }
}

function updateMenu() {
  try {
    const items = [
      "Active All Account",
      isCycleRunning ? "Stop Auto Daily Activity" : "Start Auto Daily Activity",
      "Claim Faucet",
      "Set Manual Config",
      "Clear Logs",
      "Refresh",
      "Exit"
    ];
    menuBox.setItems(items);
    safeRender();
  } catch (error) {
    addLog(`Menu update failed: ${error.message}`, "error");
  }
}

function updateFaucetMenu() {
  try {
    const items = [
      isFaucetRunning ? "Stop Auto Claim Faucet" : "Auto Claim Faucet",
      "Change 2 Captcha Key",
      "Check Account Next Faucet",
      "Refresh",
      "Clear Logs",
      "Back to Main Menu"
    ];
    faucetSubMenu.setItems(items);
    safeRender();
  } catch (error) {
    addLog(`Faucet menu update failed: ${error.message}`, "error");
  }
}

const statusInterval = setInterval(updateStatus, 100);

logBox.key(["up"], () => {
  if (screen.focused === logBox) {
    logBox.scroll(-1);
    safeRender();
  }
});

logBox.key(["down"], () => {
  if (screen.focused === logBox) {
    logBox.scroll(1);
    safeRender();
  }
});

logBox.on("click", () => {
  screen.focusPush(logBox);
  logBox.style.border.fg = "yellow";
  menuBox.style.border.fg = "red";
  dailyActivitySubMenu.style.border.fg = "blue";
  faucetSubMenu.style.border.fg = "green";
  safeRender();
});

logBox.on("blur", () => {
  logBox.style.border.fg = "magenta";
  safeRender();
});

menuBox.on("select", async (item) => {
  const action = item.getText();
  switch (action) {
    case "Active All Account":
      await activeAllAccounts();
      break;
    case "Start Auto Daily Activity":
      if (isCycleRunning) {
        addLog("Daily activity is already running.", "error");
      } else {
        await runDailyActivity();
      }
      break;
    case "Stop Auto Daily Activity":
      shouldStop = true;
      if (dailyActivityInterval) {
        clearTimeout(dailyActivityInterval);
        dailyActivityInterval = null;
        addLog("Cleared daily activity interval.", "info");
      }
      addLog("Stopping daily activity. Please wait for ongoing process to complete.", "info");
      safeRender();
      if (activeProcesses <= 0) {
        activityRunning = false;
        isCycleRunning = false;
        shouldStop = false;
        hasLoggedSleepInterrupt = false;
        addLog("Daily activity stopped successfully.", "success");
        updateMenu();
        updateStatus();
        safeRender();
      } else {
        const stopCheckInterval = setInterval(() => {
          if (activeProcesses <= 0) {
            clearInterval(stopCheckInterval);
            activityRunning = false;
            isCycleRunning = false;
            shouldStop = false;
            hasLoggedSleepInterrupt = false;
            activeProcesses = 0;
            addLog("Daily activity stopped successfully.", "success");
            updateMenu();
            updateStatus();
            safeRender();
          } else {
            addLog(`Waiting for ${activeProcesses} process(es) to complete...`, "info");
            safeRender();
          }
        }, 1000);
      }
      break;
    case "Claim Faucet":
      menuBox.hide();
      faucetSubMenu.show();
      updateFaucetMenu();
      setTimeout(() => {
        if (faucetSubMenu.visible) {
          screen.focusPush(faucetSubMenu);
          faucetSubMenu.style.border.fg = "yellow";
          logBox.style.border.fg = "magenta";
          safeRender();
        }
      }, 100);
      break;
    case "Set Manual Config":
      menuBox.hide();
      dailyActivitySubMenu.show();
      setTimeout(() => {
        if (dailyActivitySubMenu.visible) {
          screen.focusPush(dailyActivitySubMenu);
          dailyActivitySubMenu.style.border.fg = "yellow";
          logBox.style.border.fg = "magenta";
          safeRender();
        }
      }, 100);
      break;
    case "Clear Logs":
      clearTransactionLogs();
      break;
    case "Refresh":
      await updateWallets();
      addLog("Data refreshed.", "success");
      break;
    case "Exit":
      clearInterval(statusInterval);
      process.exit(0);
  }
});

dailyActivitySubMenu.on("select", (item) => {
  const action = item.getText();
  switch (action) {
    case "Set Bundle Repetitions":
      configForm.configType = "bundleRepetitions";
      configForm.setLabel(" Enter Bundle Repetitions ");
      minLabel.hide();
      maxLabel.hide();
      configInput.setValue(dailyActivityConfig.bundleRepetitions.toString());
      configInputMax.setValue("");
      configInputMax.hide();
      configForm.show();
      setTimeout(() => {
        if (configForm.visible) {
          screen.focusPush(configInput);
          configInput.clearValue();
          safeRender();
        }
      }, 100);
      break;
    case "Set Add Contact Repetitions":
      configForm.configType = "addContactRepetitions";
      configForm.setLabel(" Enter Add Contact Repetitions ");
      minLabel.hide();
      maxLabel.hide();
      configInput.setValue(dailyActivityConfig.addContactRepetitions.toString());
      configInputMax.setValue("");
      configInputMax.hide();
      configForm.show();
      setTimeout(() => {
        if (configForm.visible) {
          screen.focusPush(configInput);
          configInput.clearValue();
          safeRender();
        }
      }, 100);
      break;
    case "Set Swap Repetitions":
      configForm.configType = "swapRepetitions";
      configForm.setLabel(" Enter Swap Repetitions ");
      minLabel.hide();
      maxLabel.hide();
      configInput.setValue(dailyActivityConfig.swapRepetitions.toString());
      configInputMax.setValue("");
      configInputMax.hide();
      configForm.show();
      setTimeout(() => {
        if (configForm.visible) {
          screen.focusPush(configInput);
          configInput.clearValue();
          safeRender();
        }
      }, 100);
      break;
    case "Set TCENT Swap Range":
      configForm.configType = "tcentSwapRange";
      configForm.setLabel(" Enter TCENT Swap Range ");
      minLabel.show();
      maxLabel.show();
      configInput.setValue(dailyActivityConfig.tcentSwapRange.min.toString());
      configInputMax.setValue(dailyActivityConfig.tcentSwapRange.max.toString());
      configInputMax.show();
      configForm.show();
      setTimeout(() => {
        if (configForm.visible) {
          screen.focusPush(configInput);
          configInput.clearValue();
          safeRender();
        }
      }, 100);
      break;
    case "Set SMPL Swap Range":
      configForm.configType = "smplSwapRange";
      configForm.setLabel(" Enter SMPL Swap Range ");
      minLabel.show();
      maxLabel.show();
      configInput.setValue(dailyActivityConfig.smplSwapRange.min.toString());
      configInputMax.setValue(dailyActivityConfig.smplSwapRange.max.toString());
      configInputMax.show();
      configForm.show();
      setTimeout(() => {
        if (configForm.visible) {
          screen.focusPush(configInput);
          configInput.clearValue();
          safeRender();
        }
      }, 100);
      break;
    case "Set BULL Swap Range":
      configForm.configType = "bullSwapRange";
      configForm.setLabel(" Enter BULL Swap Range ");
      minLabel.show();
      maxLabel.show();
      configInput.setValue(dailyActivityConfig.bullSwapRange.min.toString());
      configInputMax.setValue(dailyActivityConfig.bullSwapRange.max.toString());
      configInputMax.show();
      configForm.show();
      setTimeout(() => {
        if (configForm.visible) {
          screen.focusPush(configInput);
          configInput.clearValue();
          safeRender();
        }
      }, 100);
      break;
    case "Set FLIP Swap Range":
      configForm.configType = "flipSwapRange";
      configForm.setLabel(" Enter FLIP Swap Range ");
      minLabel.show();
      maxLabel.show();
      configInput.setValue(dailyActivityConfig.flipSwapRange.min.toString());
      configInputMax.setValue(dailyActivityConfig.flipSwapRange.max.toString());
      configInputMax.show();
      configForm.show();
      setTimeout(() => {
        if (configForm.visible) {
          screen.focusPush(configInput);
          configInput.clearValue();
          safeRender();
        }
      }, 100);
      break;
    case "Set Transfer Repetitions":
      configForm.configType = "transferRepetitions";
      configForm.setLabel(" Enter Transfer Repetitions ");
      minLabel.hide();
      maxLabel.hide();
      configInput.setValue(dailyActivityConfig.transferRepetitions.toString());
      configInputMax.setValue("");
      configInputMax.hide();
      configForm.show();
      setTimeout(() => {
        if (configForm.visible) {
          screen.focusPush(configInput);
          configInput.clearValue();
          safeRender();
        }
      }, 100);
      break;
    case "Set TCENT Transfer Range":
      configForm.configType = "tcentTransferRange";
      configForm.setLabel(" Enter TCENT Transfer Range ");
      minLabel.show();
      maxLabel.show();
      configInput.setValue(dailyActivityConfig.tcentTransferRange.min.toString());
      configInputMax.setValue(dailyActivityConfig.tcentTransferRange.max.toString());
      configInputMax.show();
      configForm.show();
      setTimeout(() => {
        if (configForm.visible) {
          screen.focusPush(configInput);
          configInput.clearValue();
          safeRender();
        }
      }, 100);
      break;
    case "Set Loop Daily":
      configForm.configType = "loopHours";
      configForm.setLabel(" Enter Loop Hours (Min 1 Hours) ");
      minLabel.hide();
      maxLabel.hide();
      configInput.setValue(dailyActivityConfig.loopHours.toString());
      configInputMax.setValue("");
      configInputMax.hide();
      configForm.show();
      setTimeout(() => {
        if (configForm.visible) {
          screen.focusPush(configInput);
          configInput.clearValue();
          safeRender();
        }
      }, 100);
      break;
    case "Back to Main Menu":
      dailyActivitySubMenu.hide();
      menuBox.show();
      setTimeout(() => {
        if (menuBox.visible) {
          screen.focusPush(menuBox);
          menuBox.style.border.fg = "cyan";
          dailyActivitySubMenu.style.border.fg = "blue";
          logBox.style.border.fg = "magenta";
          safeRender();
        }
      }, 100);
      break;
  }
});

async function updateNextFaucetList() {
  const items = [];
  for (let i = 0; i < accounts.length; i++) {
    const account = accounts[i];
    if (account.isClaiming || !account.smartAddress) continue;

    const proxyUrl = proxies[i % proxies.length] || null;
    if (!account.nextFaucetTime) {
      try {
        if (await testToken(account, proxyUrl)) {
          const userRes = await makeApiCall('https://api.testnet.incentiv.io/api/user', 'GET', null, proxyUrl, account.token);
          if (userRes.code === 200) {
            account.nextFaucetTime = userRes.result.nextFaucetRequestTimestamp || 0;
          }
        }
      } catch (error) {
        addLog(`Failed to fetch next faucet time for account ${i + 1}: ${error.message}`, "error");
        continue;
      }
    }

    const timeLeft = account.nextFaucetTime - Date.now();
    let status;
    if (timeLeft <= 0) {
      status = "Ready";
    } else {
      const hours = Math.floor(timeLeft / 3600000);
      const minutes = Math.floor((timeLeft % 3600000) / 60000);
      const seconds = Math.floor((timeLeft % 60000) / 1000);
      status = `${hours.toString().padStart(2, '0')}:${minutes.toString().padStart(2, '0')}:${seconds.toString().padStart(2, '0')}`;
    }

    items.push(`Account ${i + 1}: ${getShortAddress(account.smartAddress)} - ${status}`);
  }
  nextFaucetList.setItems(items.length > 0 ? items : ["No accounts on cooldown"]);
  safeRender();
}

const debouncedFaucetSelect = makeDebouncedHandler(async (item) => {
  const action = item.getText();
  switch (action) {
    case "Auto Claim Faucet":
      await autoClaimFaucet();
      break;
    case "Stop Auto Claim Faucet":
      if (isStoppingFaucet) return; 
      isStoppingFaucet = true;
      shouldStopFaucet = true;
      addLog("Stopping auto claim faucet. Please wait for ongoing processes to complete.", "info");
      safeRender();
      setTimeout(() => { isStoppingFaucet = false; }, 5000); 
      break;
    case "Check Account Next Faucet":
      await updateNextFaucetList();
      nextFaucetBox.show();
      screen.focusPush(nextFaucetList);
      const updateInterval = setInterval(updateNextFaucetList, 1000);
      nextFaucetBox.once("hide", () => {
        clearInterval(updateInterval);
      });
      safeRender();
      break;
    case "Change 2 Captcha Key":
      keyForm.show();
      setTimeout(() => {
        if (keyForm.visible) {
          screen.focusPush(keyInput);
          keyInput.clearValue();
          safeRender();
        }
      }, 100);
      break;
    case "Refresh":
      await updateWallets();
      addLog("Data refreshed.", "success");
      break;
    case "Clear Logs":
      clearTransactionLogs();
      break;
    case "Back to Main Menu":
      faucetSubMenu.hide();
      menuBox.show();
      setTimeout(() => {
        if (menuBox.visible) {
          screen.focusPush(menuBox);
          menuBox.style.border.fg = "cyan";
          faucetSubMenu.style.border.fg = "green";
          logBox.style.border.fg = "magenta";
          safeRender();
        }
      }, 100);
      break;
  }
}, 500);

faucetSubMenu.on("select", debouncedFaucetSelect);


nextFaucetBox.key(["escape"], () => {
  nextFaucetBox.hide();
  faucetSubMenu.show();
  setTimeout(() => {
    if (faucetSubMenu.visible) {
      screen.focusPush(faucetSubMenu);
      faucetSubMenu.style.border.fg = "yellow";
      logBox.style.border.fg = "magenta";
      safeRender();
    }
  }, 100);
});

let isSubmitting = false;
configForm.on("submit", () => {
  if (isSubmitting) return;
  isSubmitting = true;

  const inputValue = configInput.getValue().trim();
  let value, maxValue;
  try {
    if (configForm.configType === "loopHours" || configForm.configType === "swapRepetitions" || configForm.configType === "transferRepetitions" || configForm.configType === "addContactRepetitions" || configForm.configType === "bundleRepetitions") {
      value = parseInt(inputValue);
    } else {
      value = parseFloat(inputValue);
    }
    if (["tcentSwapRange", "smplSwapRange", "bullSwapRange", "flipSwapRange", "tcentTransferRange"].includes(configForm.configType)) {
      maxValue = parseFloat(configInputMax.getValue().trim());
      if (isNaN(maxValue) || maxValue <= 0) {
        addLog("Invalid Max value. Please enter a positive number.", "error");
        configInputMax.clearValue();
        screen.focusPush(configInputMax);
        safeRender();
        isSubmitting = false;
        return;
      }
    }
    if (isNaN(value) || value <= 0) {
      addLog("Invalid input. Please enter a positive number.", "error");
      configInput.clearValue();
      screen.focusPush(configInput);
      safeRender();
      isSubmitting = false;
      return;
    }
    if (configForm.configType === "loopHours" && value < 1) {
      addLog("Invalid input. Minimum is 1 hour.", "error");
      configInput.clearValue();
      screen.focusPush(configInput);
      safeRender();
      isSubmitting = false;
      return;
    }
  } catch (error) {
    addLog(`Invalid format: ${error.message}`, "error");
    configInput.clearValue();
    screen.focusPush(configInput);
    safeRender();
    isSubmitting = false;
    return;
  }

  if (configForm.configType === "bundleRepetitions") {
    dailyActivityConfig.bundleRepetitions = Math.floor(value);
    addLog(`Bundle Repetitions set to ${dailyActivityConfig.bundleRepetitions}`, "success");
  } else if (configForm.configType === "addContactRepetitions") {
    dailyActivityConfig.addContactRepetitions = Math.floor(value);
    addLog(`Add Contact Repetitions set to ${dailyActivityConfig.addContactRepetitions}`, "success");
  } else if (configForm.configType === "swapRepetitions") {
    dailyActivityConfig.swapRepetitions = Math.floor(value);
    addLog(`Swap Repetitions set to ${dailyActivityConfig.swapRepetitions}`, "success");
  } else if (configForm.configType === "tcentSwapRange") {
    if (value > maxValue) {
      addLog("Min value cannot be greater than Max value.", "error");
      configInput.clearValue();
      configInputMax.clearValue();
      screen.focusPush(configInput);
      safeRender();
      isSubmitting = false;
      return;
    }
    dailyActivityConfig.tcentSwapRange.min = value;
    dailyActivityConfig.tcentSwapRange.max = maxValue;
    addLog(`TCENT Swap Range set to ${value} - ${maxValue}`, "success");
  } else if (configForm.configType === "smplSwapRange") {
    if (value > maxValue) {
      addLog("Min value cannot be greater than Max value.", "error");
      configInput.clearValue();
      configInputMax.clearValue();
      screen.focusPush(configInput);
      safeRender();
      isSubmitting = false;
      return;
    }
    dailyActivityConfig.smplSwapRange.min = value;
    dailyActivityConfig.smplSwapRange.max = maxValue;
    addLog(`SMPL Swap Range set to ${value} - ${maxValue}`, "success");
  } else if (configForm.configType === "bullSwapRange") {
    if (value > maxValue) {
      addLog("Min value cannot be greater than Max value.", "error");
      configInput.clearValue();
      configInputMax.clearValue();
      screen.focusPush(configInput);
      safeRender();
      isSubmitting = false;
      return;
    }
    dailyActivityConfig.bullSwapRange.min = value;
    dailyActivityConfig.bullSwapRange.max = maxValue;
    addLog(`BULL Swap Range set to ${value} - ${maxValue}`, "success");
  } else if (configForm.configType === "flipSwapRange") {
    if (value > maxValue) {
      addLog("Min value cannot be greater than Max value.", "error");
      configInput.clearValue();
      configInputMax.clearValue();
      screen.focusPush(configInput);
      safeRender();
      isSubmitting = false;
      return;
    }
    dailyActivityConfig.flipSwapRange.min = value;
    dailyActivityConfig.flipSwapRange.max = maxValue;
    addLog(`FLIP Swap Range set to ${value} - ${maxValue}`, "success");
  } else if (configForm.configType === "transferRepetitions") { 
    dailyActivityConfig.transferRepetitions = Math.floor(value);
    addLog(`Transfer Repetitions set to ${dailyActivityConfig.transferRepetitions}`, "success");
  } else if (configForm.configType === "tcentTransferRange") {
    if (value > maxValue) {
      addLog("Min value cannot be greater than Max value.", "error");
      configInput.clearValue();
      configInputMax.clearValue();
      screen.focusPush(configInput);
      safeRender();
      isSubmitting = false;
      return;
    }
    dailyActivityConfig.tcentTransferRange.min = value;
    dailyActivityConfig.tcentTransferRange.max = maxValue;
    addLog(`TCENT Transfer Range set to ${value} - ${maxValue}`, "success");
  } else if (configForm.configType === "loopHours") {
    dailyActivityConfig.loopHours = value;
    addLog(`Loop Daily set to ${value} hours`, "success");
  }
  saveConfig();
  updateStatus();

  configForm.hide();
  dailyActivitySubMenu.show();
  setTimeout(() => {
    if (dailyActivitySubMenu.visible) {
      screen.focusPush(dailyActivitySubMenu);
      dailyActivitySubMenu.style.border.fg = "yellow";
      logBox.style.border.fg = "magenta";
      safeRender();
    }
    isSubmitting = false;
  }, 100);
});

configInput.key(["enter"], () => {
  if (["tcentSwapRange", "smplSwapRange", "bullSwapRange", "flipSwapRange", "tcentTransferRange"].includes(configForm.configType)) {
    screen.focusPush(configInputMax);
  } else {
    configForm.submit();
  }
});

configInputMax.key(["enter"], () => {
  configForm.submit();
});



configForm.key(["escape"], () => {
  configForm.hide();
  dailyActivitySubMenu.show();
  setTimeout(() => {
    if (dailyActivitySubMenu.visible) {
      screen.focusPush(dailyActivitySubMenu);
      dailyActivitySubMenu.style.border.fg = "yellow";
      logBox.style.border.fg = "magenta";
      safeRender();
    }
  }, 100);
});

dailyActivitySubMenu.key(["escape"], () => {
  dailyActivitySubMenu.hide();
  menuBox.show();
  setTimeout(() => {
    if (menuBox.visible) {
      screen.focusPush(menuBox);
      menuBox.style.border.fg = "cyan";
      dailyActivitySubMenu.style.border.fg = "blue";
      logBox.style.border.fg = "magenta";
      safeRender();
    }
  }, 100);
});

keyInput.key(["enter"], () => {
  keyForm.submit();
});


keyForm.on("submit", () => {
  const key = keyInput.getValue().trim();
  if (key) {
    fs.writeFileSync(TWO_CAPTCHA_FILE, JSON.stringify({ twoCaptchaKey: key }));
    addLog("2Captcha key saved successfully.", "success");
  } else {
    addLog("Invalid key.", "error");
  }
  keyForm.hide();
  faucetSubMenu.show();
  setTimeout(() => {
    if (faucetSubMenu.visible) {
      screen.focusPush(faucetSubMenu);
      faucetSubMenu.style.border.fg = "yellow";
      logBox.style.border.fg = "magenta";
      safeRender();
    }
  }, 100);
});

keyForm.key(["escape"], () => {
  keyForm.hide();
  faucetSubMenu.show();
  setTimeout(() => {
    if (faucetSubMenu.visible) {
      screen.focusPush(faucetSubMenu);
      faucetSubMenu.style.border.fg = "yellow";
      logBox.style.border.fg = "magenta";
      safeRender();
    }
  }, 100);
});

faucetSubMenu.key(["escape"], () => {
  faucetSubMenu.hide();
  menuBox.show();
  setTimeout(() => {
    if (menuBox.visible) {
      screen.focusPush(menuBox);
      menuBox.style.border.fg = "cyan";
      faucetSubMenu.style.border.fg = "green";
      logBox.style.border.fg = "magenta";
      safeRender();
    }
  }, 100);
});

nextFaucetBox.key(["escape"], () => {
  nextFaucetBox.hide();
  faucetSubMenu.show();
  setTimeout(() => {
    if (faucetSubMenu.visible) {
      screen.focusPush(faucetSubMenu);
      faucetSubMenu.style.border.fg = "yellow";
      logBox.style.border.fg = "magenta";
      safeRender();
    }
  }, 100);
});

function loadTwoCaptchaKey() {
  try {
    if (fs.existsSync(TWO_CAPTCHA_FILE)) {
      const data = fs.readFileSync(TWO_CAPTCHA_FILE, "utf8");
      const config = JSON.parse(data);
      return config.twoCaptchaKey;
    }
  } catch (error) {
    addLog(`Failed to load 2Captcha key: ${error.message}`, "error");
  }
  return null;
}

async function solveTurnstile(twoCaptchaKey) {
  try {
    addLog(`Sending captcha task to 2Captcha for solving.`, "info");
    const res = await axios.post('https://2captcha.com/in.php', null, {
      params: {
        key: twoCaptchaKey,
        method: 'turnstile',
        sitekey: TURNSTILE_SITEKEY,
        pageurl: PAGE_URL,
        json: 1
      }
    });
    if (res.data.status !== 1) {
      throw new Error(res.data.request);
    }
    const requestId = res.data.request;

    addLog(`Captcha task sent, waiting for solution (ID: ${requestId})...`, "wait");
    let token;
    while (true) {
      await sleep(5000);
      const poll = await axios.get('https://2captcha.com/res.php', {
        params: {
          key: twoCaptchaKey,
          action: 'get',
          id: requestId,
          json: 1
        }
      });
      if (poll.data.status === 1) {
        token = poll.data.request;
        addLog(`Captcha solved successfully.`, "success");
        break;
      } else if (poll.data.request === 'CAPCHA_NOT_READY') {
        addLog(`Captcha not ready yet, polling again...`, "wait");
        continue;
      } else {
        throw new Error(poll.data.request);
      }
    }
    return token;
  } catch (error) {
    addLog(`Failed to solve Turnstile: ${error.message}`, "error");
    throw error;
  }
}

async function claimFaucet(account, proxyUrl) {
  account.isClaiming = true;
  try {
    addLog(`Checking faucet eligibility for ${getShortAddress(account.smartAddress)}`, "info");
    const userRes = await makeApiCall('https://api.testnet.incentiv.io/api/user', 'GET', null, proxyUrl, account.token);
    if (userRes.code !== 200) {
      throw new Error('Failed to fetch user data');
    }
    const nextTimestamp = userRes.result.nextFaucetRequestTimestamp;
    account.nextFaucetTime = nextTimestamp;
    if (Date.now() < nextTimestamp) {
      addLog(`Account ${getShortAddress(account.smartAddress)} not eligible for faucet yet. Next at ${new Date(nextTimestamp).toLocaleString()}`, "warn");
      return false;
    } else {
      addLog(`Account eligible for faucet claim. Proceeding...`, "success");
    }

    const usingProxy = proxyUrl ? `Yes (${proxyUrl})` : 'No';
    const ip = await getIP(proxyUrl);
    addLog(`Preparing to claim faucet. Using proxy: ${usingProxy}, IP: ${ip}`, "info");

    const twoCaptchaKey = loadTwoCaptchaKey();
    if (!twoCaptchaKey) {
      throw new Error('2Captcha key not set');
    }

    const token = await solveTurnstile(twoCaptchaKey);
    addLog(`Submitting faucet claim with solved captcha.`, "info");
    const payload = { verificationToken: token };
    const faucetRes = await makeApiCall('https://api.testnet.incentiv.io/api/user/faucet', 'POST', payload, proxyUrl, account.token);
    if (faucetRes.code !== 200) {
      throw new Error('Failed to claim faucet');
    }

    account.nextFaucetTime = faucetRes.result.nextFaucetRequestTimestamp;
    addLog(`Faucet claimed successfully for ${getShortAddress(account.smartAddress)}. Amount: ${faucetRes.result.amount}, Next: ${new Date(faucetRes.result.nextFaucetRequestTimestamp).toLocaleString()}`, "success");
    return true;
  } catch (error) {
    addLog(`Faucet claim failed for ${getShortAddress(account.smartAddress)}: ${error.message}`, "error");
    return false;
  } finally {
    account.isClaiming = false;
  }
}

async function autoClaimFaucet() {
  let twoCaptchaKey = loadTwoCaptchaKey();
  if (!twoCaptchaKey) {
    addLog("2Captcha key not found. Please set it first.", "error");
    keyForm.show();
    setTimeout(() => {
      if (keyForm.visible) {
        screen.focusPush(keyInput);
        keyInput.clearValue();
        safeRender();
      }
    }, 100);
    return;
  }

  isFaucetRunning = true;
  shouldStopFaucet = false;
  isStoppingFaucet = false;
  updateFaucetMenu();
  updateStatus();
  safeRender();

  addLog("Starting Auto Claim Faucet..", "info");

  async function faucetLoop() {
    if (shouldStopFaucet) {
      isFaucetRunning = false;
      shouldStopFaucet = false;
      addLog("Auto claim faucet stopped.", "success");
      updateFaucetMenu();
      updateStatus();
      safeRender();
      return;
    }

    let claimed = 0;
    let minNext = Infinity;

    for (let i = 0; i < accounts.length; i++) {
      const account = accounts[i];
      const proxyUrl = proxies[i % proxies.length] || null;

      if (!account.smartAddress || !(await testToken(account, proxyUrl))) {
        try {
          await loginAccount(account, proxyUrl);
        } catch (e) {}
      }

      if (account.smartAddress) {
        if (!account.nextFaucetTime || Date.now() >= account.nextFaucetTime) {
          try {
            const userRes = await makeApiCall('https://api.testnet.incentiv.io/api/user', 'GET', null, proxyUrl, account.token);
            if (userRes.code === 200) {
              account.nextFaucetTime = userRes.result.nextFaucetRequestTimestamp;
            }
          } catch (e) {
            addLog(`Failed to fetch user for eligibility: ${e.message}`, "error");
            continue;
          }
        }

        if (Date.now() >= account.nextFaucetTime) {
          if (await claimFaucet(account, proxyUrl)) {
            claimed++;
          }
        }

        if (account.nextFaucetTime > Date.now()) {
          minNext = Math.min(minNext, account.nextFaucetTime);
        }
      }
    }

    if (claimed > 0) {
      addLog(`Claimed for ${claimed} accounts in this cycle.`, "success");
    } else {
      addLog("No accounts eligible in this cycle.", "info");
    }

    let waitTime = 60000; 
    if (minNext !== Infinity) {
      waitTime = minNext - Date.now() + 1000; 
      if (waitTime < 1000) waitTime = 1000;
    }

    setTimeout(faucetLoop, waitTime);
  }

  faucetLoop();
}

keyForm.on("submit", () => {
  const key = keyInput.getValue().trim();
  if (key) {
    fs.writeFileSync(TWO_CAPTCHA_FILE, JSON.stringify({ twoCaptchaKey: key }));
    addLog("2Captcha key saved successfully.", "success");
  } else {
    addLog("Invalid key.", "error");
  }
  keyForm.hide();
  faucetSubMenu.show();
  setTimeout(() => {
    if (faucetSubMenu.visible) {
      screen.focusPush(faucetSubMenu);
      faucetSubMenu.style.border.fg = "yellow";
      logBox.style.border.fg = "magenta";
      safeRender();
    }
  }, 100);
});

screen.key(["escape", "q", "C-c"], () => {
  addLog("Exiting application", "info");
  clearInterval(statusInterval);
  process.exit(0);
});

async function initialize() {
  try {
    loadConfig();
    loadAccounts();
    loadProxies();
    loadRecipients();
    updateMenu(); 
    updateStatus();
    await updateWallets();
    updateLogs();
    safeRender();
    menuBox.focus();
  } catch (error) {
    addLog(`Initialization error: ${error.message}`, "error");
  }
}

setTimeout(() => {
  adjustLayout();
  screen.on("resize", adjustLayout);
}, 100);

initialize();
