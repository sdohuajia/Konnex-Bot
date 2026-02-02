const axios = require('axios');
const { ethers } = require('ethers');
const chalk = require('chalk');
const { HttpsProxyAgent } = require('https-proxy-agent');
const { SocksProxyAgent } = require('socks-proxy-agent');
const fs = require('fs');
const path = require('path');
const readlineSync = require('readline-sync');

class Konnex {
    constructor() {
        this.API_URL = {
            hub: "https://hub.konnex.world",
            testnet: "https://konnex-ai.xyz"
        };
        this.WEB_ID = "7857ae2c-2ebf-4871-a775-349bcdc416ce";
        this.ORG_ID = "dbe51e03-92cc-4a5a-8d57-61c10753246b";
        this.RULES_ID = "0b0dacb4-9b51-4b3d-b42e-700959c47bf9";
        this.referralCodes = []; // Will be loaded from referral.txt
        this.HEADERS = {};
        this.proxies = [];
        this.proxy_index = 0;
        this.account_proxies = {};
        this.sessions = {};
        this.ua_index = 0;

        this.USER_AGENTS = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:133.0) Gecko/20100101 Firefox/133.0",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1 Safari/605.1.15",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36 Edg/129.0.0.0",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36",
            "Mozilla/5.0 (X11; Linux x86_64; rv:133.0) Gecko/20100101 Firefox/133.0",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 OPR/117.0.0.0"
        ];

        this.USE_PROXY = false;
        this.ROTATE_PROXY = false;
    }

    clearTerminal() {
        console.clear();
    }

    log(message) {
        const now = new Date();
        const wibTime = now.toLocaleString('en-US', {
            timeZone: 'Asia/Jakarta',
            year: 'numeric',
            month: '2-digit',
            day: '2-digit',
            hour: '2-digit',
            minute: '2-digit',
            second: '2-digit',
            hour12: false
        });
        console.log(
            `${chalk.cyan.bold(`[ ${wibTime} WIB ]`)} ${chalk.white.bold('|')} ${message}`
        );
    }

    welcome() {
        console.log(
            chalk.green.bold('\n        Konnex ') + chalk.blue.bold('全自动化机器人\n')
        );
    }

    formatSeconds(seconds) {
        const hours = Math.floor(seconds / 3600);
        const minutes = Math.floor((seconds % 3600) / 60);
        const secs = Math.floor(seconds % 60);
        return `${String(hours).padStart(2, '0')}:${String(minutes).padStart(2, '0')}:${String(secs).padStart(2, '0')}`;
    }

    loadAccounts() {
        const filename = "accounts.txt";
        try {
            if (!fs.existsSync(filename)) {
                this.log(chalk.red.bold(`File ${filename} Not Found.`));
                return null;
            }
            const content = fs.readFileSync(filename, 'utf-8');
            const accounts = content.split('\n')
                .map(line => line.trim())
                .filter(line => line.length > 0);
            return accounts;
        } catch (e) {
            this.log(chalk.red.bold(`Failed To Load Accounts: ${e.message}`));
            return null;
        }
    }

    loadReferralAccounts() {
        const filename = "referral_accounts.txt";
        try {
            if (!fs.existsSync(filename)) {
                return [];
            }
            const content = fs.readFileSync(filename, 'utf-8');
            const accounts = content.split('\n')
                .map(line => line.trim())
                .filter(line => line.length > 0 && !line.startsWith('#'));
            return accounts;
        } catch (e) {
            this.log(chalk.red.bold(`Failed To Load Referral Accounts: ${e.message}`));
            return [];
        }
    }

    loadProxies() {
        const filename = "proxy.txt";
        try {
            if (!fs.existsSync(filename)) {
                this.log(chalk.red.bold(`File ${filename} Not Found.`));
                return;
            }
            const content = fs.readFileSync(filename, 'utf-8');
            this.proxies = content.split('\n')
                .map(line => line.trim())
                .filter(line => line.length > 0 && !line.startsWith('#'));

            if (this.proxies.length === 0) {
                this.log(chalk.red.bold('No Proxies Found.'));
                return;
            }

            this.log(
                chalk.green.bold('Proxies Total  : ') +
                chalk.white.bold(this.proxies.length)
            );
        } catch (e) {
            this.log(chalk.red.bold(`Failed To Load Proxies: ${e.message}`));
            this.proxies = [];
        }
    }

    loadReferralCodes() {
        const filename = "referral.txt";
        try {
            if (!fs.existsSync(filename)) {
                this.log(chalk.yellow.bold(`File ${filename} Not Found, Using Default Referral Code.`));
                this.referralCodes = ["ferdie"]; // 默认邀请码
                return;
            }
            const content = fs.readFileSync(filename, 'utf-8');
            this.referralCodes = content.split('\n')
                .map(line => line.trim())
                .filter(line => line.length > 0 && !line.startsWith('#'));

            if (this.referralCodes.length === 0) {
                this.log(chalk.yellow.bold('No Referral Codes Found, Using Default.'));
                this.referralCodes = ["ferdie"];
                return;
            }

            this.log(
                chalk.green.bold('Referral Codes : ') +
                chalk.white.bold(this.referralCodes.length)
            );
        } catch (e) {
            this.log(chalk.red.bold(`Failed To Load Referral Codes: ${e.message}`));
            this.referralCodes = ["ferdie"];
        }
    }

    getReferralCodeForAccount(accountIndex) {
        if (this.referralCodes.length === 0) {
            return "ferdie"; // 默认邀请码
        }
        // 如果邀请码数量少于账户数量,循环使用
        return this.referralCodes[accountIndex % this.referralCodes.length];
    }

    checkProxySchemes(proxy) {
        const schemes = ["http://", "https://", "socks4://", "socks5://"];
        if (schemes.some(scheme => proxy.startsWith(scheme))) {
            return proxy;
        }
        return `http://${proxy}`;
    }

    getProxyForAccount(accountIndex) {
        if (this.proxies.length === 0) {
            return null;
        }
        // 如果代理数量少于账户数量,超出的账户直连
        if (accountIndex >= this.proxies.length) {
            return null;
        }
        return this.checkProxySchemes(this.proxies[accountIndex]);
    }



    buildProxyConfig(proxy = null) {
        if (!proxy) {
            return null;
        }

        if (proxy.startsWith("socks")) {
            return new SocksProxyAgent(proxy);
        } else if (proxy.startsWith("http")) {
            return new HttpsProxyAgent(proxy);
        }

        throw new Error("Unsupported Proxy Type.");
    }

    displayProxy(proxyUrl = null) {
        if (!proxyUrl) return "No Proxy";

        let proxy = proxyUrl.replace(/^(http|https|socks4|socks5):\/\//, "");

        if (proxy.includes("@")) {
            proxy = proxy.split("@")[1];
        }

        return proxy;
    }

    getNextUserAgent() {
        const ua = this.USER_AGENTS[this.ua_index];
        this.ua_index = (this.ua_index + 1) % this.USER_AGENTS.length;
        return ua;
    }

    initializeHeaders(email, headerType) {
        if (!(email in this.HEADERS)) {
            this.HEADERS[email] = {};
        }

        if (!("ua" in this.HEADERS[email])) {
            this.HEADERS[email]["ua"] = this.getNextUserAgent();
        }

        const ua = this.HEADERS[email]["ua"];

        if (!(headerType in this.HEADERS[email])) {
            const baseHeaders = {
                "Accept-Encoding": "gzip, deflate, br",
                "Accept-Language": "id-ID,id;q=0.9,en-US;q=0.8,en;q=0.7",
                "Cache-Control": "no-cache",
                "Pragma": "no-cache",
                "Sec-Fetch-Dest": "empty",
                "Sec-Fetch-Mode": "cors",
                "User-Agent": ua
            };

            let headers;
            if (headerType === "hub") {
                headers = {
                    ...baseHeaders,
                    "Accept": "*/*",
                    "Origin": "https://hub.konnex.world",
                    "Referer": "https://hub.konnex.world/points",
                    "Sec-Fetch-Site": "same-origin",
                };
            } else if (headerType === "testnet") {
                headers = {
                    ...baseHeaders,
                    "Accept": "application/json, text/plain, */*",
                    "Origin": "https://testnet.konnex.world",
                    "Referer": "https://testnet.konnex.world/",
                    "Sec-Fetch-Site": "cross-site",
                };
            }

            this.HEADERS[email][headerType] = headers;
        }

        return { ...this.HEADERS[email][headerType] };
    }

    getSession(address, proxyUrl = null, referralCode = null) {
        if (!(address in this.sessions)) {
            const agent = this.buildProxyConfig(proxyUrl);
            const refCode = referralCode || "ferdie"; // 使用传入的邀请码或默认值

            const axiosConfig = {
                timeout: 60000,
                headers: {
                    'Cookie': `referral_code=${refCode}`
                }
            };

            if (agent) {
                axiosConfig.httpAgent = agent;
                axiosConfig.httpsAgent = agent;
            }

            this.sessions[address] = {
                session: axios.create(axiosConfig),
                proxy: proxyUrl,
                referralCode: refCode,
                cookies: {}
            };
        }

        return this.sessions[address];
    }

    generateAddress(account) {
        try {
            const wallet = new ethers.Wallet(account);
            return wallet.address;
        } catch (e) {
            return null;
        }
    }

    async generatePayload(account, address, csrfToken) {
        try {
            const issuedAt = new Date().toISOString();

            const rawMessage = JSON.stringify({
                domain: "hub.konnex.world",
                address: address,
                statement: "Sign in to the app. Powered by Snag Solutions.",
                uri: "https://hub.konnex.world",
                version: "1",
                chainId: 1,
                nonce: csrfToken,
                issuedAt: issuedAt
            });

            const message =
                "hub.konnex.world wants you to sign in with your Ethereum account:\n" +
                `${address}\n\n` +
                "Sign in to the app. Powered by Snag Solutions.\n\n" +
                "URI: https://hub.konnex.world\n" +
                "Version: 1\n" +
                "Chain ID: 1\n" +
                `Nonce: ${csrfToken}\n` +
                `Issued At: ${issuedAt}`;

            const wallet = new ethers.Wallet(account);
            const signature = await wallet.signMessage(message);

            const payload = {
                message: rawMessage,
                accessToken: signature,
                signature: signature,
                walletConnectorName: "MetaMask",
                walletAddress: address,
                redirect: "false",
                callbackUrl: "/protected",
                chainType: "evm",
                walletProvider: "undefined",
                csrfToken: csrfToken,
                json: "true"
            };

            return payload;
        } catch (e) {
            throw new Error(`Generate Req Payload Failed: ${e.message}`);
        }
    }

    maskAccount(account) {
        try {
            return account.slice(0, 6) + '*'.repeat(6) + account.slice(-6);
        } catch (e) {
            return null;
        }
    }



    async ensureOk(response) {
        if (response.status >= 400) {
            throw new Error(`HTTP ${response.status}: ${response.statusText}`);
        }
    }

    async checkConnection(address, proxyUrl = null, referralCode = null) {
        const url = "https://api.ipify.org?format=json";

        try {
            const sessionInfo = this.getSession(address, proxyUrl, referralCode);
            const session = sessionInfo.session;

            const response = await session.get(url);
            await this.ensureOk(response);
            return true;
        } catch (e) {
            this.log(
                chalk.cyan.bold('Status  :') +
                chalk.red.bold(' Connection Not 200 OK ') +
                chalk.magenta.bold('-') +
                chalk.yellow.bold(` ${e.message} `)
            );
        }

        return null;
    }

    async authCsrf(address, proxyUrl = null, referralCode = null, retries = 5) {
        const url = `${this.API_URL.hub}/api/auth/csrf`;
        const headers = this.initializeHeaders(address, "hub");
        headers["Content-Type"] = "application/json";

        for (let attempt = 0; attempt < retries; attempt++) {
            try {
                const sessionInfo = this.getSession(address, proxyUrl, referralCode);
                const session = sessionInfo.session;

                const response = await session.get(url, { headers });
                await this.ensureOk(response);
                return response.data;
            } catch (e) {
                if (attempt < retries - 1) {
                    await new Promise(resolve => setTimeout(resolve, 5000));
                    continue;
                }
                this.log(
                    chalk.cyan.bold('Status  :') +
                    chalk.red.bold(' Fetch Nonce Failed ') +
                    chalk.magenta.bold('-') +
                    chalk.yellow.bold(` ${e.message} `)
                );
            }
        }

        return null;
    }

    async authCredentials(account, address, csrfToken, proxyUrl = null, referralCode = null, retries = 5) {
        const url = `${this.API_URL.hub}/api/auth/callback/credentials`;
        const headers = this.initializeHeaders(address, "hub");
        headers["Content-Type"] = "application/x-www-form-urlencoded";
        const payload = await this.generatePayload(account, address, csrfToken);

        for (let attempt = 0; attempt < retries; attempt++) {
            try {
                const sessionInfo = this.getSession(address, proxyUrl, referralCode);
                const session = sessionInfo.session;

                const formData = new URLSearchParams(payload).toString();
                const response = await session.post(url, formData, {
                    headers,
                    maxRedirects: 0,
                    validateStatus: (status) => status < 500  // Accept redirects and success codes
                });

                // Check for session-token in response headers or cookies
                const setCookie = response.headers['set-cookie'];
                if (setCookie && setCookie.some(cookie => cookie.includes('session-token'))) {
                    return true;
                }

                // Also check if we got a redirect (which usually means success)
                if (response.status >= 300 && response.status < 400) {
                    return true;
                }

                // If we got here with a 200, it might still be success
                if (response.status === 200) {
                    return true;
                }
            } catch (e) {
                if (attempt < retries - 1) {
                    await new Promise(resolve => setTimeout(resolve, 5000));
                    continue;
                }
                this.log(
                    chalk.cyan.bold('Status  :') +
                    chalk.red.bold(' Login Failed ') +
                    chalk.magenta.bold('-') +
                    chalk.yellow.bold(` ${e.message} `)
                );
            }
        }

        return null;
    }

    async loyalityAccount(address, proxyUrl = null, referralCode = null, retries = 5) {
        const url = `${this.API_URL.hub}/api/loyalty/accounts`;
        const headers = this.initializeHeaders(address, "hub");
        const params = {
            websiteId: this.WEB_ID,
            organizationId: this.ORG_ID,
            walletAddress: address
        };

        for (let attempt = 0; attempt < retries; attempt++) {
            try {
                const sessionInfo = this.getSession(address, proxyUrl, referralCode);
                const session = sessionInfo.session;

                const response = await session.get(url, { headers, params });
                await this.ensureOk(response);
                return response.data;
            } catch (e) {
                if (attempt < retries - 1) {
                    await new Promise(resolve => setTimeout(resolve, 5000));
                    continue;
                }
                this.log(
                    chalk.cyan.bold('Balance :') +
                    chalk.red.bold(' Fetch Points Failed ') +
                    chalk.magenta.bold('-') +
                    chalk.yellow.bold(` ${e.message} `)
                );
            }
        }

        return null;
    }

    async completeCheckin(address, proxyUrl = null, referralCode = null, retries = 5) {
        const url = `${this.API_URL.hub}/api/loyalty/rules/${this.RULES_ID}/complete`;
        const headers = this.initializeHeaders(address, "hub");
        headers["Content-Type"] = "application/json";

        for (let attempt = 0; attempt < retries; attempt++) {
            try {
                const sessionInfo = this.getSession(address, proxyUrl, referralCode);
                const session = sessionInfo.session;

                const response = await session.post(url, {}, {
                    headers,
                    validateStatus: (status) => status < 500
                });

                if (response.status === 400) {
                    const errMsg = response.data.message || 'Unknown error';
                    this.log(
                        chalk.cyan.bold('Check-In:') +
                        chalk.yellow.bold(` ${errMsg} `)
                    );
                    return null;
                }

                await this.ensureOk(response);
                return response.data;
            } catch (e) {
                if (attempt < retries - 1) {
                    await new Promise(resolve => setTimeout(resolve, 5000));
                    continue;
                }
                this.log(
                    chalk.cyan.bold('Check-In:') +
                    chalk.red.bold(' Failed ') +
                    chalk.magenta.bold('-') +
                    chalk.yellow.bold(` ${e.message} `)
                );
            }
        }

        return null;
    }

    async listTasks(address, proxyUrl = null, referralCode = null, retries = 5) {
        const url = `${this.API_URL.testnet}/api/v1/list_tasks`;
        const headers = this.initializeHeaders(address, "testnet");

        for (let attempt = 0; attempt < retries; attempt++) {
            try {
                const sessionInfo = this.getSession(address, proxyUrl, referralCode);
                const session = sessionInfo.session;

                const response = await session.get(url, { headers });
                await this.ensureOk(response);
                return response.data;
            } catch (e) {
                if (attempt < retries - 1) {
                    await new Promise(resolve => setTimeout(resolve, 5000));
                    continue;
                }
                this.log(
                    chalk.blue.bold('   Task    :') +
                    chalk.red.bold(' Failed to Fetch Available Tasks ') +
                    chalk.magenta.bold('-') +
                    chalk.yellow.bold(` ${e.message} `)
                );
            }
        }

        return null;
    }

    async sendRequest(address, taskName, proxyUrl = null, referralCode = null, retries = 5) {
        const url = `${this.API_URL.testnet}/api/v1/send_request`;
        const headers = this.initializeHeaders(address, "testnet");
        headers["Content-Type"] = "application/json";
        const payload = {
            task: taskName
        };

        for (let attempt = 0; attempt < retries; attempt++) {
            try {
                const sessionInfo = this.getSession(address, proxyUrl, referralCode);
                const session = sessionInfo.session;

                const response = await session.post(url, payload, { headers });
                await this.ensureOk(response);
                return response.data;
            } catch (e) {
                if (attempt < retries - 1) {
                    await new Promise(resolve => setTimeout(resolve, 5000));
                    continue;
                }
                this.log(
                    chalk.blue.bold('   Submit  :') +
                    chalk.red.bold(' Failed to Send Request ') +
                    chalk.magenta.bold('-') +
                    chalk.yellow.bold(` ${e.message} `)
                );
            }
        }

        return null;
    }

    async requestStatus(address, requestId, proxyUrl = null, referralCode = null, retries = 5) {
        const url = `${this.API_URL.testnet}/api/v1/request_status`;
        const headers = this.initializeHeaders(address, "testnet");
        const params = {
            id: requestId
        };

        for (let attempt = 0; attempt < retries; attempt++) {
            try {
                const sessionInfo = this.getSession(address, proxyUrl, referralCode);
                const session = sessionInfo.session;

                const response = await session.get(url, { headers, params });
                await this.ensureOk(response);
                return response.data;
            } catch (e) {
                if (attempt < retries - 1) {
                    await new Promise(resolve => setTimeout(resolve, 5000));
                    continue;
                }
                this.log(
                    chalk.blue.bold('   Status  :') +
                    chalk.red.bold(' Failed to Fetch Request Status ') +
                    chalk.magenta.bold('-') +
                    chalk.yellow.bold(` ${e.message} `)
                );
            }
        }

        return null;
    }

    async requestFeedback(address, requestId, proxyUrl = null, referralCode = null, retries = 5) {
        const url = `${this.API_URL.testnet}/api/v1/request_feedback`;
        const headers = this.initializeHeaders(address, "testnet");
        headers["Content-Type"] = "application/json";
        const params = {
            request_id: requestId
        };
        const payload = {
            score: 8,
            wallet: address
        };

        for (let attempt = 0; attempt < retries; attempt++) {
            try {
                const sessionInfo = this.getSession(address, proxyUrl, referralCode);
                const session = sessionInfo.session;

                const response = await session.post(url, payload, { headers, params });
                await this.ensureOk(response);
                return response.data;
            } catch (e) {
                if (attempt < retries - 1) {
                    await new Promise(resolve => setTimeout(resolve, 5000));
                    continue;
                }
                this.log(
                    chalk.blue.bold('   Feedback:') +
                    chalk.red.bold(' Failed to Save Feedback ') +
                    chalk.magenta.bold('-') +
                    chalk.yellow.bold(` ${e.message} `)
                );
            }
        }

        return null;
    }

    async processCheckConnection(address, proxyUrl, referralCode) {
        this.log(
            chalk.cyan.bold('Proxy   :') +
            chalk.white.bold(` ${this.displayProxy(proxyUrl)} `)
        );
        this.log(
            chalk.cyan.bold('Referral:') +
            chalk.white.bold(` ${referralCode} `)
        );

        const isValid = await this.checkConnection(address, proxyUrl, referralCode);
        return isValid ? true : false;
    }

    async processUserLogin(account, address, proxyUrl = null, referralCode = null) {
        const isValid = await this.processCheckConnection(address, proxyUrl, referralCode);
        if (!isValid) return false;

        const authCsrf = await this.authCsrf(address, proxyUrl, referralCode);
        if (!authCsrf) return false;

        const csrfToken = authCsrf.csrfToken;

        const credentials = await this.authCredentials(account, address, csrfToken, proxyUrl, referralCode);
        if (!credentials) return false;

        this.log(
            chalk.cyan.bold('Status  :') +
            chalk.green.bold(' Login Success ')
        );

        return true;
    }

    async registerWithReferral(account, address, proxyUrl = null, referralCode = null) {
        this.log(
            chalk.yellow.bold('正在注册账户...')
        );
        this.log(
            chalk.cyan.bold('Referral:') +
            chalk.white.bold(` ${referralCode} `)
        );

        try {
            // 检查连接
            const isValid = await this.checkConnection(address, proxyUrl, referralCode);
            if (!isValid) {
                this.log(chalk.red.bold('❌ 连接失败'));
                return false;
            }

            this.log(chalk.green.bold('✓ 连接成功'));

            // 获取 CSRF 令牌
            const authCsrf = await this.authCsrf(address, proxyUrl, referralCode);
            if (!authCsrf) {
                this.log(chalk.red.bold('❌ 获取 CSRF 令牌失败'));
                return false;
            }

            this.log(chalk.green.bold('✓ CSRF 令牌获取成功'));

            const csrfToken = authCsrf.csrfToken;

            // 登录/注册
            const credentials = await this.authCredentials(account, address, csrfToken, proxyUrl, referralCode);
            if (!credentials) {
                this.log(chalk.red.bold('❌ 注册失败 - 认证失败'));
                return false;
            }

            this.log(chalk.green.bold('✅ 注册成功!'));

            // 获取账户信息
            const loyality = await this.loyalityAccount(address, proxyUrl, referralCode);
            if (loyality) {
                const loyalityData = loyality.data || [];
                const amount = loyalityData.length > 0 ? loyalityData[0].amount || 0 : 0;

                this.log(
                    chalk.cyan.bold('Balance :') +
                    chalk.white.bold(` ${amount} Points `)
                );
            }

            return true;
        } catch (e) {
            this.log(
                chalk.red.bold('❌ 注册失败 - ') +
                chalk.yellow.bold(e.message)
            );
            return false;
        }
    }

    async processAccounts(account, address, proxyUrl = null, referralCode = null) {

        this.log(chalk.yellow.bold('正在登录...'));

        const logined = await this.processUserLogin(account, address, proxyUrl, referralCode);
        if (!logined) {
            this.log(chalk.red.bold('❌ 登录失败'));
            return false;
        }

        this.log(chalk.green.bold('✅ 登录成功'));

        const loyality = await this.loyalityAccount(address, proxyUrl, referralCode);
        if (loyality) {
            const loyalityData = loyality.data || [];
            const amount = loyalityData.length > 0 ? loyalityData[0].amount || 0 : 0;

            this.log(
                chalk.cyan.bold('Balance :') +
                chalk.white.bold(` ${amount} Points `)
            );
        }

        this.log(chalk.yellow.bold('正在签到...'));

        const checkin = await this.completeCheckin(address, proxyUrl, referralCode);
        if (checkin) {
            this.log(chalk.green.bold('✅ 签到成功'));
        } else {
            this.log(chalk.yellow.bold('⚠️  签到失败或已签到'));
        }
        if (checkin) {
            this.log(
                chalk.cyan.bold('Check-In:') +
                chalk.green.bold(' Success ')
            );
        }

        this.log(chalk.cyan.bold('Testnet :'));

        const tasks = await this.listTasks(address, referralCode);
        if (tasks) {
            const task = tasks[Math.floor(Math.random() * tasks.length)];
            const taskName = task.name;
            const description = task.description;

            this.log(
                chalk.blue.bold('   Task    :') +
                chalk.white.bold(` ${description} `)
            );

            const sendReq = await this.sendRequest(address, taskName, proxyUrl, referralCode);
            if (sendReq) {
                const requestId = sendReq.id;

                this.log(
                    chalk.blue.bold('   Submit  :') +
                    chalk.green.bold(' Success ')
                );
                this.log(
                    chalk.blue.bold('   Task Id :') +
                    chalk.white.bold(` ${requestId} `)
                );

                let isDone = false;

                for (let i = 0; i < 10; i++) {
                    await new Promise(resolve => setTimeout(resolve, 3000));

                    const reqStatus = await this.requestStatus(address, requestId, proxyUrl, referralCode);
                    if (!reqStatus) continue;

                    const status = reqStatus.status;
                    if (status === "done") {
                        isDone = true;
                        this.log(
                            chalk.blue.bold('   Status  :') +
                            chalk.green.bold(' Done ')
                        );
                        break;
                    }

                    this.log(
                        chalk.blue.bold('   Status  :') +
                        chalk.yellow.bold(` ${status} (${i + 1}/10) `)
                    );
                }

                if (isDone) {
                    const feedback = await this.requestFeedback(address, requestId, proxyUrl, referralCode);
                    if (feedback) {
                        const message = feedback.message;
                        const feedbackId = feedback.id;

                        this.log(
                            chalk.blue.bold('   Feedback:') +
                            chalk.green.bold(` ${message} `) +
                            chalk.magenta.bold('-') +
                            chalk.blue.bold(' Id: ') +
                            chalk.white.bold(feedbackId)
                        );
                    }
                } else {
                    this.log(
                        chalk.blue.bold('   Status  :') +
                        chalk.yellow.bold(' Cannot Save Feedback ')
                    );
                }
            }
        }
    }

    async main() {
        try {
            // 自动加载代理文件和邀请码文件
            this.loadProxies();
            this.loadReferralCodes();

            // 显示欢迎界面和菜单
            this.clearTerminal();
            this.welcome();

            // 检查是否有待注册账户和正常账户
            const referralAccounts = this.loadReferralAccounts();
            const accounts = this.loadAccounts();

            // 显示菜单选项
            console.log(chalk.cyan.bold('\n请选择运行模式:\n'));
            console.log(chalk.yellow.bold('  1. ') + chalk.white('邀请码注册模式') + chalk.gray(` (待注册账户: ${referralAccounts.length})`));
            console.log(chalk.yellow.bold('  2. ') + chalk.white('正常签到模式') + chalk.gray(` (账户数: ${accounts ? accounts.length : 0})`));
            console.log(chalk.yellow.bold('  3. ') + chalk.white('两者都执行 (先注册后签到)'));
            console.log(chalk.yellow.bold('  0. ') + chalk.white('退出\n'));

            const choice = readlineSync.question(chalk.green.bold('请输入选项 (0-3): '));

            if (choice === '0') {
                this.log(chalk.yellow.bold('\n[ 退出 ] Konnex - BOT'));
                return;
            }

            // 执行邀请码注册
            if (choice === '1' || choice === '3') {
                if (referralAccounts.length === 0) {
                    this.log(chalk.red.bold('\n❌ referral_accounts.txt 中没有待注册账户!'));
                    if (choice === '1') return;
                } else {
                    await this.runReferralRegistration(referralAccounts);
                    if (choice === '1') {
                        this.log(chalk.yellow.bold('\n[ 完成 ] Konnex - BOT'));
                        return;
                    }
                    // 如果是选项3,继续执行签到
                    await new Promise(resolve => setTimeout(resolve, 3000));
                }
            }

            // 执行正常签到
            if (choice === '2' || choice === '3') {
                if (!accounts || accounts.length === 0) {
                    this.log(chalk.red.bold('\n❌ accounts.txt 中没有账户!'));
                    return;
                }
                await this.runNormalCheckIn(accounts);
            }

            if (choice !== '1' && choice !== '2' && choice !== '3') {
                this.log(chalk.red.bold('\n❌ 无效的选项!'));
            }

        } catch (e) {
            this.log(
                chalk.red.bold('[ ERROR ] ') +
                chalk.yellow.bold(e.message)
            );
        }
    }

    async runReferralRegistration(referralAccounts) {
        this.clearTerminal();
        this.welcome();
        this.log(
            chalk.magenta.bold("=== 邀请码注册模式 ===")
        );
        this.log(
            chalk.green.bold("待注册账户数: ") +
            chalk.white.bold(referralAccounts.length)
        );

        for (let i = 0; i < referralAccounts.length; i++) {
            const account = referralAccounts[i];
            const address = this.generateAddress(account);
            const proxyUrl = this.getProxyForAccount(i);
            const referralCode = this.getReferralCodeForAccount(i);

            this.log(
                chalk.cyan.bold('\n[ ') +
                chalk.white.bold(`账户 ${i + 1}`) +
                chalk.cyan.bold(' ]')
            );

            if (!address) {
                this.log(
                    chalk.cyan.bold('Status  :') +
                    chalk.red.bold(' 无效的私钥或库版本不支持 ')
                );
                continue;
            }

            this.log(
                chalk.cyan.bold('Proxy   :') +
                chalk.white.bold(` ${this.displayProxy(proxyUrl)} `)
            );

            await this.registerWithReferral(account, address, proxyUrl, referralCode);
            await new Promise(resolve => setTimeout(resolve, 2000 + Math.random() * 1000));
        }

        this.log(chalk.cyan.bold('='.repeat(72)));
        this.log(
            chalk.green.bold('✅ 邀请码注册完成! ') +
            chalk.white.bold('成功注册的账户可以移动到 accounts.txt 进行日常使用。')
        );
        this.log(chalk.cyan.bold('='.repeat(72)));
    }

    async runNormalCheckIn(accounts) {
        if (!accounts) return;

        while (true) {
            this.clearTerminal();
            this.welcome();
            this.log(
                chalk.green.bold("账户总数: ") +
                chalk.white.bold(accounts.length)
            );

            for (let i = 0; i < accounts.length; i++) {
                const account = accounts[i];
                const address = this.generateAddress(account);
                const proxyUrl = this.getProxyForAccount(i);
                const referralCode = this.getReferralCodeForAccount(i);

                this.log(
                    chalk.cyan.bold('\n[ ') +
                    chalk.white.bold(`账户 ${i + 1}`) +
                    chalk.cyan.bold(' ]')
                );

                if (!address) {
                    this.log(
                        chalk.cyan.bold('Status  :') +
                        chalk.red.bold(' 无效的私钥或库版本不支持 ')
                    );
                    continue;
                }

                await this.processAccounts(account, address, proxyUrl, referralCode);
                await new Promise(resolve => setTimeout(resolve, 2000 + Math.random() * 1000));
            }

            this.log(chalk.cyan.bold('='.repeat(72)));

            let delay = 24 * 60 * 60;
            while (delay > 0) {
                const formattedTime = this.formatSeconds(delay);
                process.stdout.write(
                    chalk.cyan.bold('[ Wait for') +
                    chalk.white.bold(` ${formattedTime} `) +
                    chalk.cyan.bold('... ]') +
                    chalk.white.bold(' | ') +
                    chalk.blue.bold('All Accounts Have Been Processed...') +
                    '\r'
                );
                await new Promise(resolve => setTimeout(resolve, 1000));
                delay -= 1;
            }
        }
    }
}

if (require.main === module) {
    const bot = new Konnex();

    process.on('SIGINT', () => {
        const now = new Date();
        const wibTime = now.toLocaleString('en-US', {
            timeZone: 'Asia/Jakarta',
            year: 'numeric',
            month: '2-digit',
            day: '2-digit',
            hour: '2-digit',
            minute: '2-digit',
            second: '2-digit',
            hour12: false
        });
        console.log(
            `\n${chalk.cyan.bold(`[ ${wibTime} WIB ]`)} ${chalk.white.bold('|')} ${chalk.red.bold('[ EXIT ] Konnex - BOT')}                                       `
        );
        process.exit(0);
    });

    bot.main().catch(err => {
        console.error(chalk.red.bold(`Fatal Error: ${err.message}`));
        process.exit(1);
    });
}

module.exports = Konnex;

