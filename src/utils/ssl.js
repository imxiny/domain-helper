const acme = preload.acme
import * as x509 from '@peculiar/x509'


if (utools.isDev()) {
    acme.setLogger((message) => {
        console.log(message);
    });
}
class AcmeClient {
    constructor() {
        this.client = null;
        this.accountKey = null;
        this.accountUrl = null;
        this.email = null;
        this.ca = null
        this.aborted = false;
    }

    abort() {
        this.aborted = true;
    }

    async init(email, accountKey, accountUrl, ca, ext) {
        this.email = email;
        this.ca = ca;
        if (ext?.proxy) {
            let host = null;
            let port = null;
            let protocol = 'http';
            try {
                const proxyUrl = ext.proxy.includes('://') ? ext.proxy : `http://${ext.proxy}`;
                const parsed = new URL(proxyUrl);
                host = parsed.hostname;
                port = parsed.port ? Number(parsed.port) : 80;
                protocol = parsed.protocol.replace(':', '') || 'http';
            } catch (e) {
                const [rawHost, rawPort] = ext.proxy.split(":");
                host = rawHost;
                port = Number(rawPort);
            }
            acme.axios.defaults.proxy = {
                host,
                port,
                protocol
            };
        } else {
            acme.axios.defaults.proxy = false;
        }
        try {

            if (!accountKey) {
                accountKey = await acme.crypto.createPrivateKey();
            }

            this.accountKey = accountKey;

            let options = {
                directoryUrl: acme.directory[ca].production,
                accountKey: this.accountKey,
            }
            if (ext?.kid && ext?.hmacKey) {
                options.externalAccountBinding = {
                    kid: ext.kid,
                    hmacKey: ext.hmacKey
                }
            }
            if (accountUrl) {
                options.accountUrl = accountUrl;
            }

            this.client = new acme.Client(options);

            if (!accountUrl) {
                await this.client.createAccount({
                    termsOfServiceAgreed: true,
                    contact: [`mailto:${email}`],
                });
            }
            // 返回账户信息
            this.accountUrl = this.client.getAccountUrl();
            return {
                accountKey: this.accountKey.toString(),
                accountUrl: this.accountUrl
            }
        } catch (error) {
            console.error('AcmeClient init error:', error);
            throw error;
        }
    }

    async getOrderStatus(order) {
        console.log("order", order)
        try {
            // 确保客户端已初始化
            if (!this.client) {
                throw new Error('ACME client not initialized');
            }

            // 使用订单URL获取状态
            return await this.client.getOrder({url: order.url});
        } catch (error) {
            console.error('AcmeClient getOrderStatus error:', error);
            if (error.message.includes('Replay Nonce')) {
                // 如果是 nonce 错误，可能需要重新初始化客户端
                throw new Error('订单状态已过期，请重新申请证书');
            }
            throw error;
        }
    }

    // 初始化订单
    async initOrder(domains) {
        try {
            const order = await this.createOrder(this.email, domains, () => {
            }, () => {
            });
            const authorizations = await this.client.getAuthorizations(order);

            const challenges = [];
            for (const authz of authorizations) {
                const challenge = authz.challenges.find(c => c.type === 'dns-01');
                if (!challenge) {
                    throw new Error('DNS-01 challenge not found');
                }
                const keyAuthorization = await this.client.getChallengeKeyAuthorization(challenge);
                challenges.push({
                    authz,
                    challenge,
                    keyAuthorization,
                    domain: authz.identifier.value,
                    status: 'pending'
                });
            }
            // 获取账户URL
            return {
                order,
                authorizations,
                challenges,
                accountKey: this.accountKey.toString(), // 返回accountKey
                accountUrl: this.accountUrl,
                ca: this.ca
            };
        } catch (error) {
            throw error;
        }
    }

    // 验证单个域名的ACME挑战
    async verifyDomainChallenge(authz, challenge, email, waitTime = 0) {
        try {
            // 添加延时等待DNS记录传播
            if (waitTime > 0) {
                await new Promise(resolve => setTimeout(resolve, waitTime * 1000));
            }
            await this.client.verifyChallenge(authz, challenge);
            await this.client.completeChallenge(challenge);
            await this.client.waitForValidStatus(challenge);
            return true;
        } catch (e) {
            throw e
        }
    }


    async verifyDomainByOrder(order, waitTime = 0) {
        // 检查是否需要验证域名
        const authorizations = await this.client.getAuthorizations(order);
        // 添加延时等待DNS记录传播
        if (waitTime > 0) {
            await new Promise(resolve => setTimeout(resolve, waitTime * 1000));
        }
        for (const auth of authorizations) {
            if (auth.status === 'pending') {
                // 如果需要验证，则完成域名验证
                const challenge = auth.challenges.find(c => c.type === 'dns-01');
                await this.client.verifyChallenge(auth, challenge);
                await this.client.completeChallenge(challenge);
            }
        }
        await this.client.waitForValidStatus(order);
    }


    // 最终签发证书
    async finalizeCertificate(order, domains, keyType, reNew = null) {
        try {
            return await this.finalizeOrder(order, domains, () => {
            }, () => {
            }, keyType, reNew);
        } catch (e) {
            throw e;
        }
    }

    async createOrder(email, domains, onStage, onError) {
        try {
            // 确保 domains 是数组
            const domainArray = Array.isArray(domains) ? domains : [domains];

            onStage('createOrder');
            return await this.client.createOrder({
                identifiers: domainArray.map(domain => ({
                    type: 'dns',
                    value: domain
                }))
            });
        } catch (error) {
            onError('createOrder', error);
            throw error;
        }
    }

    async getPK(type) {
        switch (type) {
            case "ECC-256":
                return await acme.crypto.createPrivateEcdsaKey("P-256");
            case "ECC-384":
                return await acme.crypto.createPrivateEcdsaKey("P-384");
            case "RSA-2048":
                return await acme.crypto.createPrivateRsaKey(2048);
            case "RSA-3072":
                return await acme.crypto.createPrivateRsaKey(3072);
            case "RSA-4096":
                return await acme.crypto.createPrivateRsaKey(4096);
            case "ECC-521":
                return await acme.crypto.createPrivateEcdsaKey("P-521");
            default:
                throw new Error(`Unsupported key type: ${type}`);
        }
    }

    async finalizeOrder(order, domain, onStage, onError, keyType = "ECC-256", reNew = null) {
        try {
            onStage('createCsr');
            const {key, csr} = await this.createCsrAndKey(domain, keyType, reNew);
            onStage('finalizeOrder');
            const finalized = await this.client.finalizeOrder(order, csr);

            onStage('getCertificate');
            const cert = await this.client.getCertificate(finalized);

            return this.parseCertificate(cert, csr, key);
        } catch (error) {
            onError('finalizeOrder', error);
            throw error;
        }
    }

    async createCsrAndKey(domains, keyType, reNew) {
        if (reNew) {
            return {key: reNew.key, csr: reNew.csr};
        } else {
            // 确保 domains 是数组
            const domainArray = Array.isArray(domains) ? domains : [domains];
            const [key, csr] = await acme.crypto.createCsr({
                altNames: domainArray,
            }, await this.getPK(keyType));
            return {key: key.toString(), csr: csr.toString()};
        }
    }

    // parseCertificate(cert, csr, key) {
    //
    //     const parsedCert = forge.pki.certificateFromPem(cert);
    //     const issuer = parsedCert.issuer.attributes.filter(item => item.shortName === "O").map(attr => `${attr.value}`).join('');
    //     const validFrom = parsedCert.validity.notBefore;
    //     const validTo = parsedCert.validity.notAfter;
    //
    //     return {
    //         csr: csr, key: key, cert: cert.toString(),
    //         issuer, validFrom, validTo
    //     };
    // }

    parseCertificate(cert, csr, key) {
        const certInfo = new x509.X509Certificate(cert);
        const issuer = certInfo.issuer
        const validFrom = certInfo.notBefore
        const validTo = certInfo.notAfter
        return {
            csr: csr,
            key: key,
            cert: cert.toString(),
            issuer,
            validFrom,
            validTo
        };
    }
}

export default AcmeClient;
