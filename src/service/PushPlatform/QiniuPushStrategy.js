import {IPushStrategy} from './IPushStrategy.js';
import {httpGet, httpMethod, httpPost} from "@/utils/http";
import * as x509 from '@peculiar/x509'

const crypto = preload.crypto
const url = preload.url

// 七牛云 API 基础配置
const QINIU_CONFIG = {
    BASE_URL: 'https://api.qiniu.com',
    ENDPOINTS: {
        SSL_CERT: '/sslcert',
        DOMAIN: '/domain',
    }
}

export class QiniuPushStrategy extends IPushStrategy {
    constructor() {
        super();
    }

    // 工具方法
    base64ToUrlSafe(v) {
        return v.replace(/\//g, '_').replace(/\+/g, '-');
    }

    hmacSha1(encodedFlags, secretKey) {
        const hmac = crypto.createHmac('sha1', secretKey);
        hmac.update(encodedFlags);
        return hmac.digest('base64');
    }

    // 认证相关方法
    generateAccessToken(mac, requestURI, reqBody = null) {
        const u = new url.URL(requestURI);
        const path = u.pathname + u.search;
        let access = path + '\n';
        if (reqBody) {
            access += reqBody;
        }
        const digest = this.hmacSha1(access, mac.secretKey);
        const safeDigest = this.base64ToUrlSafe(digest);
        return 'QBox ' + mac.accessKey + ':' + safeDigest;
    }

    // 获取通用请求头
    getCommonHeaders(config, requestURI, contentType = 'application/json') {
        const mac = {
            accessKey: config.accessKey,
            secretKey: config.secretKey
        };
        const accessToken = this.generateAccessToken(mac, requestURI);
        return {
            'Content-Type': contentType,
            'Authorization': accessToken
        };
    }

    // API 请求方法
    async makeRequest(config, endpoint, method = 'GET', payload = null) {
        const requestURI = `${QINIU_CONFIG.BASE_URL}${endpoint}`;
        const headers = this.getCommonHeaders(config, requestURI);
        
        try {
            switch (method.toUpperCase()) {
                case 'GET':
                    return await httpGet(requestURI, headers);
                case 'POST':
                    return await httpPost(requestURI, payload, headers);
                case 'PUT':
                    return await httpMethod('PUT', requestURI, headers, payload);
                default:
                    throw new Error(`不支持的请求方法: ${method}`);
            }
        } catch (error) {
            throw new Error(`请求失败: ${error.message}`);
        }
    }

    // 证书解析
    parseCertificate(cert, key) {
        const certInfo = new x509.X509Certificate(cert);
        return {
            name: certInfo.subject,
            common_name: certInfo.subject,
            pri: key,
            ca: cert
        }
    }

    // 业务方法
    async validate(config) {
        if (!config.accessKey || !config.secretKey) {
            throw new Error('请填写完整的七牛云配置信息');
        }
        const {error, error_code} = await this.getSSLList(config);
        if (error_code) {
            throw new Error(`七牛云验证失败: ${error}`);
        }
        return true;
    }

    async getSSLList(config) {
        return await this.makeRequest(config, QINIU_CONFIG.ENDPOINTS.SSL_CERT);
    }

    async pushSSL(config, certData) {
        const payload = this.parseCertificate(certData.cert, certData.key);
        return await this.makeRequest(config, QINIU_CONFIG.ENDPOINTS.SSL_CERT, 'POST', payload);
    }

    async getDomainInfo(config, domain) {
        return await this.makeRequest(config, `${QINIU_CONFIG.ENDPOINTS.DOMAIN}/${domain}`);
    }

    async changeDomainHttps(config, domain, certID, http2Enable, forceHttps) {
        const endpoint = `${QINIU_CONFIG.ENDPOINTS.DOMAIN}/${domain}/httpsconf`;
        const payload = { certID, http2Enable, forceHttps };
        return await this.makeRequest(config, endpoint, 'PUT', payload);
    }

    async openDomainHttps(config, domain, certID) {
        const endpoint = `${QINIU_CONFIG.ENDPOINTS.DOMAIN}/${domain}/sslize`;
        const payload = {
            certID,
            http2Enable: true,
            forceHttps: true,
        };
        return await this.makeRequest(config, endpoint, 'PUT', payload);
    }

    async push(config, certData, oncall = null) {
        try {
            // 推送证书
            oncall?.('beforePush', {msg: "开始推送证书"});
            const res = await this.pushSSL(config, certData);
            if (res.code !== 200) {
                throw new Error(`推送失败: ${res.error}`);
            }
            oncall?.('afterPush', {msg: "证书文件推送成功 🎉"});

            // 处理 CDN 绑定
            let bindMsg = '';
            if (config.cdnDomain) {
                bindMsg = await this.handleCdnBinding(config, res.certID, oncall);
            }

            oncall?.('success', {msg: `推送成功 证书ID: ${res.certID}`});
            return {
                msg: `推送成功 证书ID: <span style="color: #1890ff;font-weight: bold;">${res.certID}</span>` +
                     (bindMsg ? `<br><br>${bindMsg}` : ''),
                extData: res
            };
        } catch (error) {
            oncall?.('error', { msg: error.toString() });
            console.error('QiniuPushStrategy push error:', error);
            throw new Error(`推送失败: ${error.message}`);
        }
    }

    // CDN 绑定处理
    async handleCdnBinding(config, certID, oncall) {
        try {
            const {https, error} = await this.getDomainInfo(config, config.cdnDomain);
            if (error) {
                throw new Error(`获取域名信息失败: ${error}`);
            }

            if (https.certId) {
                const {error: changeError} = await this.changeDomainHttps(
                    config, 
                    config.cdnDomain, 
                    certID, 
                    https.http2Enable, 
                    https.forceHttps
                );
                if (changeError) throw new Error(`更换证书失败: ${changeError}`);
            } else {
                const {error: openError} = await this.openDomainHttps(config, config.cdnDomain, certID);
                if (openError) throw new Error(`开启https失败: ${openError}`);
            }

            const successMsg = `证书成功绑定到CDN域名 <span style="color: #52c41a;font-weight: 500;">${config.cdnDomain}</span> 🎉🎉`;
            oncall?.('bindCdn', { msg: successMsg });
            return successMsg;
        } catch (e) {
            const errorMsg = `绑定CDN失败: ${e.message} <br> 请登录七牛云控制台手动绑定`;
            oncall?.('bindCdn', { msg: errorMsg });
            return errorMsg;
        }
    }
} 
