import TencentDnsService from "./TencentDnsService.js";
import CloudflareDnsService from "./CloudFlareDnsService";
import AliDnsService from "./AliDnsService";
import HuaweiDnsService from "./HuaweiDnsService";
import AwsDnsService from "@/service/AwsDnsService";
import VolcengineDnsService from "@/service/VolcengineDnsService";
import SpaceshipDnsService from "@/service/SpaceshipDnsService";
import WestDnsService from "@/service/WestDnsService";
import UcloudDnsService from "@/service/UcloudDnsService";

const DNS_MAP_SERVICE = {}

const DNS_PROVIDER = {
    "tencent": TencentDnsService,
    "cloudflare": CloudflareDnsService,
    "ali": AliDnsService,
    'huawei': HuaweiDnsService,
    'aws': AwsDnsService,
    'volcengine': VolcengineDnsService,
    "spaceship": SpaceshipDnsService,
    "west": WestDnsService,
    "ucloud": UcloudDnsService,
}


function validateDNSRecord(type, value) {
    /**
     * 验证DNS记录是否合法
     * @param {string} type - DNS记录类型 ('A', 'AAAA', 'TXT', 'NS', 'CNAME')
     * @param {string} value - DNS记录的值
     * @throws {Error} - 如果记录不合法，抛出异常并说明原因
     */

    if (type === "A") {
        // 验证IPv4地址
        if (!isValidIPv4(value)) {
            throw new Error(`Invalid A record: '${value}' is not a valid IPv4 address.`);
        }
    } else if (type === "AAAA") {
        // 验证IPv6地址
        if (!isValidIPv6(value)) {
            throw new Error(`Invalid AAAA record: '${value}' is not a valid IPv6 address.`);
        }
    } else if (type === "TXT") {
        // 验证TXT记录 (通常为任意字符串，假设长度不超过1024个字符)
        if (typeof value !== "string" || value.length > 1024) {
            throw new Error(`Invalid TXT record: '${value}' must be a string of at most 1024 characters.`);
        }
    } else if (type === "NS" || type === "CNAME") {
        // 验证NS和CNAME记录 (通常为有效的域名)
        if (!isValidHostname(value)) {
            throw new Error(`Invalid ${type} record: '${value}' is not a valid hostname.`);
        }
    } else if (type === "MX") {
        // 验证MX记录 (通常为有效的域名)
        if (!isValidHostname(value)) {
            throw new Error(`Invalid MX record: '${value}' is not a valid hostname.`);
        }
    } else {
        // 不支持的类型
        throw new Error(`Unsupported DNS record type: '${type}'. Supported types are A, AAAA, TXT, NS, CNAME.`);
    }
}

function isValidIPv4(ip) {
    /**
     * 验证IPv4地址是否合法
     * @param {string} ip - IPv4地址
     * @returns {boolean}
     */
    const ipv4Regex = /^(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])(\.(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])){3}$/;
    return ipv4Regex.test(ip);
}

function isValidIPv6(ip) {
    /**
     * 验证IPv6地址是否合法
     * @param {string} ip - IPv6地址
     * @returns {boolean}
     */
    const ipv6Regex = /^(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))$/;
    return ipv6Regex.test(ip);
}

function isValidHostname(hostname) {
    // /**
    //  * 验证域名是否合法
    //  * @param {string} hostname - 要验证的域名
    //  * @returns {boolean}
    //  */
    // if (hostname.length > 255) return false;
    // if (hostname.endsWith(".")) {
    //     hostname = hostname.slice(0, -1); // 移除末尾的点
    // }
    // const hostnameRegex = /^(?!-)[A-Za-z0-9-]{1,63}(?<!-)$/;
    // return hostname.split(".").every((part) => hostnameRegex.test(part));
    return true;
}


export function getDnsService(key, provider, credentials, refresh = false) {
    if (refresh) {
        if (DNS_MAP_SERVICE[key]) {
            DNS_MAP_SERVICE[key].xDestroy()
        }
        DNS_MAP_SERVICE[key] = null;
    }
    if (!DNS_MAP_SERVICE[key]) {
        DNS_MAP_SERVICE[key] = new DnsService(provider, credentials);
    }
    return DNS_MAP_SERVICE[key];
}

class DnsService {
    constructor(provider, credentials) {
        const params = credentials.map(item => item.value);
        this.provider = new DNS_PROVIDER[provider](...params);
    }

    async listDomains() {
        return this.provider.listDomains();
    }

    async listRecords(domain) {
        let {count, list} = await this.provider.listRecords(domain);
        list = list.map(r => {
            r.Domain = domain;
            return r
        }).sort((a, b) => {
            if (a.Type < b.Type) {
                return -1;
            } else if (a.Type > b.Type) {
                return 1;
            } else {
                // If Type is the same, then sort by Name
                if (a.Name < b.Name) {
                    return -1;
                } else if (a.Name > b.Name) {
                    return 1;
                } else {
                    return 0;
                }
            }
        })
        return {
            count,
            list
        }
    }

    async checkDomain(domain) {
        // 如果provider 有方法
        if (typeof this.provider.checkDomain === "function") {
            return this.provider.checkDomain(domain);
        }
        //
        const domains = await this.listDomains();
        if (domains.length === 0) {
            throw new Error('未找到任何有效域名');
        }
        if (domains.some(zone => zone.domain === domain)) {
            return {
                zone_id: domains.find(zone => zone.domain === domain).zone_id,
            };
        }
        throw new Error('域名不在列表中');
    }

    async addRecord(domain, record) {
        if (typeof this.provider.validateDNSRecord === 'function') {
            this.provider.validateDNSRecord(record.Type, record.Value);
        } else {
            validateDNSRecord(record.type, record.value);
        }
        return this.provider.addRecord(domain, record);
    }

    async updateRecord(domain, record) {
        if (typeof this.provider.validateDNSRecord === 'function') {
            this.provider.validateDNSRecord(record.type, record.value);
        } else {
            validateDNSRecord(record.type, record.value);
        }
        // 原始类有这个方法 则调用 ，没有则先删除再添加
        if (typeof this.provider.updateRecord === 'function') {
            return this.provider.updateRecord(domain, record);
        } else {
            await this.deleteRecord(domain, record.id);
            return this.addRecord(domain, record);
        }

    }

    async deleteRecord(domain, recordId, record) {
        // 传了record 又传了recordId 这就是屎山代码的由来，见识短了 以为所有平台都有id
        return this.provider.deleteRecord(domain, recordId, record);
    }

    async xDestroy() {
        if (typeof this.provider.xDestroy === 'function') {
            this.provider.xDestroy();
        }
    }

    // 删除所有 _acme-challenge 记录
    async deleteAcmeRecord(domain, acmeDomain) {
        const target = `_acme-challenge.${acmeDomain}`.replace(`.${domain}`, "")
        // 列出所有域名
        return this.listRecords(domain).then(res => {
            // 找到所有 _acme-challenge 记录
            const acmeRecords = res.list.filter(item => item.Name === target);
            // 删除所有 _acme-challenge 记录
            return Promise.all(acmeRecords.map(item => this.deleteRecord(domain, item.RecordId)));
        });
    }

    async changeRecordStatus(domain, recordId, extra = {}) {
        if (typeof this.provider.changeRecordStatus === 'function') {
            return this.provider.changeRecordStatus(domain, recordId, extra);
        }
    }

    // 获取线路列表（仅腾讯云支持）
    async getRecordLineList(domain) {
        if (typeof this.provider.getRecordLineList === 'function') {
            return this.provider.getRecordLineList(domain);
        }
        // 其他云服务商返回默认线路
        return {
            count: 1,
            list: [{
                name: '默认',
                id: '0',
                category: '基础线路'
            }]
        };
    }

    // 按分类获取线路列表（仅腾讯云支持）
    async getRecordLineCategoryList(domain) {
        if (typeof this.provider.getRecordLineCategoryList === 'function') {
            return this.provider.getRecordLineCategoryList(domain);
        }
        // 其他云服务商返回默认线路
        return {
            count: 1,
            list: [{
                name: '默认',
                id: '0',
                useful: true,
                grade: 'DP_Free',
                subLines: []
            }]
        };
    }
}