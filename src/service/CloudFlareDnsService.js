import {httpsRequest} from '@/utils/http';
import {containsAnySubstring, getDnsServer, getDomain} from "@/utils/tool";


// 文档地址 https://developers.cloudflare.com/api/operations/dns-records-for-a-zone-create-dns-record
class CloudflareDnsService {
    constructor(email, apiKey, apiToken) {
        this.apiKey = apiKey;
        this.apiToken = apiToken;
        this.email = email;
        this.apiBase = 'api.cloudflare.com';
        this.dnsServer = ['cloudflare']
    }

    async listDomains() {
        const response = await this.cfRest('GET', '/client/v4/zones');
        if (!response.success) {
            throw new Error(`获取区域时出错: ${response.errors[0].message}`);
        }
        let zones = await Promise.all(response.result.map(async item => {
            if (item.status !== "active") {
                return null;
            }
            try {
                const {nsname} = await getDnsServer(item.name);
                return containsAnySubstring(this.dnsServer, nsname) ? item : null;
            } catch (e) {
                return item;
            }
        }));
        zones = zones.filter(zone => zone !== null);
        return zones.map(zone => {
            return {
                zone_id: zone.id,
                domain: zone.name,
                cloud: "cloudflare",
            }
        })
    }

    async checkDomain(domain) {
        return new Promise((resolve, reject) => {
            this.listDomains().then(zones => {
                if (zones.length === 0) {
                    reject(new Error('未找到任何区域'));
                }
                if (zones.some(zone => zone.domain === domain)) {
                    resolve({
                        zone_id: zones.find(zone => zone.domain === domain).zone_id,
                    });
                }
                reject(new Error('未找到区域'));
            })
        })
    }

    async listRecords(domain) {

        // 根据doman 获取zoneId
        const {zone_id} = getDomain("cloudflare/" + domain);

        return new Promise(async (resolve, reject) => {
            try {
                let allRecords = [];
                let page = 1;
                let totalPages = 1;

                // 循环获取所有页的记录
                while (page <= totalPages) {
                    const endpoint = `/client/v4/zones/${zone_id}/dns_records?per_page=100&page=${page}`;
                    const response = await this.cfRest('GET', endpoint);

                    if (!response.success) {
                        reject(new Error(`获取记录时出错: ${response.errors[0].message}`));
                        return;
                    }

                    // 更新总页数
                    if (response.result_info) {
                        totalPages = response.result_info.total_pages;
                    }

                    // 添加当前页的记录
                    allRecords = allRecords.concat(response.result);
                    page++;
                }

                // 处理所有记录
                const records = allRecords.map(record => {
                    // 如果 name 是根域名，替换成 @
                    if (record.name === domain) {
                        record.name = '@';
                    }
                    // 其它域名，去掉域名后缀
                    if (record.name.endsWith(`.${domain}`)) {
                        record.name = record.name.slice(0, -domain.length - 1);
                    }
                    return {
                        RecordId: record.id,
                        Name: record.name,
                        Value: record.content,
                        Type: record.type,
                        TTL: record.ttl,
                        MX: record.priority,
                        ProxyStatus: record.proxied, // cloudflare 代理状态
                        Remark: record.comment
                    }
                })
                resolve({
                    count: records.length,
                    list: records,
                });
            } catch (e) {
                reject(e);
            }
        })
    }

    async addRecord(domain, record) {
        const {zone_id} = getDomain("cloudflare/" + domain)
        return new Promise((resolve, reject) => {
                let formData = {
                    type: record.type,
                    name: record.name === "@" ? '@' : `${record.name}.${domain}`,
                    content: record.value,
                    ttl: record.ttl,
                    proxied: record.proxied,
                    comment: record.remark,
                }
                // 如果是 MX 记录，添加 MX 字段
                if (record.type === "MX") {
                    formData.priority = record.mx;
                }
                this.cfRest('POST', `/client/v4/zones/${zone_id}/dns_records`, formData).then(response => {
                    if (!response.success) {
                        reject(new Error(`添加记录时出错: ${response.errors[0].message}`));
                    }
                    resolve(response);
                }).catch(e => {
                    reject(e);
                })
            }
        )
    }

    async updateRecord(domain, record) {
        const {zone_id} = getDomain("cloudflare/" + domain)

        let formData = {
            type: record.type,
            name: record.name === "@" ? '@' : `${record.name}.${domain}`,
            content: record.value,
            proxied: record.proxied,
            comment: record.remark,
            ttl: record.ttl,
        };
        // 如果是 MX 记录，添加 MX 字段
        if (record.type === "MX") {
            formData.priority = record.mx;
        }
        return this.cfRest("PATCH", `/client/v4/zones/${zone_id}/dns_records/${record.id}`,
            formData)
    }

    async deleteRecord(domain, recordId) {
        // 根据doman 获取zoneId
        const {zone_id} = getDomain("cloudflare/" + domain)
        return new Promise((resolve, reject) => {
            this.cfRest('DELETE', `/client/v4/zones/${zone_id}/dns_records/${recordId}`)
                .then(response => {
                    if (!response.success) {
                        reject(new Error(`删除记录时出错: ${response.errors[0].message}`));
                    }
                    resolve(response);
                }).catch(e => {
                reject(e);
            })
        })
    }

    async cfRest(method, endpoint, data = null) {
        const headers = {
            'Content-Type': 'application/json',
        };
        if (this.apiToken) {
            headers['Authorization'] = `Bearer ${this.apiToken}`;
        } else {
            headers['X-Auth-Email'] = this.email;
            headers['X-Auth-Key'] = this.apiKey;
        }

        const options = {
            hostname: this.apiBase,
            path: endpoint,
            method,
            headers,
        };
        try {
            const res = await httpsRequest(options, data ? JSON.stringify(data) : null);
            return JSON.parse(res);
        } catch (error) {
            throw new Error(`API请求错误: ${error.message}`);
        }
    }
}

export default CloudflareDnsService;
