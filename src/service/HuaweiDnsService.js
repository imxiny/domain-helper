import {httpsRequest, httpsRequestWithResponseHeader} from '@/utils/http';
import {containsAnySubstring, getDnsServer, getDomain, getItem, setItem} from "@/utils/tool";


// 文档地址 https://support.huaweicloud.com/api-dns/dns_api_64001.html
class HuaweiDnsService {
    constructor(domainName, username, password) {
        this.username = username;
        this.password = password;
        this.domainName = domainName;
        this.cacheKey = "extra/huawei_iam_token"
        this.hostname = "dns.ap-southeast-1.myhuaweicloud.com"
        this.dnsServer = ["huawei"]
    }

    getMillisecondTimestamp(datetime) {
        const date = new Date(datetime);
        return date.getTime();
    }

    xDestroy() {
        // 资源回收方法
        utools.dbStorage.removeItem(this.cacheKey)
    }

    async getToken() {
        // 判断是否缓存了 token
        const cacheToken = getItem(this.cacheKey, null);

        // 判断是否过期了
        if (cacheToken && cacheToken.expire > Date.now()) {
            return cacheToken.token
        }

        const body = JSON.stringify({
            auth: {
                identity: {
                    methods: ["password"],
                    password: {
                        user: {
                            name: this.username,
                            password: this.password,
                            domain: {name: this.domainName}
                        }
                    }
                },
                scope: {project: {name: "ap-southeast-1"}}
            }
        });

        const options = {
            hostname: 'iam.myhuaweicloud.com',
            path: '/v3/auth/tokens',
            method: 'POST',
            headers: {'Content-Type': 'application/json;charset=utf8'}
        };

        const response = await httpsRequestWithResponseHeader(options, body);
        return new Promise((resolve, reject) => {
            if (response.data.error) {
                reject(new Error(response.data.error.message))
            }
            const token = response.headers['x-subject-token'];
            const expire = this.getMillisecondTimestamp(response.data.token.expires_at) - 1000 * 60 * 5;
            setItem(this.cacheKey, {token, expire})
            resolve(token)
        })

    }


    async listDomains() {
        return new Promise((resolve, reject) => {
            this.getToken().then(async token => {
                const options = {
                    hostname: this.hostname,
                    path: `/v2/zones`,
                    method: 'GET',
                    headers: {'X-Auth-Token': token}
                };
                const response = await httpsRequest(options, null, true);
                let zones = await Promise.all(response.zones.map(async zone => {
                    if (zone.status !== "ACTIVE") {
                        return null;
                    }
                    try {
                        const {nsname} = await getDnsServer(zone.name.slice(0, -1));
                        return containsAnySubstring(this.dnsServer, nsname) ? zone : null; // 检测是否是华为云的dns服务器
                    } catch (e) {
                        return zone;
                    }
                }));
                zones = zones.filter(zone => zone !== null);
                // 华为云现有接口无法满足判断dns服务器是否正常，暂时不做判断
                resolve(zones.map(zone => {
                    return {
                        cloud: "huawei",
                        domain: zone.name.slice(0, -1),
                        zone_id: zone.id
                    }
                }));
            }).catch(e => {
                reject(e)
            })
        })
    }

    async listRecords(domain, options = {}) {
        const hasOptions = Object.keys(options).length > 0;
        const page = Math.max(parseInt(options.page || 1, 10), 1);
        const pageSize = Math.max(parseInt(options.pageSize || (hasOptions ? 20 : 500), 10), 1);
        // 根据doman 获取zoneId
        const {zone_id} = getDomain("huawei/" + domain);
        return new Promise((resolve, reject) => {
            this.getToken().then(async token => {
                const options = {
                    hostname: this.hostname,
                    path: `/v2/zones/${zone_id}/recordsets?limit=${pageSize}&offset=${(page - 1) * pageSize}`,
                    method: 'GET',
                    headers: {'X-Auth-Token': token}
                };

                const response = await httpsRequestWithResponseHeader(options, null);
                if (response.statusCode >= 400) {
                    reject(new Error(response.data.error.message))
                }
                const total = response.data.metadata.total_count;
                resolve({
                    count: total,
                    page,
                    pageSize,
                    hasMore: page * pageSize < total,
                    searchedAll: false,
                    list: response.data.recordsets.map(record => {
                        // 如果 name 是根域名，替换成 @
                        if (record.name === `${domain}.`) {
                            record.name = '@';
                        }
                        // 其它域名，去掉域名后缀
                        if (record.name.endsWith(`.${domain}.`)) {
                            record.name = record.name.slice(0, -domain.length - 2);
                        }
                        return {
                            RecordId: record.id,
                            Name: record.name,
                            Value: record.records.join("\n"),
                            Type: record.type,
                            TTL: record.ttl,
                            Status: record.status === "ACTIVE", // 暂停状态\
                            Remark: record.description
                        }
                    })
                })
            }).catch(e => {
                reject(e)
            });
        });
    }

    async addRecord(domain, record) {
        const {zone_id} = getDomain("huawei/" + domain);
        return new Promise(async (resolve, reject) => {
            const token = await this.getToken();

            let value = [`${record.value}`];
            // 如果是 TXT 记录，需要转义 前后增加双引号
            if (record.type === "TXT") {
                value = value.map(item => `"${item}"`)
            }

            const body = JSON.stringify({
                name: record.name === "@" ? domain : `${record.name}.${domain}`,
                type: record.type,
                records: value,
                description: record.remark,
            });
            const options = {
                hostname: this.hostname,
                path: `/v2/zones/${zone_id}/recordsets`,
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-Auth-Token': token
                }
            };
            const response = await httpsRequestWithResponseHeader(options, body);
            if (response.statusCode >= 400) {
                reject(new Error(response.data.message))
            }
            resolve(response.data)
        })
    }

    async deleteRecord(domain, recordId) {
        const token = await this.getToken();
        const {zone_id} = getDomain("huawei/" + domain);
        const options = {
            hostname: this.hostname,
            path: `/v2/zones/${zone_id}/recordsets/${recordId}`,
            method: 'DELETE',
            headers: {
                'X-Auth-Token': token
            }
        };
        const response = await httpsRequestWithResponseHeader(options);
        if (response.statusCode >= 400) {
            throw new Error(response.data.message)
        }
    }

    async changeRecordStatus(domain, recordId, extra = {}) {
        const token = await this.getToken();
        const options = {
            hostname: this.hostname,
            path: `/v2.1/recordsets/${recordId}/statuses/set`,
            method: 'PUT',
            headers: {
                'X-Auth-Token': token
            },
            body: JSON.stringify({
                status: extra.Status ? "ENABLE" : "DISABLE"
            })
        };
        const response = await httpsRequestWithResponseHeader(options);
        if (response.statusCode >= 400) {
            throw new Error(response.data.message)
        }
    }
}

export default HuaweiDnsService;
