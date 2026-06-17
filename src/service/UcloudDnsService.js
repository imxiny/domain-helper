import {httpsRequest} from '@/utils/http';

const crypto = preload.crypto
const renewLink = "https://console.ucloud.cn/udnr/manage";

const REGIN = "cn-bj2";

// https://console-docs.apipost.cn/preview/ab2c3103b22855ba/fac91d1e43fafb69?target_id=fd825e19-ee7e-4f49-a8cb-62836c690301
class UcloudDnsService {
    constructor(publicKey, privateKey) {
        this.publicKey = publicKey;
        this.privateKey = privateKey;
    }

    _generateSignature(params) {
        // 1. 将参数按照参数名进行字典序排序
        const sortedParams = Object.keys(params).sort().reduce((acc, key) => {
            acc[key] = params[key];
            return acc;
        }, {});

        // 2. 将排序后的参数拼接成字符串
        const paramString = Object.entries(sortedParams)
            .map(([key, value]) => `${key}${value}`)
            .join('');

        // 3. 在字符串末尾拼接API密钥
        const stringToSign = paramString + this.privateKey;

        // 4. 对整个字符串进行SHA1哈希
        return crypto.createHash('sha1').update(stringToSign).digest('hex');
    }

    async _ucloudRest(method, action, payload) {
        const params = {
            ...payload,
            PublicKey: this.publicKey,
            Region: REGIN,
            Action: action,
        };
        params.Signature = this._generateSignature(params);
        const options = {
            hostname: 'api.ucloud.cn',
            method: method,
            path: "/",
            headers: {
                'Content-Type': "application/json"
            }
        };
        return new Promise((resolve, reject) => {
            httpsRequest(options, JSON.stringify(params), true)
                .then(response => {
                    if (response.RetCode !== 0) {
                        reject(new Error(response.Message || 'API request failed'));
                        return;
                    }
                    resolve(response);
                })
                .catch(e => {
                    reject(e);
                });
        });
    }

    async listDomains() {
        return [];
    }

    async checkDomain(domain) {
        // 获取记录，看是否正确
        const data = await this._ucloudRest('POST', "UdnrDomainDNSQuery", {
            "Dn": domain
        });
        if (data.RetCode === 0) {
            return {
                zone_id: domain
            }
        }
        throw new Error(data.Message);
    }

    async listRecords(domain, options = {}) {
        const hasOptions = Object.keys(options).length > 0;
        const page = Math.max(parseInt(options.page || 1, 10), 1);
        const pageSize = Math.max(parseInt(options.pageSize || (hasOptions ? 20 : 5000), 10), 1);
        const {Data} = await this._ucloudRest('POST', "UdnrDomainDNSQuery", {
            "Dn": domain
        });
        if (Data === null) {
            return {
                count: 0,
                list: [],
                page,
                pageSize,
                hasMore: false,
                searchedAll: true,
            }
        }
        const start = (page - 1) * pageSize;
        const pageData = Data.slice(start, start + pageSize);
        return {
            count:  Data.length,
            page,
            pageSize,
            hasMore: start + pageData.length < Data.length,
            searchedAll: true,
            list: pageData.map(item => {
                // 解析记录清空 域名
                item.RecordName = item.RecordName.replace(`.${domain}`, "");
                return {
                    RecordId: item.RecordName + "##" + item.DnsType + "##" + item.TTL,
                    Name: item.RecordName,
                    Type: item.DnsType,
                    Value: item.Content,
                    TTL: item.TTL,
                    Level: item.Prio,
                }
            })
        }
    }

    async addRecord(domain, record) {
        const payload = {
            Dn: domain,
            RecordName: record.name + `.${domain}`,
            DnsType: record.type,
            Content: record.value,
            TTL: `${record.ttl}`,
        }
        await this._ucloudRest('POST', "UdnrDomainDNSAdd", payload);
    }

    async updateRecord(domain, record) {
        const id = record.id;
        delete record.id;
        await this.deleteRecord(domain, id);
        await this.addRecord(domain, {
            ...record,
        });
    }

    async deleteRecord(domain, recordId) {
        const {list} = await this.listRecords(domain)
        let record = list.filter(i => i.RecordId === recordId);
        if (record) {
            record = record[0];
        } else {
            throw new Error(`${recordId} not found`);
        }
        await this._ucloudRest('POST', "UdnrDeleteDnsRecord", {
            Dn: domain,
            RecordName: record.Name + `.${domain}`,
            DnsType: record.Type,
            Content: record.Value,
        });
    }
}

export default UcloudDnsService;
