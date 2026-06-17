import {httpsRequest} from '@/utils/http';

const crypto = preload.crypto
const renewLink = "https://www.west.cn/manager/domain/";


// https://console-docs.apipost.cn/preview/ab2c3103b22855ba/fac91d1e43fafb69?target_id=fd825e19-ee7e-4f49-a8cb-62836c690301
class WestDnsService {
    constructor(username, api_password) {
        this.username = username;
        this.api_password = api_password;
    }
    getCommonParam() {
        const now = new Date().getTime();
        return {
            username: this.username,
            time: now,
            token: crypto.createHash('md5').update(this.username + this.api_password + now).digest('hex')
        }
    }

    async listDomains() {
        const payload = {
            act: 'getdomains',
            page: 1,
            limit: 1000
        }
        const {data} = await this._westRest('GET', "domain", payload);
        return data.items.map(item => {
            return {
                domain: item.domain,
                cloud: "west",
                expire_time: item.expdate,
                renew_link: item.expdate ? renewLink : ""
            }
        });
    }

    async listRecords(domain, options = {}) {
        const hasOptions = Object.keys(options).length > 0;
        const page = Math.max(parseInt(options.page || 1, 10), 1);
        const pageSize = Math.max(parseInt(options.pageSize || (hasOptions ? 20 : 1000), 10), 1);
        const payload = {
            act: 'getdnsrecord',
            page,
            limit: pageSize,
            domain,
        }
        const {data} = await this._westRest('GET', "domain", payload);
        return {
            count: data.total,
            page,
            pageSize,
            hasMore: page * pageSize < data.total,
            searchedAll: false,
            list: data.items.map(item => {
                return {
                    RecordId: item.id,
                    Name: item.item,
                    Type: item.type,
                    Value: item.value,
                    Status: item.pause === 0,
                    TTL: item.ttl,
                    Level: item.level,
                }
            })
        }
    }

    async addRecord(domain, record) {
        const payload = {
            act: 'adddnsrecord',
            domain,
            host: record.name,
            type: record.type,
            value: record.value,
            ttl: 900,
            level: 10,
        }
        await this._westRest('POST', "domain", payload);
    }

    async updateRecord(domain, record) {
        const id = record.id;
        delete record.id;
        await this.addRecord(domain, {
            ...record,
            ttl: 900,
            level: 10
        });
        await this.deleteRecord(domain, id);
    }

    async deleteRecord(domain, recordId) {
        const payload = {
            act: 'deldnsrecord',
            domain,
            id: recordId
        }
        await this._westRest('POST', "domain", payload);
    }

    async changeRecordStatus(domain, recordId, extra = {}) {
        const payload = {
            act: 'pause',
            domain,
            id: recordId,
            val: extra.Status ? 0 : 1
        }
        console.log(payload)
        const res = await this._westRest('POST', "domain", payload);
        console.log(res);
    }

    _westRest(method, endpoint, payload) {
        let path = `/api/v2/${endpoint}/`;
        payload = {...payload, ...this.getCommonParam()}
        payload = Object.keys(payload).map(key => `${key}=${payload[key]}`).join('&');
        if (method === "GET") {
            path = `${path}?${payload}`;
        }
        const options = {
            hostname: 'api.west.cn',
            method: method,
            path,
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded'
            }
        };

        return new Promise((resolve, reject) => {
            httpsRequest(options, payload, true)
                .then(response => {
                    // 将response 从 gb2312 转换为 utf-8
                    response = JSON.parse(response)
                    if (response.result !== 200) {
                        reject(new Error(response.msg || 'API request failed'));
                        return;
                    }
                    resolve(response);
                })
                .catch(reject);
        });
    }
}

export default WestDnsService;
