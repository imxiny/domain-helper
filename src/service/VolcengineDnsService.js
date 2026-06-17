import {httpsRequest} from '@/utils/http';
import {containsAnySubstring, getDnsServer, getDomain} from "@/utils/tool";

const crypto = preload.crypto;


// 火山引擎 https://www.volcengine.com/docs/6758/155086
class VolcengineDnsService {
    constructor(secretId, secretKey) {
        this.secretId = secretId;
        this.secretKey = secretKey;
        this.service = 'DNS';
        this.region = 'cn-north-1';
        this.host = 'open.volcengineapi.com';
        this.version = '2018-08-01';
        this.dnsServer = ['volcengine']
    }


    async listDomains() {
        const requestQuery = {};
        try {
            const checkZoneResult = await this._request("GET", requestQuery, {}, this.secretId, this.secretKey, "ListZones", {});
            return checkZoneResult?.Result?.Zones.filter(async z => {
                const {nsname} = await getDnsServer(z.ZoneName)
                return containsAnySubstring(this.dnsServer, nsname)
            }).map(z => {
                return {
                    domain: z.ZoneName,
                    cloud: "volcengine",
                    zone_id: z.ZID,
                }
            })
        } catch (e) {
            throw e;
        }
    }

    async listRecords(domain, options = {}) {
        const hasOptions = Object.keys(options).length > 0;
        const page = Math.max(parseInt(options.page || 1, 10), 1);
        const pageSize = Math.max(parseInt(options.pageSize || (hasOptions ? 20 : 500), 10), 1);
        const {zone_id} = getDomain("volcengine/" + domain);
        const requestQuery = {ZID: zone_id, PageNumber: page, PageSize: pageSize};
        try {
            const checkZoneResult = await this._request("GET", requestQuery, {}, this.secretId, this.secretKey, "ListRecords", {});
            const count = checkZoneResult?.Result?.TotalCount || 0;
            return {
                count,
                page,
                pageSize,
                hasMore: page * pageSize < count,
                searchedAll: false,
                list: (checkZoneResult?.Result?.Records || []).map(r => {
                    return {
                        RecordId: r.RecordID,
                        Name: r.Host,
                        Value: r.Value,
                        TTL: r.TTL,
                        Type: r.Type,
                        Remark: r.Remark,
                        Status: r.Enable,
                        Line: r.Line,
                    }
                })
            }
        } catch (e) {
            throw e;
        }
    }

    async addRecord(domain, record) {
        const {zone_id} = getDomain("volcengine/" + domain);
        const requestQuery = {};
        const requestHeader = {};
        const requestBody = {
            Host: record.name,
            Value: record.value,
            Type: record.type,
            Remark: record.remark,
            ZID: zone_id
        };
        return await this._request("POST", requestQuery, requestHeader, this.secretId, this.secretKey, "CreateRecord", requestBody);
    }

    async changeRecordStatus(domain, recordId, extra = {}) {
        const requestQuery = {};
        const requestHeader = {};
        const requestBody = {
            RecordID: recordId,
            Enable: extra.Status
        };
        console.log(requestBody)
        return await this._request("POST", requestQuery, requestHeader, this.secretId, this.secretKey, "UpdateRecordStatus", requestBody);
    }

    async deleteRecord(domain, recordId) {
        const requestQuery = {};
        const requestHeader = {};
        const requestBody = {
            RecordID: recordId
        };
        return await this._request("POST", requestQuery, requestHeader, this.secretId, this.secretKey, "DeleteRecord", requestBody);
    }

    async updateRecord(domain, record) {
        const oldRecord = (await this.listRecords(domain)).list.find(item => item.RecordId === record.id);
        const requestQuery = {};
        const requestHeader = {};
        const requestBody = {
            RecordID: record.id,
            Host: record.name,
            Line: oldRecord.Line,
            Value: record.value,
            Type: record.type,
            Remark: record.remark,
        };
        return await this._request("POST", requestQuery, requestHeader, this.secretId, this.secretKey, "UpdateRecord", requestBody)
    }

    normQuery(params) {
        let query = "";
        const keys = Object.keys(params).sort();
        keys.forEach(key => {
            if (Array.isArray(params[key])) {
                params[key].forEach(k => {
                    query += `${encodeURIComponent(key)}=${encodeURIComponent(k)}&`;
                });
            } else {
                query += `${encodeURIComponent(key)}=${encodeURIComponent(params[key])}&`;
            }
        });
        return query.slice(0, -1).replace(/\+/g, "%20");
    }

    hmacSha256(key, content) {
        return crypto.createHmac('sha256', key).update(content).digest();
    }

    hashSha256(content) {
        return crypto.createHash('sha256').update(content).digest('hex');
    }

    async _request(method, query, header, ak, sk, action, body) {
        const credential = {
            access_key_id: ak,
            secret_access_key: sk,
            service: this.service,
            region: this.region
        };

        query = {Action: action, Version: this.version, ...query};
        const sortedQuery = Object.keys(query).sort().reduce((acc, key) => {
            acc[key] = query[key];
            return acc;
        }, {});

        const requestParam = {
            body: "",
            host: this.host,
            path: "/",
            method: method,
            content_type: "application/json",
            date: new Date().toISOString().replace(/[:-]|\.\d{3}/g, ''),
            query: sortedQuery,
        };

        if (method === "POST") {
            requestParam.body = JSON.stringify(body);
        }

        const x_date = requestParam.date;
        const short_x_date = x_date.slice(0, 8);
        const x_content_sha256 = this.hashSha256(requestParam.body);
        const signResult = {
            Host: requestParam.host,
            "X-Content-Sha256": x_content_sha256,
            "X-Date": x_date,
            "Content-Type": requestParam.content_type,
        };

        const signedHeadersStr = "content-type;host;x-content-sha256;x-date";
        const canonicalRequestStr = [
            requestParam.method,
            requestParam.path,
            this.normQuery(requestParam.query),
            `content-type:${requestParam.content_type}\nhost:${requestParam.host}\nx-content-sha256:${x_content_sha256}\nx-date:${x_date}\n`,
            signedHeadersStr,
            x_content_sha256,
        ].join('\n');

        const hashedCanonicalRequest = this.hashSha256(canonicalRequestStr);
        const credentialScope = `${short_x_date}/${credential.region}/${credential.service}/request`;
        const stringToSign = `HMAC-SHA256\n${x_date}\n${credentialScope}\n${hashedCanonicalRequest}`;
        const kDate = this.hmacSha256(`${credential.secret_access_key}`, short_x_date);
        const kRegion = this.hmacSha256(kDate, credential.region);
        const kService = this.hmacSha256(kRegion, credential.service);
        const kSigning = this.hmacSha256(kService, "request");
        const signature = this.hmacSha256(kSigning, stringToSign).toString('hex');

        signResult.Authorization = `HMAC-SHA256 Credential=${credential.access_key_id}/${credentialScope}, SignedHeaders=${signedHeadersStr}, Signature=${signature}`;
        header = {...header, ...signResult};

        const options = {
            hostname: requestParam.host,
            path: `/?${this.normQuery(requestParam.query)}`,
            method: requestParam.method,
            headers: header,
        };

        if (method === "POST") {
            return await httpsRequest(options, requestParam.body, true);
        } else if (method === "GET") {
            return await httpsRequest(options, null, true);
        }
    }
}

export default VolcengineDnsService;
