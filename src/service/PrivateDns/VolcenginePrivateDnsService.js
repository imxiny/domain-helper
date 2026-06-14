import {httpsRequest} from "@/utils/http";

const crypto = preload.crypto;

class VolcenginePrivateDnsService {
    constructor(secretId, secretKey) {
        this.secretId = secretId;
        this.secretKey = secretKey;
        this.service = "DNS";
        this.region = "cn-north-1";
        this.host = "open.volcengineapi.com";
        this.version = "2018-08-01";
        this.supportsRecordRemarkUpdate = true;
    }

    async listZones(options = {}) {
        const page = Math.max(parseInt(options.page || 1, 10), 1);
        const pageSize = Math.max(parseInt(options.pageSize || 100, 10), 1);
        const res = await this._request("GET", {
            PageNumber: page,
            PageSize: pageSize,
        }, {}, "ListPrivateZones", {});
        this._assertResponse(res);
        const zones = res?.Result?.Zones || res?.Result?.PrivateZones || [];
        return zones.map(zone => this._zoneToModel(zone));
    }

    async createZone({name}) {
        const res = await this._request("POST", {}, {}, "CreatePrivateZone", {
            ZoneName: name,
        });
        this._assertResponse(res);
        const zone = res?.Result?.Zone || res?.Result || {};
        return this._zoneToModel({
            ...zone,
            ZoneName: zone.ZoneName || name,
        });
    }

    async deleteZone(zone) {
        const res = await this._request("POST", {}, {}, "DeletePrivateZone", {
            ZID: zone.zone_id,
        });
        this._assertResponse(res);
        return res;
    }

    async listVpcBindings(zone) {
        const res = await this._request("GET", {ZID: zone.zone_id}, {}, "GetPrivateZone", {});
        this._assertResponse(res);
        const info = res?.Result?.Zone || res?.Result || {};
        return this._normalizeVpcBindings(info.Vpcs || info.VPCs || info.VpcList || []);
    }

    async listRecords(zone, options = {}) {
        const page = Math.max(parseInt(options.page || 1, 10), 1);
        const pageSize = Math.max(parseInt(options.pageSize || 20, 10), 1);
        const res = await this._request("GET", {
            ZID: zone.zone_id,
            PageNumber: page,
            PageSize: pageSize,
        }, {}, "ListPrivateZoneRecords", {});
        this._assertResponse(res);
        const records = res?.Result?.Records || [];
        const count = res?.Result?.TotalCount || records.length;
        return {
            count,
            page,
            pageSize,
            hasMore: page * pageSize < count,
            searchedAll: false,
            list: records.map(record => this._recordToModel(record)),
        };
    }

    async addRecord(zone, record) {
        const res = await this._request("POST", {}, {}, "CreatePrivateZoneRecord", {
            ZID: zone.zone_id,
            Host: record.name,
            Type: record.type,
            Value: record.value,
            TTL: record.ttl || 600,
            Remark: record.remark || "",
        });
        this._assertResponse(res);
        return res;
    }

    async updateRecord(zone, record) {
        const res = await this._request("POST", {}, {}, "UpdatePrivateZoneRecord", {
            RecordID: record.id,
            Host: record.name,
            Type: record.type,
            Value: record.value,
            TTL: record.ttl || 600,
            Remark: record.remark || "",
        });
        this._assertResponse(res);
        return res;
    }

    async deleteRecord(zone, recordId) {
        const res = await this._request("POST", {}, {}, "DeletePrivateZoneRecord", {
            RecordID: recordId,
        });
        this._assertResponse(res);
        return res;
    }

    async changeRecordStatus(zone, recordId, extra = {}) {
        const res = await this._request("POST", {}, {}, "UpdatePrivateZoneRecordStatus", {
            RecordID: recordId,
            Enable: extra.Status,
        });
        this._assertResponse(res);
        return res;
    }

    _zoneToModel(zone) {
        return {
            zone_id: zone.ZID || zone.ZoneId || zone.ID,
            zone_name: zone.ZoneName || zone.Name,
            cloud: "volcengine",
            record_count: zone.RecordCount || 0,
            vpc_bindings: this._normalizeVpcBindings(zone.Vpcs || zone.VPCs || zone.VpcList || []),
            remark: zone.Remark || "",
            status: zone.Status || "",
        };
    }

    _recordToModel(record) {
        return {
            RecordId: record.RecordID || record.RecordId || record.ID,
            Name: record.Host || record.Name || "@",
            Value: record.Value,
            TTL: record.TTL || 600,
            Type: record.Type,
            Remark: record.Remark || "",
            Status: this._normalizeRecordStatus(record),
            StatusText: this._normalizeRecordStatus(record) ? "启用" : "暂停",
            Line: record.Line,
            RecordLine: record.Line || record.View || "默认",
            CreatedAt: record.CreatedAt || record.CreateTime || record.CreatedTime || "",
            UpdatedAt: record.UpdatedAt || record.UpdateTime || record.UpdatedTime || "",
        };
    }

    _normalizeVpcBindings(bindings) {
        const list = Array.isArray(bindings) ? bindings : [bindings].filter(Boolean);
        return list.map(item => ({
            id: item.VpcId || item.VPCId || item.ID || "",
            name: item.VpcName || item.Name || item.VpcId || item.VPCId || "",
            region: item.Region || item.RegionId || "",
        }));
    }

    _normalizeRecordStatus(record) {
        if (typeof record.Enable === "boolean") {
            return record.Enable;
        }
        const value = (record.Status || "").toString().toLowerCase();
        return !["disable", "disabled", "inactive", "false"].includes(value);
    }

    _assertResponse(response) {
        const error = response?.ResponseMetadata?.Error || response?.Error;
        if (error) {
            throw new Error(error.Message || error.Code || "火山引擎 API 请求失败");
        }
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
        return crypto.createHmac("sha256", key).update(content).digest();
    }

    hashSha256(content) {
        return crypto.createHash("sha256").update(content).digest("hex");
    }

    async _request(method, query, header, action, body) {
        const credential = {
            access_key_id: this.secretId,
            secret_access_key: this.secretKey,
            service: this.service,
            region: this.region,
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
            method,
            content_type: "application/json",
            date: new Date().toISOString().replace(/[:-]|\.\d{3}/g, ""),
            query: sortedQuery,
        };
        if (method === "POST") {
            requestParam.body = JSON.stringify(body);
        }
        const xDate = requestParam.date;
        const shortDate = xDate.slice(0, 8);
        const xContentSha256 = this.hashSha256(requestParam.body);
        const signedHeadersStr = "content-type;host;x-content-sha256;x-date";
        const canonicalRequestStr = [
            requestParam.method,
            requestParam.path,
            this.normQuery(requestParam.query),
            `content-type:${requestParam.content_type}\nhost:${requestParam.host}\nx-content-sha256:${xContentSha256}\nx-date:${xDate}\n`,
            signedHeadersStr,
            xContentSha256,
        ].join("\n");
        const credentialScope = `${shortDate}/${credential.region}/${credential.service}/request`;
        const stringToSign = `HMAC-SHA256\n${xDate}\n${credentialScope}\n${this.hashSha256(canonicalRequestStr)}`;
        const kDate = this.hmacSha256(`${credential.secret_access_key}`, shortDate);
        const kRegion = this.hmacSha256(kDate, credential.region);
        const kService = this.hmacSha256(kRegion, credential.service);
        const kSigning = this.hmacSha256(kService, "request");
        const signature = this.hmacSha256(kSigning, stringToSign).toString("hex");
        header = {
            ...header,
            Host: requestParam.host,
            "X-Content-Sha256": xContentSha256,
            "X-Date": xDate,
            "Content-Type": requestParam.content_type,
            Authorization: `HMAC-SHA256 Credential=${credential.access_key_id}/${credentialScope}, SignedHeaders=${signedHeadersStr}, Signature=${signature}`,
        };
        const options = {
            hostname: requestParam.host,
            path: `/?${this.normQuery(requestParam.query)}`,
            method: requestParam.method,
            headers: header,
        };
        return method === "POST"
            ? httpsRequest(options, requestParam.body, true)
            : httpsRequest(options, null, true);
    }
}

export default VolcenginePrivateDnsService;
