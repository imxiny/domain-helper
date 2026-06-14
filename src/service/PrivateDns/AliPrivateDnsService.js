import {httpsRequest} from "@/utils/http";

class AliPrivateDnsService {
    constructor(accessKeyId, accessKeySecret) {
        this.accessKeyId = accessKeyId;
        this.accessKeySecret = accessKeySecret;
        this.apiBase = "pvtz.aliyuncs.com";
        this.version = "2018-01-01";
    }

    async listZones(options = {}) {
        const page = Math.max(parseInt(options.page || 1, 10), 1);
        const pageSize = Math.max(parseInt(options.pageSize || 100, 10), 1);
        const action = "DescribeZones";
        const payload = this._buildQuery(action, {PageNumber: page, PageSize: pageSize});
        const res = await this._aliRest(action, payload);
        const zones = res.Zones?.Zone || res.Zones || [];
        const list = (Array.isArray(zones) ? zones : [zones]).filter(Boolean);
        return list.map(item => ({
            zone_id: item.ZoneId,
            zone_name: item.ZoneName,
            cloud: "ali",
            record_count: item.RecordCount || 0,
            vpc_bindings: this._normalizeVpcBindings(item.BindVpcs?.Vpc || item.BindVpcs || []),
            remark: item.Remark || "",
            status: item.ZoneType || item.Status || "",
        }));
    }

    async createZone({name}) {
        const action = "AddZone";
        const payload = this._buildQuery(action, {ZoneName: name});
        const res = await this._aliRest(action, payload);
        return {
            zone_id: res.ZoneId,
            zone_name: name,
            cloud: "ali",
            vpc_bindings: [],
            remark: "",
            status: "",
        };
    }

    async deleteZone(zone) {
        const action = "DeleteZone";
        const payload = this._buildQuery(action, {ZoneId: zone.zone_id});
        return this._aliRest(action, payload);
    }

    async listVpcBindings(zone) {
        const action = "DescribeZoneInfo";
        const payload = this._buildQuery(action, {ZoneId: zone.zone_id});
        const res = await this._aliRest(action, payload);
        return this._normalizeVpcBindings(res.BindVpcs?.Vpc || res.BindVpcs || []);
    }

    async listRecords(zone, options = {}) {
        const page = Math.max(parseInt(options.page || 1, 10), 1);
        const pageSize = Math.max(parseInt(options.pageSize || 20, 10), 1);
        const action = "DescribeZoneRecords";
        const payload = this._buildQuery(action, {
            ZoneId: zone.zone_id,
            PageNumber: page,
            PageSize: pageSize,
        });
        const res = await this._aliRest(action, payload);
        const records = res.Records?.Record || res.Records || [];
        const list = (Array.isArray(records) ? records : [records]).filter(Boolean);
        const total = Number(res.TotalItems || res.TotalCount || list.length);
        return {
            count: total,
            page,
            pageSize,
            hasMore: page * pageSize < total,
            searchedAll: true,
            list: list.map(item => ({
                RecordId: item.RecordId,
                Name: item.Rr || item.RR || "@",
                Value: item.Value,
                TTL: item.Ttl || item.TTL || 60,
                Type: item.Type,
                Status: item.Status !== "DISABLE",
                StatusText: this._normalizeStatusText(item.Status),
                Remark: item.Remark || "",
                MX: item.Priority || "",
                RecordLine: item.Line || item.RecordLine || item.LineName || item.ViewName || "默认",
                CreatedAt: item.CreateTime || item.CreateTimestamp || item.CreatedTime || "",
                UpdatedAt: item.UpdateTime || item.UpdateTimestamp || item.UpdatedTime || "",
            })),
        };
    }

    async addRecord(zone, record) {
        const action = "AddZoneRecord";
        const params = {
            ZoneId: zone.zone_id,
            Rr: record.name,
            Type: record.type,
            Value: record.value,
            Ttl: record.ttl || 60,
        };
        if (record.type === "MX") {
            params.Priority = record.mx || 10;
        }
        const payload = this._buildQuery(action, params);
        const res = await this._aliRest(action, payload);
        if (this._shouldUpdateRemark(record)) {
            await this.updateRecordRemark(res.RecordId, record.remark);
        }
        return res;
    }

    async updateRecord(zone, record) {
        const action = "UpdateZoneRecord";
        const params = {
            RecordId: record.id,
            Rr: record.name,
            Type: record.type,
            Value: record.value,
            Ttl: record.ttl || 60,
        };
        if (record.type === "MX") {
            params.Priority = record.mx || 10;
        }
        const payload = this._buildQuery(action, params);
        const res = await this._aliRest(action, payload);
        if (this._hasRemarkField(record)) {
            await this.updateRecordRemark(record.id, record.remark);
        }
        return res;
    }

    async updateRecordRemark(recordId, remark = "") {
        const action = "UpdateRecordRemark";
        const payload = this._buildQuery(action, {
            RecordId: recordId,
            Remark: (remark || "").toString(),
        });
        return this._aliRest(action, payload);
    }

    async deleteRecord(zone, recordId) {
        const action = "DeleteZoneRecord";
        const payload = this._buildQuery(action, {RecordId: recordId});
        return this._aliRest(action, payload);
    }

    async changeRecordStatus(zone, recordId, extra = {}) {
        const action = "SetZoneRecordStatus";
        const payload = this._buildQuery(action, {
            RecordId: recordId,
            Status: extra.Status ? "ENABLE" : "DISABLE",
        });
        return this._aliRest(action, payload);
    }

    _hasRemarkField(record = {}) {
        return Object.prototype.hasOwnProperty.call(record, "remark");
    }

    _shouldUpdateRemark(record = {}) {
        return this._hasRemarkField(record) && Boolean((record.remark || "").toString());
    }

    _normalizeVpcBindings(bindings) {
        const list = Array.isArray(bindings) ? bindings : [bindings].filter(Boolean);
        return list.map(item => ({
            id: item.VpcId || item.RegionId || item.Id || "",
            name: item.VpcName || item.Name || item.VpcId || "",
            region: item.RegionId || item.RegionName || "",
        }));
    }

    _normalizeStatusText(status) {
        if (status === "DISABLE") {
            return "暂停";
        }
        if (status === "ENABLE" || status === "Enable" || status === "NORMAL") {
            return "启用";
        }
        return status || "启用";
    }

    _buildQuery(action, params) {
        const request = new AliRequest("GET", "/", this.apiBase, action, this.version);
        request.queryParam = {...params};
        this._getAuthorization(request);
        return {
            headers: request.headers,
            query: new URLSearchParams(request.queryParam).toString(),
        };
    }

    _getAuthorization(signRequest) {
        const newQueryParam = {};
        this._processObject(newQueryParam, "", signRequest.queryParam);
        signRequest.queryParam = newQueryParam;
        const canonicalQueryString = Object.entries(signRequest.queryParam)
            .sort(([keyA, valueA], [keyB, valueB]) => keyA === keyB ? String(valueA).localeCompare(String(valueB)) : keyA.localeCompare(keyB))
            .map(([key, value]) => `${this._percentCode(key)}=${this._percentCode(value)}`)
            .join("&");
        const requestPayload = signRequest.body || "";
        const hashedRequestPayload = this._sha256Hex(requestPayload);
        signRequest.headers["x-acs-content-sha256"] = hashedRequestPayload;
        signRequest.headers = Object.fromEntries(
            Object.entries(signRequest.headers).map(([key, value]) => [key.toLowerCase(), value])
        );
        const sortedKeys = Object.keys(signRequest.headers)
            .filter(key => key.startsWith("x-acs-") || key === "host" || key === "content-type")
            .sort();
        const signedHeaders = sortedKeys.join(";");
        const canonicalHeaders = sortedKeys.map(key => `${key}:${signRequest.headers[key]}`).join("\n") + "\n";
        const canonicalRequest = [
            signRequest.httpMethod,
            signRequest.canonicalUri,
            canonicalQueryString,
            canonicalHeaders,
            signedHeaders,
            hashedRequestPayload,
        ].join("\n");
        const stringToSign = `ACS3-HMAC-SHA256\n${this._sha256Hex(canonicalRequest)}`;
        const signature = this._hmac256(this.accessKeySecret, stringToSign);
        signRequest.headers.Authorization = `ACS3-HMAC-SHA256 Credential=${this.accessKeyId},SignedHeaders=${signedHeaders},Signature=${signature}`;
    }

    _percentCode(str) {
        return encodeURIComponent(str).replace(/\+/g, "%20").replace(/\*/g, "%2A").replace(/~/g, "%7E");
    }

    _hmac256(key, data) {
        const hmac = preload.crypto.createHmac("sha256", key);
        hmac.update(data);
        return hmac.digest("hex").toLowerCase();
    }

    _sha256Hex(data) {
        const hash = preload.crypto.createHash("sha256");
        hash.update(data);
        return hash.digest("hex").toLowerCase();
    }

    _processObject(map, key, value) {
        if (value === null || typeof value === "undefined") return;
        if (Array.isArray(value)) {
            value.forEach((item, index) => this._processObject(map, `${key}.${index + 1}`, item));
        } else if (typeof value === "object") {
            Object.entries(value).forEach(([subKey, subValue]) => this._processObject(map, `${key}.${subKey}`, subValue));
        } else {
            map[key.startsWith(".") ? key.slice(1) : key] = String(value);
        }
    }

    async _aliRest(action, {headers, query}) {
        const response = await httpsRequest({
            hostname: this.apiBase,
            path: `/?${query}`,
            method: "GET",
            headers: {
                ...headers,
                "Content-Type": "application/x-www-form-urlencoded",
            },
        });
        const result = JSON.parse(response);
        if (result.Code) {
            throw new Error(result.Message || `${action} 请求失败`);
        }
        return result;
    }
}

class AliRequest {
    constructor(httpMethod, canonicalUri, host, xAcsAction, xAcsVersion) {
        this.httpMethod = httpMethod;
        this.canonicalUri = canonicalUri || "/";
        this.host = host;
        this.xAcsAction = xAcsAction;
        this.xAcsVersion = xAcsVersion;
        this.headers = {};
        this.body = null;
        this.queryParam = {};
        this._initHeader();
    }

    _initHeader() {
        this.headers = {
            host: this.host,
            "x-acs-action": this.xAcsAction,
            "x-acs-version": this.xAcsVersion,
            "x-acs-date": new Date().toISOString().replace(/\..+/, "Z"),
            "x-acs-signature-nonce": Math.random().toString(36).substring(2),
        };
    }
}

export default AliPrivateDnsService;
