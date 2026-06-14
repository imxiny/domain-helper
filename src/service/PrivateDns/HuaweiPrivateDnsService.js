import {httpsRequestWithResponseHeader} from "@/utils/http";
import {getItem, setItem} from "@/utils/tool";

class HuaweiPrivateDnsService {
    constructor(domainName, username, password) {
        this.domainName = domainName;
        this.username = username;
        this.password = password;
        this.project = "ap-southeast-1";
        this.hostname = "dns.ap-southeast-1.myhuaweicloud.com";
        this.cacheKey = `extra/huawei_private_iam_token/${domainName}/${username}`;
        this.supportsRecordRemarkUpdate = true;
    }

    getMillisecondTimestamp(datetime) {
        return new Date(datetime).getTime();
    }

    async getToken() {
        const cacheToken = getItem(this.cacheKey, null);
        if (cacheToken && cacheToken.expire > Date.now()) {
            return cacheToken.token;
        }
        const body = JSON.stringify({
            auth: {
                identity: {
                    methods: ["password"],
                    password: {
                        user: {
                            name: this.username,
                            password: this.password,
                            domain: {name: this.domainName},
                        },
                    },
                },
                scope: {project: {name: this.project}},
            },
        });
        const response = await httpsRequestWithResponseHeader({
            hostname: "iam.myhuaweicloud.com",
            path: "/v3/auth/tokens",
            method: "POST",
            headers: {"Content-Type": "application/json;charset=utf8"},
        }, body);
        if (response.data.error) {
            throw new Error(response.data.error.message);
        }
        const token = response.headers["x-subject-token"];
        const expire = this.getMillisecondTimestamp(response.data.token.expires_at) - 1000 * 60 * 5;
        setItem(this.cacheKey, {token, expire});
        return token;
    }

    async listZones(options = {}) {
        const page = Math.max(parseInt(options.page || 1, 10), 1);
        const pageSize = Math.max(parseInt(options.pageSize || 100, 10), 1);
        const token = await this.getToken();
        const response = await httpsRequestWithResponseHeader({
            hostname: this.hostname,
            path: `/v2/zones?type=private&limit=${pageSize}&offset=${(page - 1) * pageSize}`,
            method: "GET",
            headers: {"X-Auth-Token": token},
        }, null);
        this._assertResponse(response);
        return (response.data.zones || []).map(zone => this._zoneToModel(zone));
    }

    async createZone({name, vpcId, vpcRegion}) {
        if (!vpcId || !vpcRegion) {
            throw new Error("华为云创建内网域名需要绑定 VPC；当前版本仅支持拉取已有内网域名后管理记录。");
        }
        const token = await this.getToken();
        const body = JSON.stringify({
            name,
            zone_type: "private",
            router: {
                router_id: vpcId,
                router_region: vpcRegion,
            },
        });
        const response = await httpsRequestWithResponseHeader({
            hostname: this.hostname,
            path: "/v2/zones",
            method: "POST",
            headers: {
                "Content-Type": "application/json",
                "X-Auth-Token": token,
            },
        }, body);
        this._assertResponse(response);
        return this._zoneToModel(response.data);
    }

    async deleteZone(zone) {
        const token = await this.getToken();
        const response = await httpsRequestWithResponseHeader({
            hostname: this.hostname,
            path: `/v2/zones/${zone.zone_id}`,
            method: "DELETE",
            headers: {"X-Auth-Token": token},
        }, null);
        this._assertResponse(response);
    }

    async listVpcBindings(zone) {
        const token = await this.getToken();
        const response = await httpsRequestWithResponseHeader({
            hostname: this.hostname,
            path: `/v2/zones/${zone.zone_id}`,
            method: "GET",
            headers: {"X-Auth-Token": token},
        }, null);
        this._assertResponse(response);
        return this._normalizeVpcBindings(response.data.routers || response.data.router || []);
    }

    async listRecords(zone, options = {}) {
        const page = Math.max(parseInt(options.page || 1, 10), 1);
        const pageSize = Math.max(parseInt(options.pageSize || 20, 10), 1);
        const token = await this.getToken();
        const response = await httpsRequestWithResponseHeader({
            hostname: this.hostname,
            path: `/v2.1/zones/${zone.zone_id}/recordsets?limit=${pageSize}&offset=${(page - 1) * pageSize}`,
            method: "GET",
            headers: {"X-Auth-Token": token},
        }, null);
        this._assertResponse(response);
        const total = response.data.metadata?.total_count || 0;
        return {
            count: total,
            page,
            pageSize,
            hasMore: page * pageSize < total,
            searchedAll: false,
            list: (response.data.recordsets || []).map(record => this._recordToModel(record, zone.zone_name)),
        };
    }

    async addRecord(zone, record) {
        const token = await this.getToken();
        let records = [`${record.value}`];
        if (record.type === "TXT") {
            records = records.map(item => item.startsWith("\"") ? item : `"${item}"`);
        }
        const body = JSON.stringify({
            name: record.name === "@" ? zone.zone_name : `${record.name}.${zone.zone_name}`,
            type: record.type,
            records,
            ttl: record.ttl || 300,
            description: record.remark || "",
        });
        const response = await httpsRequestWithResponseHeader({
            hostname: this.hostname,
            path: `/v2.1/zones/${zone.zone_id}/recordsets`,
            method: "POST",
            headers: {
                "Content-Type": "application/json",
                "X-Auth-Token": token,
            },
        }, body);
        this._assertResponse(response);
        return response.data;
    }

    async updateRecord(zone, record) {
        const token = await this.getToken();
        let records = [`${record.value}`];
        if (record.type === "TXT") {
            records = records.map(item => item.startsWith("\"") ? item : `"${item}"`);
        }
        const body = JSON.stringify({
            name: record.name === "@" ? zone.zone_name : `${record.name}.${zone.zone_name}`,
            type: record.type,
            records,
            ttl: record.ttl || 300,
            description: record.remark || "",
        });
        const response = await httpsRequestWithResponseHeader({
            hostname: this.hostname,
            path: `/v2.1/zones/${zone.zone_id}/recordsets/${record.id}`,
            method: "PUT",
            headers: {
                "Content-Type": "application/json",
                "X-Auth-Token": token,
            },
        }, body);
        this._assertResponse(response);
        return response.data;
    }

    async deleteRecord(zone, recordId) {
        const token = await this.getToken();
        const response = await httpsRequestWithResponseHeader({
            hostname: this.hostname,
            path: `/v2.1/zones/${zone.zone_id}/recordsets/${recordId}`,
            method: "DELETE",
            headers: {"X-Auth-Token": token},
        }, null);
        this._assertResponse(response);
    }

    async changeRecordStatus(zone, recordId, extra = {}) {
        const token = await this.getToken();
        const body = JSON.stringify({
            status: extra.Status ? "ENABLE" : "DISABLE",
        });
        const response = await httpsRequestWithResponseHeader({
            hostname: this.hostname,
            path: `/v2.1/recordsets/${recordId}/statuses/set`,
            method: "PUT",
            headers: {
                "Content-Type": "application/json",
                "X-Auth-Token": token,
            },
        }, body);
        this._assertResponse(response);
    }

    _zoneToModel(zone) {
        return {
            zone_id: zone.id,
            zone_name: (zone.name || "").replace(/\.$/, ""),
            cloud: "huawei",
            record_count: zone.record_num || 0,
            vpc_bindings: this._normalizeVpcBindings(zone.routers || zone.router || []),
            remark: zone.description || "",
            status: zone.status || "",
        };
    }

    _recordToModel(record, zoneName) {
        let name = record.name || "@";
        if (name === `${zoneName}.`) {
            name = "@";
        } else if (name.endsWith(`.${zoneName}.`)) {
            name = name.slice(0, -zoneName.length - 2);
        }
        return {
            RecordId: record.id,
            Name: name,
            Value: (record.records || []).map(item => this._normalizeRecordValue(record.type, item)).join("\n"),
            Type: record.type,
            TTL: record.ttl,
            Status: this._normalizeRecordStatus(record.status),
            StatusText: this._normalizeRecordStatus(record.status) ? "启用" : "暂停",
            Remark: record.description || "",
            RecordLine: record.line || record.view || "默认",
            CreatedAt: record.created_at || record.create_at || record.create_time || "",
            UpdatedAt: record.updated_at || record.update_at || record.update_time || "",
        };
    }

    _normalizeVpcBindings(bindings) {
        const list = Array.isArray(bindings) ? bindings : [bindings].filter(Boolean);
        return list.map(item => ({
            id: item.router_id || item.id || "",
            name: item.router_id || item.id || "",
            region: item.router_region || item.region || "",
        }));
    }

    _normalizeRecordStatus(status) {
        const value = (status || "").toString().toUpperCase();
        return !["DISABLE", "DISABLED", "INACTIVE"].includes(value);
    }

    _normalizeRecordValue(type, value) {
        const text = (value || "").toString();
        if (type === "TXT") {
            return text.replace(/^"|"$/g, "");
        }
        return text;
    }

    _assertResponse(response) {
        if (response.statusCode >= 400) {
            throw new Error(response.data?.message || response.data?.error?.message || "华为云 API 请求失败");
        }
    }
}

export default HuaweiPrivateDnsService;
