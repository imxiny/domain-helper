import {httpsRequest} from "@/utils/http";

const crypto = preload.crypto;

class TencentPrivateDnsService {
    constructor(secretId, secretKey) {
        this.secretId = secretId;
        this.secretKey = secretKey;
        this.service = "privatedns";
        this.host = "privatedns.tencentcloudapi.com";
        this.version = "2020-10-28";
        this.supportsRecordRemarkUpdate = true;
    }

    async listZones(options = {}) {
        const action = "DescribePrivateZoneList";
        const page = Math.max(parseInt(options.page || 1, 10), 1);
        const pageSize = Math.max(parseInt(options.pageSize || 100, 10), 1);
        const res = await this._tencentRest(action, {
            Limit: pageSize,
            Offset: (page - 1) * pageSize,
        });
        const zones = res.PrivateZoneSet || res.PrivateZoneList || res.ZoneSet || [];
        return (zones || []).map(item => ({
            zone_id: item.ZoneId || item.PrivateZoneId || item.UniqVpcId,
            zone_name: item.Domain || item.ZoneName,
            cloud: "tencent",
            record_count: typeof item.RecordCount === "undefined" ? undefined : Number(item.RecordCount || 0),
            vpc_bindings: this._normalizeVpcBindings(item.VpcSet || item.VpcList || []),
            remark: item.Remark || "",
            status: item.Status || "",
        }));
    }

    async createZone({name}) {
        const res = await this._tencentRest("CreatePrivateZone", {
            Domain: name,
        });
        return {
            zone_id: res.ZoneId || res.PrivateZoneId,
            zone_name: name,
            cloud: "tencent",
            vpc_bindings: [],
            remark: "",
            status: "",
        };
    }

    async deleteZone(zone) {
        return this._tencentRest("DeletePrivateZone", {
            ZoneId: zone.zone_id,
        });
    }

    async listVpcBindings(zone) {
        const res = await this._tencentRest("DescribePrivateZone", {
            ZoneId: zone.zone_id,
        });
        return this._normalizeVpcBindings(res.VpcSet || res.VpcList || res.PrivateZone?.VpcSet || []);
    }

    async listRecords(zone, options = {}) {
        const page = Math.max(parseInt(options.page || 1, 10), 1);
        const pageSize = Math.max(parseInt(options.pageSize || 20, 10), 1);
        const res = await this._tencentRest("DescribePrivateZoneRecordList", {
            ZoneId: zone.zone_id,
            Limit: pageSize,
            Offset: (page - 1) * pageSize,
        });
        const records = res.RecordSet || res.RecordList || [];
        const total = Number(res.TotalCount || records.length);
        return {
            count: total,
            page,
            pageSize,
            hasMore: page * pageSize < total,
            searchedAll: true,
            list: records.map(item => ({
                RecordId: item.RecordId,
                Name: item.SubDomain || item.RecordName || item.Name || "@",
                Value: item.RecordValue || item.Value,
                TTL: item.TTL || item.Ttl || 600,
                Type: item.RecordType || item.Type,
                Status: this._normalizeRecordStatus(item.Status),
                StatusText: this._normalizeRecordStatus(item.Status) ? "启用" : "暂停",
                Remark: item.Remark || "",
                MX: item.MX || "",
                RecordLine: item.Line || item.RecordLine || "默认",
                CreatedAt: item.CreatedOn || item.CreateTime || item.CreatedTime || "",
                UpdatedAt: item.UpdatedOn || item.UpdateTime || item.UpdatedTime || "",
            })),
        };
    }

    async addRecord(zone, record) {
        return this._tencentRest("CreatePrivateZoneRecord", {
            ZoneId: zone.zone_id,
            RecordType: record.type,
            SubDomain: record.name,
            RecordValue: record.value,
            TTL: record.ttl || 600,
            MX: record.type === "MX" ? record.mx : undefined,
            Remark: record.remark || "",
        });
    }

    async updateRecord(zone, record) {
        return this._tencentRest("ModifyPrivateZoneRecord", {
            ZoneId: zone.zone_id,
            RecordId: record.id,
            RecordType: record.type,
            SubDomain: record.name,
            RecordValue: record.value,
            TTL: record.ttl || 600,
            MX: record.type === "MX" ? record.mx : undefined,
            Remark: record.remark || "",
        });
    }

    async deleteRecord(zone, recordId) {
        return this._tencentRest("DeletePrivateZoneRecord", {
            ZoneId: zone.zone_id,
            RecordId: recordId,
        });
    }

    async changeRecordStatus(zone, recordId, extra = {}) {
        return this._tencentRest("ModifyRecordsStatus", {
            ZoneId: zone.zone_id,
            RecordIds: [parseInt(recordId, 10)],
            Status: extra.Status ? "enabled" : "disabled",
        });
    }

    _normalizeRecordStatus(status) {
        const value = (status || "").toString().toLowerCase();
        return !["disable", "disabled"].includes(value);
    }

    _normalizeVpcBindings(bindings) {
        const list = Array.isArray(bindings) ? bindings : [bindings].filter(Boolean);
        return list.map(item => ({
            id: item.UniqVpcId || item.VpcId || "",
            name: item.VpcName || item.UniqVpcId || item.VpcId || "",
            region: item.Region || item.RegionName || "",
        }));
    }

    _tencentRest(action, data) {
        const payload = JSON.stringify(Object.fromEntries(
            Object.entries(data || {}).filter(([, value]) => typeof value !== "undefined")
        ));
        const timestamp = Math.floor(Date.now() / 1000);
        const token = this._tencentSignatureV3(action, payload, timestamp);
        const options = {
            hostname: this.host,
            path: "/",
            method: "POST",
            headers: {
                "Content-Type": "application/json",
                Authorization: token,
                "X-TC-Version": this.version,
                "X-TC-Timestamp": timestamp,
                "X-TC-Action": action,
            },
        };
        return new Promise((resolve, reject) => {
            httpsRequest(options, payload, true).then(res => {
                if (res.Response?.Error) {
                    reject(res.Response.Error.Message);
                    return;
                }
                resolve(res.Response);
            }).catch(e => reject(e));
        });
    }

    _tencentSignatureV3(action, payload, timestamp) {
        const algorithm = "TC3-HMAC-SHA256";
        const date = new Date(timestamp * 1000).toISOString().split("T")[0];
        const canonicalHeaders = `content-type:application/json\nhost:${this.host}\nx-tc-action:${action.toLowerCase()}\n`;
        const signedHeaders = "content-type;host;x-tc-action";
        const hashedPayload = crypto.createHash("sha256").update(payload).digest("hex");
        const canonicalRequest = `POST\n/\n\n${canonicalHeaders}\n${signedHeaders}\n${hashedPayload}`;
        const credentialScope = `${date}/${this.service}/tc3_request`;
        const stringToSign = `${algorithm}\n${timestamp}\n${credentialScope}\n${crypto.createHash("sha256").update(canonicalRequest).digest("hex")}`;
        const secretDate = crypto.createHmac("sha256", `TC3${this.secretKey}`).update(date).digest();
        const secretService = crypto.createHmac("sha256", secretDate).update(this.service).digest();
        const secretSigning = crypto.createHmac("sha256", secretService).update("tc3_request").digest();
        const signature = crypto.createHmac("sha256", secretSigning).update(stringToSign).digest("hex");
        return `${algorithm} Credential=${this.secretId}/${credentialScope}, SignedHeaders=${signedHeaders}, Signature=${signature}`;
    }
}

export default TencentPrivateDnsService;
