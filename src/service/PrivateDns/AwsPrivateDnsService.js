import {httpsRequestWithResponseHeader} from "@/utils/http";

const crypto = preload.crypto;

class AwsPrivateDnsService {
    constructor(accessKeyId, secretAccessKey) {
        this.accessKeyId = accessKeyId;
        this.secretAccessKey = secretAccessKey;
        this.host = "route53.amazonaws.com";
    }

    async listZones() {
        const response = preload.xml2Json(await this._awsRest("GET", "2013-04-01/hostedzone", "maxitems=100"), ["HostedZone"]);
        let zones = response?.ListHostedZonesResponse?.HostedZones?.HostedZone || [];
        zones = Array.isArray(zones) ? zones : [zones].filter(Boolean);
        return zones.filter(item => this._isPrivate(item)).map(item => ({
            zone_id: item.Id,
            zone_name: (item.Name || "").replace(/\.$/, ""),
            cloud: "aws",
            record_count: Number(item.ResourceRecordSetCount || 0),
            vpc_bindings: [],
            remark: item.Config?.Comment || "",
            status: "PRIVATE",
        }));
    }

    async createZone({name, vpcId, vpcRegion}) {
        if (!vpcId || !vpcRegion) {
            throw new Error("AWS 创建 Private Hosted Zone 必须指定 VPC ID 和 VPC Region；当前版本仅支持拉取已有私有 Zone 后管理记录。");
        }
        const xmlPayload = `<CreateHostedZoneRequest xmlns="https://route53.amazonaws.com/doc/2013-04-01/">
            <Name>${this._escapeXml(name)}</Name>
            <VPC>
                <VPCId>${this._escapeXml(vpcId)}</VPCId>
                <VPCRegion>${this._escapeXml(vpcRegion)}</VPCRegion>
            </VPC>
            <CallerReference>${Date.now()}</CallerReference>
            <HostedZoneConfig>
                <PrivateZone>true</PrivateZone>
            </HostedZoneConfig>
        </CreateHostedZoneRequest>`;
        const response = preload.xml2Json(await this._awsRest("POST", "2013-04-01/hostedzone", "", xmlPayload));
        const zone = response?.CreateHostedZoneResponse?.HostedZone || {};
        return {
            zone_id: zone.Id,
            zone_name: (zone.Name || name).replace(/\.$/, ""),
            cloud: "aws",
            record_count: Number(zone.ResourceRecordSetCount || 0),
            vpc_bindings: this._normalizeVpcBindings(response?.CreateHostedZoneResponse?.VPC || zone.VPC || []),
            remark: zone.Config?.Comment || "",
            status: "PRIVATE",
        };
    }

    async deleteZone(zone) {
        return this._awsRest("DELETE", `2013-04-01${zone.zone_id}`);
    }

    async listVpcBindings(zone) {
        const response = preload.xml2Json(await this._awsRest("GET", `2013-04-01${zone.zone_id}`), ["VPC"]);
        const hostedZone = response?.GetHostedZoneResponse || {};
        return this._normalizeVpcBindings(hostedZone.VPCs?.VPC || hostedZone.VPC || []);
    }

    async listRecords(zone, options = {}) {
        const page = Math.max(parseInt(options.page || 1, 10), 1);
        const pageSize = Math.max(parseInt(options.pageSize || 20, 10), 1);
        const response = preload.xml2Json(await this._awsRest("GET", `2013-04-01${zone.zone_id}/rrset`, "maxitems=500"), ["ResourceRecordSet"]);
        let records = response.ListResourceRecordSetsResponse?.ResourceRecordSets?.ResourceRecordSet || [];
        records = Array.isArray(records) ? records : [records].filter(Boolean);
        const start = (page - 1) * pageSize;
        const pageRecords = records.slice(start, start + pageSize);
        return {
            count: records.length,
            page,
            pageSize,
            hasMore: start + pageRecords.length < records.length,
            searchedAll: true,
            list: pageRecords.map(record => this._recordToModel(record, zone.zone_name)),
        };
    }

    async addRecord(zone, param) {
        const name = param.name === "@" ? zone.zone_name : `${param.name}.${zone.zone_name}`;
        const targetValue = param.type === "TXT" ? `"${param.value}"` : param.value;
        const ttl = param.ttl || 300;
        const xmlPayload = this._changeRecordXml("UPSERT", {
            name,
            type: param.type,
            ttl,
            values: [targetValue],
        });
        return this._awsRest("POST", `2013-04-01${zone.zone_id}/rrset/`, "", xmlPayload);
    }

    async updateRecord(zone, record) {
        if (this._recordIdentityChanged(zone, record)) {
            await this.deleteRecord(zone, record.id, record.originRecord);
        }
        return this.addRecord(zone, record);
    }

    async deleteRecord(zone, id, record) {
        const targetRecord = record || {};
        const name = targetRecord.Name === "@" ? `${zone.zone_name}.` : `${targetRecord.Name}.${zone.zone_name}.`;
        const values = (targetRecord.Value || "").split("\n").filter(Boolean).map(value => targetRecord.Type === "TXT" && !value.startsWith("\"") ? `"${value}"` : value);
        const xmlPayload = this._changeRecordXml("DELETE", {
            name,
            type: targetRecord.Type,
            ttl: targetRecord.TTL || 300,
            values,
        });
        return this._awsRest("POST", `2013-04-01${zone.zone_id}/rrset/`, "", xmlPayload);
    }

    _isPrivate(item) {
        const value = item.Config?.PrivateZone;
        return value === true || value === "true";
    }

    _recordIdentityChanged(zone, record) {
        const origin = record.originRecord;
        if (!origin) {
            return false;
        }
        const nextName = record.name === "@" ? zone.zone_name : `${record.name}.${zone.zone_name}`;
        const oldName = origin.Name === "@" ? zone.zone_name : `${origin.Name}.${zone.zone_name}`;
        return nextName !== oldName || record.type !== origin.Type;
    }

    _recordToModel(record, zoneName) {
        let values = record.ResourceRecords?.ResourceRecord || [];
        values = Array.isArray(values) ? values : [values].filter(Boolean);
        const value = values.map(item => item.Value).join("\n").replace(/^"|"$/g, "");
        const fqdn = (record.Name || "").replace(/\.$/, "");
        let name = fqdn === zoneName ? "@" : fqdn.replace(new RegExp(`\\.${zoneName.replace(/\./g, "\\.")}$`), "");
        return {
            RecordId: `${record.Name}##${record.Type}##${record.TTL}##${value}`,
            Remark: "",
            Name: name || "@",
            Type: record.Type,
            TTL: Number(record.TTL || 300),
            Value: value,
            Status: true,
            StatusText: "启用",
            RecordLine: "默认",
            CreatedAt: "",
            UpdatedAt: "",
        };
    }

    _changeRecordXml(action, record) {
        const values = record.values.map(value => `<ResourceRecord><Value>${this._escapeXml(value)}</Value></ResourceRecord>`).join("");
        return `<ChangeResourceRecordSetsRequest xmlns="https://route53.amazonaws.com/doc/2013-04-01/">
            <ChangeBatch>
                <Changes>
                    <Change>
                        <Action>${action}</Action>
                        <ResourceRecordSet>
                            <Name>${this._escapeXml(record.name)}</Name>
                            <Type>${record.type}</Type>
                            <TTL>${record.ttl}</TTL>
                            <ResourceRecords>${values}</ResourceRecords>
                        </ResourceRecordSet>
                    </Change>
                </Changes>
            </ChangeBatch>
        </ChangeResourceRecordSetsRequest>`;
    }

    async _awsRest(method, endpoint, queryString = "", data = null) {
        const requestDate = new Date().toISOString().replace(/[:-]|\.\d{3}/g, "");
        const date = requestDate.slice(0, 8);
        const canonicalUri = `/${endpoint}`;
        const canonicalHeaders = `host:${this.host}\nx-amz-date:${requestDate}\n`;
        const signedHeaders = "host;x-amz-date";
        const payloadHash = this._hash(data || "");
        const canonicalRequest = `${method}\n${canonicalUri}\n${queryString}\n${canonicalHeaders}\n${signedHeaders}\n${payloadHash}`;
        const credentialScope = `${date}/us-east-1/route53/aws4_request`;
        const stringToSign = `AWS4-HMAC-SHA256\n${requestDate}\n${credentialScope}\n${this._hash(canonicalRequest)}`;
        const signingKey = this._getSignatureKey(this.secretAccessKey, date, "us-east-1", "route53");
        const signature = this._hmac(signingKey, stringToSign, "hex");
        const options = {
            hostname: this.host,
            path: `/${endpoint}${queryString ? `?${queryString}` : ""}`,
            method,
            headers: {
                "Content-Type": "application/xml",
                "x-amz-date": requestDate,
                Authorization: `AWS4-HMAC-SHA256 Credential=${this.accessKeyId}/${credentialScope}, SignedHeaders=${signedHeaders}, Signature=${signature}`,
            },
        };
        const {data: resData, statusCode} = await httpsRequestWithResponseHeader(options, data);
        if (statusCode >= 400) {
            throw new Error(JSON.stringify(preload.xml2Json(resData)));
        }
        return this._unescapeDns(resData || "");
    }

    _escapeXml(value) {
        return String(value || "")
            .replace(/&/g, "&amp;")
            .replace(/</g, "&lt;")
            .replace(/>/g, "&gt;")
            .replace(/"/g, "&quot;")
            .replace(/'/g, "&apos;");
    }

    _unescapeDns(input) {
        return input.replace(/\\(\d{3})/g, (match, octal) => String.fromCharCode(parseInt(octal, 8)));
    }

    _normalizeVpcBindings(bindings) {
        const list = Array.isArray(bindings) ? bindings : [bindings].filter(Boolean);
        return list.map(item => ({
            id: item.VPCId || "",
            name: item.VPCId || "",
            region: item.VPCRegion || "",
        }));
    }

    _hash(data) {
        return crypto.createHash("sha256").update(data).digest("hex");
    }

    _hmac(key, data, encoding) {
        return crypto.createHmac("sha256", key).update(data).digest(encoding);
    }

    _getSignatureKey(key, date, region, service) {
        const kDate = this._hmac(`AWS4${key}`, date);
        const kRegion = this._hmac(kDate, region);
        const kService = this._hmac(kRegion, service);
        return this._hmac(kService, "aws4_request");
    }
}

export default AwsPrivateDnsService;
