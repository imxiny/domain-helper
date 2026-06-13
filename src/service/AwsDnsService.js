import {httpsRequestWithResponseHeader} from '@/utils/http';
import {containsAnySubstring, getDnsServer, getDomain} from "@/utils/tool";

const crypto = preload.crypto

// 文档地址 https://docs.aws.amazon.com/Route53/latest/APIReference/API_ListHostedZones.html

class AwsDnsService {
    constructor(accessKeyId, secretAccessKey) {
        this.accessKeyId = accessKeyId;
        this.secretAccessKey = secretAccessKey;
        this.host = 'route53.amazonaws.com';
        this.apiBase = `https://${this.host}`;
        this.dnsServer = ["awsdns"]
    }

    async listDomains() {
        let response = await this._awsRest('GET', '2013-04-01/hostedzone', "maxitems=100");
        response = preload.xml2Json(response, ['HostedZone'])
        const zones = response?.ListHostedZonesResponse?.HostedZones?.HostedZone || [];
        return (await Promise.all(zones.map(async item => {
            const domain = item.Name.slice(0, -1);
            try {
                const {nsname} = await getDnsServer(domain);
                return containsAnySubstring(this.dnsServer, nsname) ? {
                    domain: domain,
                    cloud: "aws",
                    zone_id: item.Id
                } : null;
            } catch (e) {
                return {
                    domain: domain,
                    cloud: "aws",
                    zone_id: item.Id
                };
            }
        }))).filter(zone => zone !== null);
    }

    async listRecords(domain, options = {}) {
        const hasOptions = Object.keys(options).length > 0;
        const page = Math.max(parseInt(options.page || 1, 10), 1);
        const pageSize = Math.max(parseInt(options.pageSize || (hasOptions ? 20 : 500), 10), 1);
        const {zone_id} = getDomain("aws/" + domain);
        const response = preload.xml2Json(await this._awsRest('GET', `2013-04-01${zone_id}/rrset`, "maxitems=500"), ['ResourceRecordSet'])
        let records = response.ListResourceRecordSetsResponse.ResourceRecordSets.ResourceRecordSet;
        if (!Array.isArray(records)) {
            records = records ? [records] : [];
        }
        const start = (page - 1) * pageSize;
        const pageRecords = records.slice(start, start + pageSize);
        return {
            count: records.length,
            page,
            pageSize,
            hasMore: start + pageRecords.length < records.length,
            searchedAll: true,
            list: pageRecords.map(record => {
                const value = record.ResourceRecords.ResourceRecord.Value ? record.ResourceRecords.ResourceRecord.Value : record.ResourceRecords.ResourceRecord.map(item => item.Value).join('\n');
                return {
                    RecordId: record.Name + "##" + record.Type + "##" + record.TTL + "##" + value,
                    Remark: "",
                    Name: record.Name.slice(0, -(domain.length + 2)) || "@",
                    Type: record.Type,
                    TTL: record.TTL,
                    Value: value,
                }
            })
        }
    }

    async addRecord(domain, param) {
        const targetValue = param.type === "TXT" ? `"${param.value}"` : param.value;
        const fulldomain = param.name === '@' ? domain : `${param.name}.${domain}`
        const {zone_id} = getDomain("aws/" + domain);
        const xmlPayload = `<ChangeResourceRecordSetsRequest xmlns="https://route53.amazonaws.com/doc/2013-04-01/">
            <ChangeBatch>
                <Changes>
                    <Change>
                        <Action>UPSERT</Action>
                        <ResourceRecordSet>
                            <Name>${fulldomain}</Name>
                            <Type>${param.type}</Type>
                            <TTL>300</TTL>
                            <ResourceRecords><ResourceRecord><Value>${targetValue}</Value></ResourceRecord></ResourceRecords>
                        </ResourceRecordSet>
                    </Change>
                </Changes>
            </ChangeBatch>
        </ChangeResourceRecordSetsRequest>`;
        await this._awsRest('POST', `2013-04-01${zone_id}/rrset/`, '', xmlPayload);
    }

    async deleteRecord(domain, id) {

        const zone_id = getDomain("aws/" + domain).zone_id;
        // 获取全部记录
        const {list} = await this.listRecords(domain)
        const record = list.filter(i => i.RecordId === id);
        const fulldomain = `${record[0].Name}.${domain}.`;
        const resourceRecords = record.map(record => `<ResourceRecord><Value>${record.Value}</Value></ResourceRecord>`).join('');
        const xmlPayload = `<ChangeResourceRecordSetsRequest xmlns="https://route53.amazonaws.com/doc/2013-04-01/">
            <ChangeBatch>
                <Changes>
                    <Change>
                        <Action>DELETE</Action>
                        <ResourceRecordSet>
                            <Name>${fulldomain}</Name>
                            <Type>${record[0].Type}</Type>
                            <TTL>${record[0].TTL}</TTL>
                            <ResourceRecords>${resourceRecords}</ResourceRecords>
                        </ResourceRecordSet>
                    </Change>
                </Changes>
            </ChangeBatch>
        </ChangeResourceRecordSetsRequest>`;
        await this._awsRest('POST', `2013-04-01${zone_id}/rrset/`, '', xmlPayload);
    }


    async _awsRest(method, endpoint, queryString = '', data = null) {
        const requestDate = new Date().toISOString().replace(/[:-]|\.\d{3}/g, '');
        const date = requestDate.slice(0, 8);
        const canonicalUri = `/${endpoint}`;
        const canonicalQueryString = queryString;
        const canonicalHeaders = `host:${this.host}\nx-amz-date:${requestDate}\n`;
        const signedHeaders = 'host;x-amz-date';
        const payloadHash = this._hash(data || '');
        const canonicalRequest = `${method}\n${canonicalUri}\n${canonicalQueryString}\n${canonicalHeaders}\n${signedHeaders}\n${payloadHash}`;
        const credentialScope = `${date}/us-east-1/route53/aws4_request`;
        const stringToSign = `AWS4-HMAC-SHA256\n${requestDate}\n${credentialScope}\n${this._hash(canonicalRequest)}`;
        const signingKey = this._getSignatureKey(this.secretAccessKey, date, 'us-east-1', 'route53');
        const signature = this._hmac(signingKey, stringToSign, 'hex');
        const authorizationHeader = `AWS4-HMAC-SHA256 Credential=${this.accessKeyId}/${credentialScope}, SignedHeaders=${signedHeaders}, Signature=${signature}`;

        const options = {
            hostname: this.host,
            path: `/${endpoint}${queryString ? `?${queryString}` : ''}`,
            method,
            headers: {
                'Content-Type': 'application/xml',
                'x-amz-date': requestDate,
                'Authorization': authorizationHeader
            }
        };
        const {data: resData, statusCode} = await httpsRequestWithResponseHeader(options, data)
        if (statusCode >= 400) {
            throw new Error(JSON.stringify(preload.xml2Json(resData)));
        }
        return this.unescapeDns(resData);
    }

    unescapeDns(input) {
        return input.replace(/\\(\d{3})/g, (match, octal) => {
            return String.fromCharCode(parseInt(octal, 8));
        });
    }


    _hash(data) {
        return crypto.createHash('sha256').update(data).digest('hex');
    }

    _hmac(key, data, encoding) {
        return crypto.createHmac('sha256', key).update(data).digest(encoding);
    }

    _getSignatureKey(key, date, region, service) {
        const kDate = this._hmac(`AWS4${key}`, date);
        const kRegion = this._hmac(kDate, region);
        const kService = this._hmac(kRegion, service);
        return this._hmac(kService, 'aws4_request');
    }
}

export default AwsDnsService;
