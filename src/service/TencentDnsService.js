const crypto = window.xcrypto;
import {httpsRequest} from '@/utils/http';


/**通用list列表
 *
 * Type 解析类型
 * Name 主机记录
 * Value 记录值
 * TTL TTL
 * Weight 权重
 * MX
 * Status 状态
 * UpdatedOn 更新时间
 *
 */
// 文档 https://cloud.tencent.com/document/product/1427/56180
const renewLink = "https://console.cloud.tencent.com/domain/all-domain/all"

class TencentDnsService {
    constructor(secretId, secretKey) {
        this.secretId = secretId;
        this.secretKey = secretKey;
    }

    async listDomains() {
        const action = "DescribeDomainList";
        const payload = JSON.stringify({Limit: 3000});
        let myDomainList = [];
        try {
            const {DomainSet} = await this._tencentRestDomain("DescribeDomainNameList", JSON.stringify({Limit: 100}));
            myDomainList = DomainSet;
        } catch (e) {
            console.error('Error fetching domain names:', e);
        }

        try {
            const r = await this._tencentRest(action, payload);
            return r.DomainList.filter(item => item.Status === "ENABLE" && item.DNSStatus === "").map(item => {
                console.log("myDomainList", myDomainList);
                let expire_time = "";
                if (myDomainList.length && myDomainList.some(domain => domain.DomainName === item.Name)) {
                    expire_time = myDomainList.find(domain => domain.DomainName === item.Name).ExpirationDate;
                }
                return {
                    domain: item.Name,
                    cloud: "tencent",
                    expire_time: expire_time,
                    renew_link: expire_time ? renewLink : ""
                };
            });
        } catch (e) {
            console.error('Error fetching domains:', e);
            throw e;
        }
    }

    async listRecords(domain) {
        const action = 'DescribeRecordList';
        const payload = JSON.stringify({Domain: domain, Limit: 3000});
        return new Promise((resolve, reject) => {
            this._tencentRest(action, payload).then(r => {
                let res = {
                    count: r.RecordCountInfo.TotalCount,
                    list: r.RecordList.map(item => {
                        return {
                            RecordId: item.RecordId,
                            Name: item.Name,
                            Weight: item.Weight,
                            Value: item.Value,
                            TTL: item.TTL,
                            Type: item.Type,
                            Status: item.Status === "ENABLE",
                            UpdatedOn: item.UpdatedOn,
                            Remark: item.Remark,
                            MX: item.MX,
                            RecordLine: item.Line
                        }
                    })
                }
                resolve(res);
            }).catch(e => {
                reject(e);
            });
        })
    }

    async addRecord(domain, record) {
        const action = 'CreateRecord';
        let formData = {
            Domain: domain,
            SubDomain: record.name,
            RecordType: record.type,
            RecordLine: '默认',
            Value: record.value,
            Remark: record.remark,
            TTL: record.ttl || 600,
        };
        if (record.type === "MX") {
            formData.MX = record.mx;
        }
        const payload = JSON.stringify(formData);
        return this._tencentRest(action, payload);
    }

    async updateRecord(domain, record) {

        const oldRecord = (await this.listRecords(domain)).list.find(item => item.RecordId === record.id);
        const action = 'ModifyRecord';

        let formData = {
            Domain: domain,
            SubDomain: record.name,
            RecordId: record.id,
            RecordType: record.type,
            RecordLine: oldRecord.RecordLine,
            Value: record.value,
            Remark: record.remark,
            TTL: record.ttl || 600,
        }
        if (record.type === "MX") {
            formData.MX = record.mx;
        }
        const payload = JSON.stringify(formData);
        return this._tencentRest(action, payload);
    }

    async deleteRecord(domain, recordId) {
        const action = 'DeleteRecord';
        const payload = JSON.stringify({Domain: domain, RecordId: recordId});
        return this._tencentRest(action, payload);
    }

    _tencentRest(action, payload) {
        const service = 'dnspod';
        const timestamp = Math.floor(Date.now() / 1000);
        const version = '2021-03-23';
        const token = this._tencentSignatureV3(service, action, payload, timestamp);

        const options = {
            hostname: 'dnspod.tencentcloudapi.com',
            path: '/',
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': token,
                'X-TC-Version': version,
                'X-TC-Timestamp': timestamp,
                'X-TC-Action': action
            }
        };
        return new Promise((resolve, reject) => {
            httpsRequest(options, payload, true).then(res => {
                if (res.Response.Error) {
                    reject(res.Response.Error.Message);
                }
                resolve(res.Response);
            }).catch(e => {
                reject(e);
            });
        })
    }


    _tencentRestDomain(action, payload) {
        const service = 'domain';
        const timestamp = Math.floor(Date.now() / 1000);
        const version = '2018-08-08';
        const token = this._tencentSignatureV3(service, action, payload, timestamp);

        const options = {
            hostname: 'domain.tencentcloudapi.com',
            path: '/',
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': token,
                'X-TC-Version': version,
                'X-TC-Timestamp': timestamp,
                'X-TC-Action': action
            }
        };
        return new Promise((resolve, reject) => {
            httpsRequest(options, payload, true).then(res => {
                if (res.Response.Error) {
                    reject(res.Response.Error.Message);
                }
                resolve(res.Response);
            }).catch(e => {
                reject(e);
            });
        })
    }

    _tencentSignatureV3(service, action, payload, timestamp) {
        const algorithm = 'TC3-HMAC-SHA256';
        const date = new Date(timestamp * 1000).toISOString().split('T')[0];
        const canonicalUri = '/';
        const canonicalQuery = '';
        const canonicalHeaders = `content-type:application/json\nhost:${service}.tencentcloudapi.com\nx-tc-action:${action.toLowerCase()}\n`;
        const signedHeaders = 'content-type;host;x-tc-action';
        const hashedPayload = crypto.createHash('sha256').update(payload).digest('hex');
        const canonicalRequest = `POST\n${canonicalUri}\n${canonicalQuery}\n${canonicalHeaders}\n${signedHeaders}\n${hashedPayload}`;
        const credentialScope = `${date}/${service}/tc3_request`;
        const stringToSign = `${algorithm}\n${timestamp}\n${credentialScope}\n${crypto.createHash('sha256').update(canonicalRequest).digest('hex')}`;

        const secretDate = crypto.createHmac('sha256', `TC3${this.secretKey}`).update(date).digest();
        const secretService = crypto.createHmac('sha256', secretDate).update(service).digest();
        const secretSigning = crypto.createHmac('sha256', secretService).update('tc3_request').digest();
        const signature = crypto.createHmac('sha256', secretSigning).update(stringToSign).digest('hex');

        return `${algorithm} Credential=${this.secretId}/${credentialScope}, SignedHeaders=${signedHeaders}, Signature=${signature}`;
    }

    async changeRecordStatus(domain, recordId, extra = {}) {
        const action = 'ModifyRecordStatus';
        const payload = JSON.stringify({
            Domain: domain,
            RecordId: recordId,
            Status: extra.Status ? "ENABLE" : "DISABLE"
        });
        return this._tencentRest(action, payload);
    }
}

export default TencentDnsService;