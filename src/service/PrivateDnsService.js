import AliPrivateDnsService from "./PrivateDns/AliPrivateDnsService.js";
import TencentPrivateDnsService from "./PrivateDns/TencentPrivateDnsService.js";
import AwsPrivateDnsService from "./PrivateDns/AwsPrivateDnsService.js";
import HuaweiPrivateDnsService from "./PrivateDns/HuaweiPrivateDnsService.js";
import VolcenginePrivateDnsService from "./PrivateDns/VolcenginePrivateDnsService.js";

const PRIVATE_DNS_MAP_SERVICE = {};

const PRIVATE_DNS_PROVIDER = {
    ali: AliPrivateDnsService,
    tencent: TencentPrivateDnsService,
    aws: AwsPrivateDnsService,
    huawei: HuaweiPrivateDnsService,
    volcengine: VolcenginePrivateDnsService,
};

function normalizeRecordListOptions(options = {}) {
    const paged = Object.prototype.hasOwnProperty.call(options, "page") ||
        Object.prototype.hasOwnProperty.call(options, "pageSize") ||
        Object.prototype.hasOwnProperty.call(options, "keyword");
    const page = Math.max(parseInt(options.page || 1, 10), 1);
    const pageSize = paged
        ? ([20, 50, 100].includes(parseInt(options.pageSize, 10))
            ? parseInt(options.pageSize, 10)
            : Math.max(parseInt(options.pageSize || 20, 10), 1))
        : 5000;
    return {
        paged,
        page,
        pageSize,
        keyword: (options.keyword || "").toString().trim(),
    };
}

function recordMatchesKeyword(record, keyword) {
    if (!keyword) {
        return true;
    }
    const key = keyword.toLowerCase();
    return [record.Name, record.Value].some(value =>
        (value || "").toString().toLowerCase().includes(key)
    );
}

function sortRecords(list) {
    return (list || []).sort((a, b) => {
        if (a.Type !== b.Type) {
            return a.Type.localeCompare(b.Type);
        }
        return (a.Name || "").localeCompare(b.Name || "");
    });
}

function validateDNSRecord(type, value) {
    if (!type || !value) {
        throw new Error("解析记录类型和记录值不能为空");
    }
    if (type === "A" && !/^(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])(\.(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])){3}$/.test(value)) {
        throw new Error(`Invalid A record: '${value}' is not a valid IPv4 address.`);
    }
    if (type === "AAAA" && !/^(([0-9a-fA-F]{1,4}:){1,7}:|::1|::|([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4})/.test(value)) {
        throw new Error(`Invalid AAAA record: '${value}' is not a valid IPv6 address.`);
    }
    if (type === "TXT" && (typeof value !== "string" || value.length > 1024)) {
        throw new Error(`Invalid TXT record: '${value}' must be a string of at most 1024 characters.`);
    }
}

export function getPrivateDnsService(key, provider, credentials, refresh = false) {
    const cacheKey = `${provider}/${key}`;
    if (refresh) {
        PRIVATE_DNS_MAP_SERVICE[cacheKey] = null;
    }
    if (!PRIVATE_DNS_MAP_SERVICE[cacheKey]) {
        PRIVATE_DNS_MAP_SERVICE[cacheKey] = new PrivateDnsService(provider, credentials);
    }
    return PRIVATE_DNS_MAP_SERVICE[cacheKey];
}

class PrivateDnsService {
    constructor(provider, credentials) {
        if (!PRIVATE_DNS_PROVIDER[provider]) {
            throw new Error("当前云厂商暂不支持私有解析");
        }
        const params = credentials.map(item => item.value);
        this.provider = new PRIVATE_DNS_PROVIDER[provider](...params);
    }

    async listZones(options = {}) {
        return this.provider.listZones(options);
    }

    async createZone(params) {
        return this.provider.createZone(params);
    }

    async deleteZone(zone) {
        return this.provider.deleteZone(zone);
    }

    async listVpcBindings(zone) {
        if (typeof this.provider.listVpcBindings === "function") {
            return this.provider.listVpcBindings(zone);
        }
        return [];
    }

    async listRecords(zone, options = {}) {
        const recordOptions = normalizeRecordListOptions(options);
        let result;
        if (recordOptions.keyword && this.provider.supportsRecordKeywordSearch !== true) {
            result = await this.searchRecordsByPage(zone, recordOptions);
        } else {
            result = await this.provider.listRecords(zone, recordOptions);
        }
        let {count = 0, list = []} = result || {};
        list = sortRecords(list.map(record => ({
            ...record,
            ZoneId: zone.zone_id,
            ZoneName: zone.zone_name,
        })));
        return {
            count,
            list,
            page: result?.page || recordOptions.page,
            pageSize: result?.pageSize || recordOptions.pageSize,
            hasMore: result?.hasMore,
            searchedAll: result?.searchedAll,
        };
    }

    async searchRecordsByPage(zone, options) {
        const {page, pageSize, keyword} = options;
        const targetEnd = page * pageSize;
        const scanPageSize = Math.max(pageSize, 100);
        const matchedRecords = [];
        let scanPage = 1;
        let hasMore = true;
        let searchedAll = false;

        while (hasMore) {
            const result = await this.provider.listRecords(zone, {
                page: scanPage,
                pageSize: scanPageSize,
                keyword: "",
            });
            const list = result?.list || [];
            matchedRecords.push(...list.filter(record => recordMatchesKeyword(record, keyword)));
            const count = Number(result?.count || 0);
            hasMore = typeof result?.hasMore === "boolean"
                ? result.hasMore
                : scanPage * scanPageSize < count;
            if (matchedRecords.length >= targetEnd && hasMore) {
                break;
            }
            if (!hasMore) {
                searchedAll = true;
            }
            scanPage++;
        }

        const sortedRecords = sortRecords(matchedRecords);
        const start = (page - 1) * pageSize;
        const list = sortedRecords.slice(start, start + pageSize);
        return {
            count: searchedAll ? sortedRecords.length : Math.max(targetEnd + 1, sortedRecords.length),
            list,
            page,
            pageSize,
            hasMore: !searchedAll || start + list.length < sortedRecords.length,
            searchedAll,
        };
    }

    async addRecord(zone, record) {
        validateDNSRecord(record.type, record.value);
        return this.provider.addRecord(zone, record);
    }

    async updateRecord(zone, record) {
        validateDNSRecord(record.type, record.value);
        if (typeof this.provider.updateRecord === "function") {
            return this.provider.updateRecord(zone, record);
        }
        await this.deleteRecord(zone, record.id, record);
        return this.addRecord(zone, record);
    }

    supportsRecordRemarkChange() {
        return typeof this.provider.updateRecordRemark === "function" ||
            (this.provider.supportsRecordRemarkUpdate === true && typeof this.provider.updateRecord === "function");
    }

    async updateRecordRemark(zone, record, remark = "") {
        if (typeof this.provider.updateRecordRemark === "function") {
            return this.provider.updateRecordRemark(record.RecordId, remark, zone, record);
        }
        if (this.provider.supportsRecordRemarkUpdate === true && typeof this.provider.updateRecord === "function") {
            return this.provider.updateRecord(zone, {
                id: record.RecordId,
                name: record.Name,
                type: record.Type,
                value: record.Value,
                ttl: record.TTL,
                mx: record.MX,
                remark,
            });
        }
        throw new Error("当前云厂商暂不支持单独修改私有解析记录备注");
    }

    async deleteRecord(zone, recordId, record) {
        return this.provider.deleteRecord(zone, recordId, record);
    }

    supportsRecordStatusChange() {
        return typeof this.provider.changeRecordStatus === "function";
    }

    async changeRecordStatus(zone, recordId, extra = {}) {
        if (typeof this.provider.changeRecordStatus === "function") {
            return this.provider.changeRecordStatus(zone, recordId, extra);
        }
        throw new Error("当前云厂商暂不支持修改私有解析记录状态");
    }
}
