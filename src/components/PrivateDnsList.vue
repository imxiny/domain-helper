<script setup>
import {computed, h, onMounted, reactive, ref} from "vue";
import {message, Modal, notification, theme} from "ant-design-vue";
import {BarsOutlined, CloudDownloadOutlined, CopyOutlined, DeleteOutlined, PlusOutlined, SyncOutlined} from "@ant-design/icons-vue";
import {deletePrivateZoneDb, getAllAccount, getAllPrivateZones, savePrivateZone, xcopyText} from "@/utils/tool";
import {getPrivateDnsService} from "@/service/PrivateDnsService";
import PrivateDnsRecords from "@/components/PrivateDnsRecords.vue";

const supportedClouds = ["ali", "tencent", "aws", "huawei", "volcengine"];
const {useToken} = theme;
const {token} = useToken();
const zones = ref([]);
const accounts = ref([]);
const recordsDrawerVisible = ref(false);
const currentZone = ref(null);
const createOpen = ref(false);
const createLoading = ref(false);
const syncOpen = ref(false);
const syncLoading = ref(false);
const refreshLoading = ref(false);
const form = reactive({
    account_key: undefined,
    zone_name: "",
});
const syncForm = reactive({
    account_key: undefined,
});
const searchForm = reactive({
    cloud: undefined,
    account: undefined,
    keyword: "",
});

const refresh = () => {
    accounts.value = getAllAccount().filter(item => supportedClouds.includes(item.cloud_key));
    zones.value = getAllPrivateZones();
};

onMounted(refresh);

const accountOptions = computed(() => accounts.value.map(item => ({
    value: item._id,
    label: `${item.cloud_info.title}-${item.tag}`,
    account: item,
})));

const filteredZones = computed(() => {
    const keyword = searchForm.keyword.toString().toLowerCase();
    return zones.value.filter(item => {
        const matchCloud = !searchForm.cloud || item.cloud === searchForm.cloud;
        const matchAccount = !searchForm.account || item.account_key === searchForm.account;
        const matchKeyword = !keyword || item.zone_name.toLowerCase().includes(keyword);
        return matchCloud && matchAccount && matchKeyword;
    });
});

const getAccount = accountKey => accounts.value.find(item => item._id === accountKey);

const normalizeAndSaveZone = (zone, account) => {
    const nextZone = {
        ...zone,
        cloud: account.cloud_key,
        account_key: account._id,
        vpc_bindings: zone.vpc_bindings || [],
    };
    savePrivateZone(nextZone);
    return nextZone;
};

const fillZoneRecordCount = async (dns, zone) => {
    if (typeof zone.record_count !== "undefined") {
        return zone;
    }
    try {
        const res = await dns.listRecords(zone, {page: 1, pageSize: 20});
        return {
            ...zone,
            record_count: Number(res.count || 0),
        };
    } catch (e) {
        return zone;
    }
};

const syncAccountZones = async account => {
    const dns = getPrivateDnsService(account._id, account.cloud_key, account.tokens, true);
    const remoteZones = await dns.listZones();
    const zonesWithRecordCount = await Promise.all(remoteZones.map(zone => fillZoneRecordCount(dns, zone)));
    zonesWithRecordCount.forEach(zone => normalizeAndSaveZone(zone, account));
    return zonesWithRecordCount;
};

const openSync = () => {
    syncForm.account_key = undefined;
    syncOpen.value = true;
};

const handleSync = async () => {
    const selectedAccounts = syncForm.account_key ? [getAccount(syncForm.account_key)] : accounts.value;
    if (!selectedAccounts.length || selectedAccounts.some(item => !item)) {
        message.error("请选择可用账号");
        return;
    }
    syncLoading.value = true;
    const results = {success: 0, failed: []};
    for (const account of selectedAccounts) {
        try {
            const remoteZones = await syncAccountZones(account);
            results.success += remoteZones.length;
        } catch (e) {
            results.failed.push(`${account.cloud_info.title}-${account.tag}: ${e.toString()}`);
        }
    }
    syncLoading.value = false;
    syncOpen.value = false;
    refresh();
    if (results.success > 0) {
        message.success(`成功拉取 ${results.success} 个私有 Zone`);
    }
    if (results.failed.length) {
        notification.error({
            message: "部分账号拉取失败",
            description: results.failed.join("\n"),
            duration: 10,
        });
    }
};

const refreshRemoteZones = async () => {
    if (!zones.value.length) {
        refresh();
        return;
    }
    refreshLoading.value = true;
    const accountKeys = [...new Set(zones.value.map(zone => zone.account_key))];
    const results = {success: 0, failed: []};
    for (const accountKey of accountKeys) {
        const account = getAccount(accountKey);
        if (!account) {
            continue;
        }
        try {
            const remoteZones = await syncAccountZones(account);
            results.success += remoteZones.length;
        } catch (e) {
            results.failed.push(`${account.cloud_info.title}-${account.tag}: ${e.toString()}`);
        }
    }
    refreshLoading.value = false;
    refresh();
    if (results.success > 0) {
        message.success("私有解析列表已刷新");
    }
    if (results.failed.length) {
        notification.error({
            message: "部分账号刷新失败",
            description: results.failed.join("\n"),
            duration: 10,
        });
    }
};

const openCreate = () => {
    form.account_key = undefined;
    form.zone_name = "";
    createOpen.value = true;
};

const handleCreate = async () => {
    const account = getAccount(form.account_key);
    if (!account) {
        message.error("请选择云平台账号");
        return;
    }
    if (["aws", "huawei"].includes(account.cloud_key)) {
        message.warning(`${account.cloud_info.title} 创建私有 Zone 需要绑定 VPC，请先在云控制台创建后再拉取。`);
        return;
    }
    if (!form.zone_name.trim()) {
        message.error("请输入 Zone 名称");
        return;
    }
    createLoading.value = true;
    try {
        const dns = getPrivateDnsService(account._id, account.cloud_key, account.tokens, true);
        const zone = await dns.createZone({name: form.zone_name.trim()});
        normalizeAndSaveZone(zone, account);
        message.success(`创建私有 Zone ${form.zone_name} 成功`);
        createOpen.value = false;
        refresh();
    } catch (e) {
        notification.error({
            message: "创建私有 Zone 失败",
            description: e.toString(),
            duration: 10,
        });
    } finally {
        createLoading.value = false;
    }
};

const chooseZone = zone => {
    currentZone.value = zone;
    recordsDrawerVisible.value = true;
};

const removeLocalZone = zone => {
    Modal.confirm({
        title: "从域名助手中移除",
        content: h("div", null, [
            h("p", null, [
                "确认将 ",
                h("span", {style: {color: token.value.colorPrimary, fontWeight: 500}}, zone.zone_name),
                " 从当前工具的私有解析列表中移除吗？",
            ]),
            h("p", {style: {marginBottom: 0, color: token.value.colorTextSecondary}}, "该操作只删除域名助手本地保存的列表记录，不会删除云厂商上的私有 Zone，也不会删除任何解析记录。"),
        ]),
        okText: "从列表移除",
        cancelText: "取消",
        okButtonProps: {danger: true},
        onOk: () => {
            deletePrivateZoneDb(zone);
            message.success("已从域名助手列表中移除");
            refresh();
        },
    });
};

const refreshZoneAccount = zone => {
    syncAccountZones(zone.account_info).then(() => {
        refresh();
        message.success("私有 Zone 已刷新");
    }).catch(e => {
        notification.error({
            message: "刷新私有 Zone 失败",
            description: e.toString(),
            duration: 10,
        });
    });
};

</script>

<template>
    <div class="private-zone-page">
        <div class="header" :style="{backgroundColor: token.colorBgElevated}">
            <a-space>
                <div class="title" :style="{color: token.colorText}">私有解析</div>
                <div class="desc" :style="{color: token.colorTextTertiary}">管理内网私有 Zone 与解析记录</div>
            </a-space>
            <a-space>
                <a-input-search v-model:value="searchForm.keyword" placeholder="搜索 Zone" style="width: 180px" allow-clear></a-input-search>
                <a-select v-model:value="searchForm.cloud" placeholder="云厂商" style="width: 120px" allow-clear>
                    <a-select-option value="ali">阿里云</a-select-option>
                    <a-select-option value="tencent">腾讯云</a-select-option>
                    <a-select-option value="aws">AWS</a-select-option>
                    <a-select-option value="huawei">华为云</a-select-option>
                    <a-select-option value="volcengine">火山引擎</a-select-option>
                </a-select>
                <a-select v-model:value="searchForm.account" placeholder="账号" style="width: 160px" allow-clear>
                    <a-select-option v-for="item in accountOptions" :key="item.value" :value="item.value">{{ item.label }}</a-select-option>
                </a-select>
                <a-divider type="vertical"/>
                <a-tooltip title="拉取私有 Zone">
                    <a-button :icon="h(CloudDownloadOutlined)" @click="openSync"></a-button>
                </a-tooltip>
                <a-tooltip title="刷新私有 Zone">
                    <a-button :icon="h(SyncOutlined)" :loading="refreshLoading" @click="refreshRemoteZones"></a-button>
                </a-tooltip>
                <a-button type="primary" :icon="h(PlusOutlined)" @click="openCreate">创建 Zone</a-button>
            </a-space>
        </div>

        <div v-if="filteredZones.length" class="cards">
            <a-card v-for="zone in filteredZones" :key="zone._id" size="small" hoverable @click="chooseZone(zone)">
                <template #title>
                    <a-flex class="card-title" justify="space-between" align="center" gap="10">
                        <a-space>
                            <img :src="zone.cloud_info.icon" alt="" style="height: 17px"/>
                            <a-typography-text v-if="zone.cloud_info.name">{{ zone.cloud_info.name }}</a-typography-text>
                        </a-space>
                        <span class="account-tag">{{ zone.account_info.tag }}</span>
                    </a-flex>
                </template>
                <div class="private-zone-card-body">
                    <div class="private-info-row">
                        <div class="zone-name-wrapper">
                            <span class="zone-name">{{ zone.zone_name }}</span>
                            <CopyOutlined @click.stop="xcopyText(zone.zone_name)" class="copy-btn"/>
                        </div>
                    </div>
                    <div class="private-info-row record-count-row">
                        <span class="label">记录数</span>
                        <span class="value">{{ zone.record_count || 0 }}</span>
                    </div>
                </div>
                <template #actions>
                    <a-tooltip title="从域名助手列表移除，不删除云上私有 Zone">
                        <DeleteOutlined @click.stop="removeLocalZone(zone)" key="delete"/>
                    </a-tooltip>
                    <a-tooltip title="复制 Zone 名称">
                        <CopyOutlined @click.stop="xcopyText(zone.zone_name)" key="copy"/>
                    </a-tooltip>
                    <a-tooltip title="拉取并刷新该账号私有 Zone">
                        <CloudDownloadOutlined @click.stop="refreshZoneAccount(zone)" key="sync"/>
                    </a-tooltip>
                    <a-tooltip title="解析记录">
                        <BarsOutlined key="records"/>
                    </a-tooltip>
                </template>
            </a-card>
        </div>

        <a-empty v-else style="margin-top: 20vh;">
            <template #description>
                <p :style="{color: token.colorTextTertiary}">{{ zones.length ? '未找到匹配的私有 Zone' : '暂未添加私有 Zone' }}</p>
                <a-space>
                    <a-button @click="openSync">拉取私有 Zone</a-button>
                    <a-button type="primary" @click="openCreate">创建 Zone</a-button>
                </a-space>
            </template>
        </a-empty>

        <a-modal v-model:open="syncOpen" title="拉取私有 Zone" :confirm-loading="syncLoading" @ok="handleSync" ok-text="拉取" cancel-text="取消" width="420px">
            <a-form layout="vertical">
                <a-form-item label="云平台账号">
                    <a-select v-model:value="syncForm.account_key" placeholder="不选择则拉取所有支持的账号" allow-clear>
                        <a-select-option v-for="item in accountOptions" :key="item.value" :value="item.value">{{ item.label }}</a-select-option>
                    </a-select>
                </a-form-item>
            </a-form>
        </a-modal>

        <a-modal v-model:open="createOpen" title="创建私有 Zone" :confirm-loading="createLoading" @ok="handleCreate" ok-text="创建" cancel-text="取消" width="420px">
            <a-form layout="vertical">
                <a-form-item label="云平台账号">
                    <a-select v-model:value="form.account_key" placeholder="请选择支持私有解析的账号">
                        <a-select-option v-for="item in accountOptions" :key="item.value" :value="item.value">{{ item.label }}</a-select-option>
                    </a-select>
                </a-form-item>
                <a-form-item label="Zone 名称">
                    <a-input v-model:value="form.zone_name" placeholder="例如 corp.local 或 internal.example.com"></a-input>
                </a-form-item>
                <a-alert v-if="['aws', 'huawei'].includes(getAccount(form.account_key)?.cloud_key)" type="warning" show-icon message="该云厂商创建私有 Zone 需要同时绑定 VPC。当前版本不在应用内管理 VPC 绑定，请先在云控制台创建后再拉取。" />
            </a-form>
        </a-modal>

        <a-drawer v-model:open="recordsDrawerVisible" :closable="false" :width="'100vw'" placement="right" :destroyOnClose="true" :bodyStyle="{padding: 0}">
            <PrivateDnsRecords v-if="recordsDrawerVisible" :zone-info="currentZone" @close="recordsDrawerVisible = false"></PrivateDnsRecords>
        </a-drawer>
    </div>
</template>

<style scoped lang="scss">
.private-zone-page {
    height: 100vh;
    display: flex;
    flex-direction: column;
    overflow: hidden;
}

.header {
    height: 60px;
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 0 16px;
    border-bottom: 1px dashed v-bind("token.colorBorder");
    flex-shrink: 0;
}

.title {
    font-size: 20px;
    font-weight: 500;
}

.desc {
    font-size: 12px;
}

.cards {
    padding: 16px;
    height: calc(100vh - 60px);
    overflow: auto;
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
    grid-auto-rows: 182px;
    gap: 16px;
    max-width: 100%;
    justify-content: center;

    &:has(> :only-child) {
        display: flex;
        justify-content: flex-start;
        align-items: flex-start;

        :deep(.ant-card) {
            width: 45%;
            height: 182px;
            flex-shrink: 0;
        }
    }

    @media screen and (max-width: 1000px) {
        grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
    }

    :deep(.ant-card-actions) {
        background: transparent;
    }
}

.card-title {
    height: 50px;
    padding: 10px 0;
}

.account-tag {
    font-size: 12px;
    padding: 1px 8px;
    border-radius: 4px;
    border: 1px solid v-bind("token.colorBorder");
    color: v-bind("token.colorTextSecondary");
    background: v-bind("token.colorBgContainer");
    flex-shrink: 0;
}

.private-zone-card-body {
    display: flex;
    flex-direction: column;
    justify-content: space-evenly;
    padding: 0 10px;
    width: 100%;
}

.private-info-row {
    display: flex;
    align-items: center;
    justify-content: space-between;
    width: 100%;
}

.zone-name-wrapper {
    display: flex;
    align-items: center;
    justify-content: space-between;
    width: 100%;
    gap: 8px;
}

.zone-name {
    min-width: 0;
    flex: 1;
    font-size: 16px;
    font-weight: 500;
    color: v-bind("token.colorText");
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
}

.copy-btn {
    width: 24px;
    height: 24px;
    display: flex;
    align-items: center;
    justify-content: center;
    color: v-bind("token.colorTextSecondary");
    cursor: pointer;
    flex-shrink: 0;

    &:hover {
        color: v-bind("token.colorPrimary");
    }
}

.record-count-row {
    height: 30px;
}

.label {
    font-size: 12px;
    color: v-bind("token.colorTextLabel");
    flex-shrink: 0;
}

.value {
    margin-left: 10px;
    color: v-bind("token.colorTextSecondary");
}
</style>
