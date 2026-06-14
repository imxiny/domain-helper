<script setup>
import {computed, h, onBeforeUnmount, onMounted, reactive, ref} from "vue";
import {message, Modal, notification, theme} from "ant-design-vue";
import {
    DeleteOutlined,
    EditOutlined,
    FormOutlined,
    PlusOutlined,
    SettingOutlined,
    SyncOutlined,
} from "@ant-design/icons-vue";
import {getPrivateDnsService} from "@/service/PrivateDnsService";
import {RecordTypes} from "@/utils/data";
import AddPrivateDnsRecord from "@/components/AddPrivateDnsRecord.vue";
import {debounce} from "lodash-es";
import {useThemeStore} from "@/stroes/themeStore.js";
import {getAllPrivateZones} from "@/utils/tool";

const props = defineProps({
    zoneInfo: {
        type: Object,
        required: true,
    },
});
const emit = defineEmits(["close"]);
const {useToken} = theme;
const {token} = useToken();
const themeStore = useThemeStore();
const config = computed(() => themeStore.config);
const nowZoneInfo = ref(props.zoneInfo);
const allZones = ref([]);
const records = ref([]);
const loading = ref(false);
const selectedRecords = ref([]);
const selectedRowKeys = ref([]);
const requestKeyword = ref("");
const editingRemarkRecordId = ref("");
const editingRemarkValue = ref("");
const savingRemarkRecordId = ref("");
let recordsRequestId = 0;
const pagination = reactive({
    current: 1,
    pageSize: 20,
    total: 0,
    showSizeChanger: true,
    pageSizeOptions: ["20", "50", "100"],
    showTotal: total => `共 ${total} 条`,
});
const searchForm = reactive({
    type: null,
    status: null,
    keyword: "",
});
const tablePagination = computed(() => ({...pagination}));

const requiredColumnKeys = ["Name", "Type", "Value", "operation"];
const requiredBaseColumnKeys = ["Name", "Type", "Value"];
const defaultColumnKeys = ["Name", "Type", "RecordLine", "Value", "TTL", "Status", "Remark", "CreatedAt", "UpdatedAt", "operation"];
const allColumns = [
    {title: "主机记录", dataIndex: "Name", key: "Name", fixed: "left", align: "center", disabled: true},
    {title: "类型", dataIndex: "Type", key: "Type", width: 90, align: "center", disabled: true},
    {title: "线路", dataIndex: "RecordLine", key: "RecordLine", width: 110, align: "center"},
    {title: "记录值", dataIndex: "Value", key: "Value", align: "center", disabled: true},
    {title: "TTL", dataIndex: "TTL", key: "TTL", align: "center", width: 90},
    {title: "状态", dataIndex: "Status", key: "Status", width: 90, align: "center"},
    {title: "备注", dataIndex: "Remark", key: "Remark", align: "center"},
    {title: "创建时间", dataIndex: "CreatedAt", key: "CreatedAt", width: 170, align: "center"},
    {title: "更新时间", dataIndex: "UpdatedAt", key: "UpdatedAt", width: 170, align: "center"},
    {title: "操作", key: "operation", width: 110, align: "center", disabled: true},
];
const optionalColumnOptions = allColumns.filter(column => !requiredColumnKeys.includes(column.key)).map(column => ({
    label: column.title,
    value: column.key,
}));
const enabledColumnKeys = computed(() => {
    const savedKeys = config.value.privateDnsRecordColumns || defaultColumnKeys;
    return [...new Set([...requiredColumnKeys, ...savedKeys])].filter(key => allColumns.some(column => column.key === key));
});
const optionalEnabledKeys = computed({
    get() {
        return enabledColumnKeys.value.filter(key => !requiredColumnKeys.includes(key));
    },
    set(keys) {
        themeStore.updateConfig({
            privateDnsRecordColumns: [...requiredBaseColumnKeys, ...keys, "operation"],
        });
    }
});
const columns = computed(() => {
    return allColumns.filter(column => enabledColumnKeys.value.includes(column.key));
});
const tableScrollX = computed(() => columns.value.reduce((sum, column) => sum + (column.width || 180), 0));
const statusEditableClouds = ["ali", "tencent", "huawei", "volcengine"];
const statusEditable = computed(() => statusEditableClouds.includes(nowZoneInfo.value?.cloud));
const remarkEditableClouds = ["ali", "tencent", "huawei", "volcengine"];
const remarkEditable = computed(() => remarkEditableClouds.includes(nowZoneInfo.value?.cloud));

const calcRecords = computed(() => {
    if (!searchForm.type && !searchForm.status) {
        return records.value;
    }
    return records.value.filter(item => {
        const matchType = !searchForm.type || item.Type === searchForm.type;
        const matchStatus = !searchForm.status || item.Status === (searchForm.status === "true");
        return matchType && matchStatus;
    });
});

const recordTypeCounts = computed(() => {
    const count = {};
    records.value.forEach(item => {
        count[item.Type] = (count[item.Type] || 0) + 1;
    });
    return count;
});

const refreshAllZones = () => {
    allZones.value = getAllPrivateZones();
};

const padDatePart = value => String(value).padStart(2, "0");

const formatRecordTime = value => {
    if (!value) {
        return "-";
    }
    if (typeof value === "string") {
        const normalized = value.replace("T", " ").replace(/Z$/, "");
        const match = normalized.match(/^(\d{4})-(\d{2})-(\d{2})\s+(\d{2}):(\d{2})(?::(\d{2}))?/);
        if (match) {
            return `${match[1]}-${match[2]}-${match[3]} ${match[4]}:${match[5]}:${match[6] || "00"}`;
        }
    }
    const timestamp = typeof value === "number" || /^\d+$/.test(String(value))
        ? Number(value)
        : Date.parse(value);
    if (Number.isNaN(timestamp)) {
        return String(value);
    }
    const date = new Date(String(timestamp).length === 10 ? timestamp * 1000 : timestamp);
    if (Number.isNaN(date.getTime())) {
        return String(value);
    }
    return [
        date.getFullYear(),
        padDatePart(date.getMonth() + 1),
        padDatePart(date.getDate()),
    ].join("-") + " " + [
        padDatePart(date.getHours()),
        padDatePart(date.getMinutes()),
        padDatePart(date.getSeconds()),
    ].join(":");
};

const refreshRecords = (options = {}) => {
    selectedRecords.value = [];
    selectedRowKeys.value = [];
    if (options.resetPage) {
        pagination.current = 1;
    }
    const requestId = ++recordsRequestId;
    loading.value = true;
    const dns = getPrivateDnsService(nowZoneInfo.value.account_key, nowZoneInfo.value.cloud, nowZoneInfo.value.account_info.tokens);
    dns.listRecords(nowZoneInfo.value, {
        page: pagination.current,
        pageSize: pagination.pageSize,
        keyword: requestKeyword.value,
    }).then(res => {
        if (requestId !== recordsRequestId) return;
        pagination.total = res.count;
        records.value = res.list;
        if (records.value.length === 0 && pagination.current > 1 && pagination.total > 0) {
            pagination.current -= 1;
            refreshRecords();
        }
    }).catch(e => {
        if (requestId !== recordsRequestId) return;
        records.value = [];
        notification.error({
            message: "获取私有解析记录失败",
            description: e.toString(),
            duration: 10,
        });
    }).finally(() => {
        if (requestId === recordsRequestId) {
            loading.value = false;
        }
    });
};

onMounted(() => {
    refreshAllZones();
    refreshRecords();
});

const addRecordModal = ref(null);
const addRecord = () => {
    addRecordModal.value?.openModal(nowZoneInfo.value);
};
const editRecord = record => {
    addRecordModal.value?.openModal(nowZoneInfo.value, record);
};

const selectZone = value => {
    const zone = allZones.value.find(item => item._id === value);
    if (!zone) {
        return;
    }
    nowZoneInfo.value = zone;
    searchForm.type = null;
    searchForm.status = null;
    searchForm.keyword = "";
    requestKeyword.value = "";
    refreshRecords({resetPage: true});
};

const startEditRemark = record => {
    if (!remarkEditable.value) {
        message.warning("当前云厂商暂不支持单独修改备注");
        return;
    }
    editingRemarkRecordId.value = record.RecordId;
    editingRemarkValue.value = record.Remark || "";
};

const cancelEditRemark = () => {
    editingRemarkRecordId.value = "";
    editingRemarkValue.value = "";
};

const onRemarkPopoverOpenChange = (open, record) => {
    if (open) {
        startEditRemark(record);
        return;
    }
    if (savingRemarkRecordId.value !== record.RecordId) {
        cancelEditRemark();
    }
};

const saveRecordRemark = record => {
    const remark = editingRemarkValue.value.trim();
    if (remark === (record.Remark || "")) {
        cancelEditRemark();
        return;
    }
    savingRemarkRecordId.value = record.RecordId;
    const dns = getPrivateDnsService(nowZoneInfo.value.account_key, nowZoneInfo.value.cloud, nowZoneInfo.value.account_info.tokens, true);
    dns.updateRecordRemark(nowZoneInfo.value, record, remark).then(() => {
        message.success("修改备注成功");
        record.Remark = remark;
        cancelEditRemark();
        refreshRecords();
    }).catch(e => {
        notification.error({
            message: "修改备注失败",
            description: e.toString(),
            duration: 10,
        });
    }).finally(() => {
        savingRemarkRecordId.value = "";
    });
};

const deleteRecord = record => {
    Modal.confirm({
        title: "删除记录",
        content: h("div", null, [
            "确认删除 ",
            h("span", {style: {color: token.value.colorPrimary}}, record.Name === "@" ? nowZoneInfo.value.zone_name : `${record.Name}.${nowZoneInfo.value.zone_name}`),
            " 吗？",
        ]),
        okText: "确认",
        cancelText: "取消",
        onOk: () => {
            loading.value = true;
            const dns = getPrivateDnsService(nowZoneInfo.value.account_key, nowZoneInfo.value.cloud, nowZoneInfo.value.account_info.tokens);
            return dns.deleteRecord(nowZoneInfo.value, record.RecordId, record).then(() => {
                message.success("删除记录成功");
                refreshRecords();
            }).catch(e => {
                notification.error({
                    message: "删除记录失败",
                    description: e.toString(),
                    duration: 10,
                });
                loading.value = false;
            });
        },
    });
};

const batchDelete = () => {
    Modal.confirm({
        title: "批量删除记录",
        content: `确认删除选中的 ${selectedRecords.value.length} 条记录？`,
        okText: "确认",
        cancelText: "取消",
        onOk: () => {
            loading.value = true;
            const dns = getPrivateDnsService(nowZoneInfo.value.account_key, nowZoneInfo.value.cloud, nowZoneInfo.value.account_info.tokens);
            return Promise.all(selectedRecords.value.map(item => dns.deleteRecord(nowZoneInfo.value, item.RecordId, item))).then(() => {
                message.success("批量删除成功");
                refreshRecords();
            }).catch(e => {
                notification.error({
                    message: "批量删除失败",
                    description: e.toString(),
                    duration: 10,
                });
                loading.value = false;
            });
        },
    });
};

const changeStatus = (value, record) => {
    Modal.confirm({
        title: "修改状态",
        content: h("div", null, [
            "确认将 ",
            h("span", {style: {color: token.value.colorPrimary}}, record.Name),
            " 状态修改为 ",
            h("span", {style: {color: value ? "#40c057" : "#f03e3e"}}, value ? "启用" : "暂停"),
            " 吗？",
        ]),
        okText: "确认",
        cancelText: "取消",
        onOk: () => {
            const dns = getPrivateDnsService(nowZoneInfo.value.account_key, nowZoneInfo.value.cloud, nowZoneInfo.value.account_info.tokens, true);
            return dns.changeRecordStatus(nowZoneInfo.value, record.RecordId, {Status: value}).then(() => {
                message.success("修改状态成功");
                record.Status = value;
                record.StatusText = value ? "启用" : "暂停";
                refreshRecords();
            }).catch(e => {
                record.Status = !value;
                notification.error({
                    message: "修改状态失败",
                    description: e.toString(),
                    duration: 10,
                });
            });
        },
        onCancel: () => {
            record.Status = !value;
        },
    });
};

const rowSelection = {
    selectedRowKeys,
    onChange: (keys, rows) => {
        selectedRowKeys.value = keys;
        selectedRecords.value = rows.filter(item => !["NS", "SOA"].includes(item.Type));
    },
};

const onTableChange = nextPagination => {
    pagination.current = parseInt(nextPagination.current || 1, 10);
    pagination.pageSize = parseInt(nextPagination.pageSize || 20, 10);
    refreshRecords();
};

const applyKeywordSearch = debounce(() => {
    requestKeyword.value = searchForm.keyword.toString().trim();
    refreshRecords({resetPage: true});
}, 350);

const onKeywordSearch = () => {
    applyKeywordSearch.cancel();
    requestKeyword.value = searchForm.keyword.toString().trim();
    refreshRecords({resetPage: true});
};

onBeforeUnmount(() => {
    applyKeywordSearch.cancel();
});
</script>

<template>
    <div class="private-records">
        <a-flex class="topbar" align="center" justify="space-between">
            <a-space :size="12">
                <div class="zone-cloud-icon">
                    <img :src="nowZoneInfo.cloud_info.icon" alt="" style="height: 17px"/>
                </div>
                <a-select
                    show-search
                    :value="nowZoneInfo._id"
                    style="width: 280px"
                    option-filter-prop="label"
                    @change="selectZone"
                >
                    <a-select-option
                        v-for="item in allZones"
                        :key="item._id"
                        :value="item._id"
                        :label="`${item.cloud_info.title}-${item.zone_name}-${item.account_info.tag}`"
                    >
                        {{ item.cloud_info.title }}-{{ item.zone_name }}
                    </a-select-option>
                </a-select>
                <a-tooltip>
                    <template #title>
                        <div v-for="(count, type) in recordTypeCounts" :key="type">{{ type }}: {{ count }} 条</div>
                    </template>
                    <a-typography-text :style="{color: token.colorPrimary}">{{ pagination.total }} 条记录</a-typography-text>
                </a-tooltip>
            </a-space>
            <a-space>
                <a-button :icon="h(SyncOutlined)" @click="refreshRecords()"></a-button>
                <a-button @click="emit('close')">关闭</a-button>
            </a-space>
        </a-flex>
        <a-flex class="toolbar" justify="space-between">
            <a-space>
                <a-select v-model:value="searchForm.type" allow-clear placeholder="解析类型" style="width: 110px">
                    <a-select-option v-for="item in RecordTypes" :key="item" :value="item">{{ item }}</a-select-option>
                </a-select>
                <a-select v-model:value="searchForm.status" allow-clear placeholder="解析状态" style="width: 110px">
                    <a-select-option value="true">启用</a-select-option>
                    <a-select-option value="false">暂停</a-select-option>
                </a-select>
                <a-input-search v-model:value="searchForm.keyword" placeholder="搜索主机记录/记录值" style="width: 200px" @change="applyKeywordSearch" @search="onKeywordSearch"></a-input-search>
            </a-space>
            <a-space>
                <a-popover trigger="click" placement="bottomRight">
                    <template #content>
                        <div class="column-setting">
                            <div class="column-setting-title">字段列展示</div>
                            <a-checkbox-group v-model:value="optionalEnabledKeys" :options="optionalColumnOptions"></a-checkbox-group>
                        </div>
                    </template>
                    <a-tooltip title="字段列设置">
                        <a-button :icon="h(SettingOutlined)"></a-button>
                    </a-tooltip>
                </a-popover>
                <a-button type="primary" :icon="h(PlusOutlined)" @click="addRecord">添加记录</a-button>
                <a-button danger :icon="h(DeleteOutlined)" :disabled="selectedRecords.length === 0" @click="batchDelete"></a-button>
            </a-space>
        </a-flex>
        <div class="table-wrap">
            <a-table
                :row-selection="rowSelection"
                :row-key="record => record.RecordId"
                :columns="columns"
                :data-source="calcRecords"
                :pagination="tablePagination"
                :loading="{spinning: loading, tip: '加载中...'}"
                :scroll="{x: tableScrollX, y: 'calc(100vh - 250px)'}"
                sticky
                @change="onTableChange"
            >
                <template #bodyCell="{ column, record }">
                    <template v-if="column.key === 'RecordLine'">
                        {{ record.RecordLine || '-' }}
                    </template>
                    <template v-if="column.key === 'Value'">
                        <div class="record-value">{{ record.Value }} <a-tag v-if="record.Type === 'MX'">优先级: {{ record.MX }}</a-tag></div>
                    </template>
                    <template v-if="column.key === 'Status'">
                        <a-switch
                            v-if="statusEditable"
                            v-model:checked="record.Status"
                            :checked-value="true"
                            :un-checked-value="false"
                            checked-children="启用"
                            un-checked-children="暂停"
                            @change="value => changeStatus(value, record)"
                        ></a-switch>
                        <template v-else>
                            <a-tag v-if="record.Status" color="success">{{ record.StatusText || '启用' }}</a-tag>
                            <a-tag v-else color="error">{{ record.StatusText || '暂停' }}</a-tag>
                        </template>
                    </template>
                    <template v-if="column.key === 'Remark'">
                        <a-space class="remark-display" :size="6">
                            <a-typography-text class="remark-text" :type="record.Remark ? undefined : 'secondary'">
                                {{ record.Remark || '-' }}
                            </a-typography-text>
                            <a-popover
                                v-if="remarkEditable"
                                trigger="click"
                                placement="bottom"
                                :open="editingRemarkRecordId === record.RecordId"
                                @openChange="open => onRemarkPopoverOpenChange(open, record)"
                            >
                                <template #content>
                                    <div class="remark-popover">
                                        <a-input
                                            v-model:value="editingRemarkValue"
                                            :maxlength="200"
                                            :disabled="savingRemarkRecordId === record.RecordId"
                                            @pressEnter="saveRecordRemark(record)"
                                        ></a-input>
                                        <a-space>
                                            <a-button
                                                type="primary"
                                                :loading="savingRemarkRecordId === record.RecordId"
                                                @click="saveRecordRemark(record)"
                                            >确定</a-button>
                                            <a-button
                                                :disabled="savingRemarkRecordId === record.RecordId"
                                                @click="cancelEditRemark"
                                            >取消</a-button>
                                        </a-space>
                                    </div>
                                </template>
                                <a-tooltip title="编辑备注">
                                    <a-button
                                        type="text"
                                        size="small"
                                        class="remark-edit-button"
                                        :icon="h(EditOutlined)"
                                    ></a-button>
                                </a-tooltip>
                            </a-popover>
                        </a-space>
                    </template>
                    <template v-if="column.key === 'CreatedAt'">
                        {{ formatRecordTime(record.CreatedAt) }}
                    </template>
                    <template v-if="column.key === 'UpdatedAt'">
                        {{ formatRecordTime(record.UpdatedAt) }}
                    </template>
                    <template v-if="column.key === 'operation'">
                        <a-dropdown-button @click.stop="editRecord(record)">
                            <FormOutlined/>
                            <template #overlay>
                                <a-menu>
                                    <a-menu-item key="delete" danger @click="deleteRecord(record)">
                                        <a-space><DeleteOutlined/>删除记录</a-space>
                                    </a-menu-item>
                                </a-menu>
                            </template>
                        </a-dropdown-button>
                    </template>
                </template>
            </a-table>
        </div>
        <AddPrivateDnsRecord ref="addRecordModal" @refresh="refreshRecords"></AddPrivateDnsRecord>
    </div>
</template>

<style scoped lang="scss">
.private-records {
    height: 100%;
    display: flex;
    flex-direction: column;
    overflow: hidden;
}

.topbar {
    height: 64px;
    padding: 0 16px;
    border-bottom: 1px dashed v-bind("token.colorBorder");
    flex-shrink: 0;
}

.toolbar {
    padding: 10px 16px;
    flex-shrink: 0;
}

.zone-cloud-icon {
    width: 100px;
    text-align: center;
}

.table-wrap {
    flex: 1;
    min-height: 0;
    overflow: hidden;
    padding-bottom: 6px;
}

:deep(.ant-table-wrapper),
:deep(.ant-spin-nested-loading),
:deep(.ant-spin-container) {
    height: 100%;
}

:deep(.ant-spin-container) {
    display: flex;
    flex-direction: column;
    min-height: 0;
}

:deep(.ant-table) {
    flex: 1;
    min-height: 0;
}

:deep(.ant-table-container) {
    height: 100%;
}

:deep(.ant-pagination) {
    flex: 0 0 auto;
    margin: 12px 0 0;
    padding: 0 16px;
}

:deep(.ant-table-body) {
    &::-webkit-scrollbar {
        width: 6px;
        height: 6px;
    }

    &::-webkit-scrollbar-thumb {
        background-color: v-bind("token.colorBorder") !important;
        border-radius: 10px !important;
        border: 1px solid v-bind("token.colorBorder") !important;
    }

    &::-webkit-scrollbar-thumb:hover {
        background-color: v-bind("token.colorPrimary") !important;
        border: 1px solid v-bind("token.colorPrimary") !important;
    }

    &::-webkit-scrollbar-track {
        background-color: transparent;
    }
}

.record-value {
    white-space: normal;
    word-break: break-all;
}

.remark-display {
    width: 100%;
    justify-content: center;
}

.remark-text {
    max-width: 220px;
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
}

.remark-edit-button {
    width: 22px;
    height: 22px;
}

.remark-popover {
    width: 260px;
    display: flex;
    flex-direction: column;
    gap: 12px;
}

.remark-popover :deep(.ant-input) {
    width: 100%;
}

.column-setting {
    width: 220px;
}

.column-setting-title {
    margin-bottom: 10px;
    font-weight: 500;
    color: v-bind("token.colorText");
}

.column-setting :deep(.ant-checkbox-group) {
    display: grid;
    grid-template-columns: repeat(2, minmax(0, 1fr));
    gap: 8px 12px;
}
</style>
