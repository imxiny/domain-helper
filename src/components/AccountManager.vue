<script setup>
import {CloudDownloadOutlined, DeleteOutlined, InfoCircleOutlined, PartitionOutlined} from "@ant-design/icons-vue";
import {computed, getCurrentInstance, h, ref, reactive} from "vue";
import {Modal, message, notification, theme} from 'ant-design-vue';
import {
    getAllAccount,
    getAllDomains,
    getAllPrivateZones,
    getDomainBaseCloud,
    openDoc,
    savePrivateZone,
    saveSettingDb
} from "@/utils/tool";
import {getDnsService} from "@/service/DnsService";
import {getPrivateDnsService} from "@/service/PrivateDnsService";
import {cloudsData} from "@/utils/data";
import {afterCommon} from "@/service/afterSaveSetting";

const {useToken} = theme;
const {token} = useToken();

const searchKey = ref("");
const allCloudsAccounts = ref(getAllAccount());
const keySwitch = ref(false);
const isEdit = ref(false);

const form = reactive({
    _id: null,
    tag: "",
    cloud_key: "ali",
    desc: "", // 额外描述
    tokens: [
        {
            key: "KEY",
            value: ""
        },
        {
            key: "SECRET",
            value: ""
        }
    ]
});

const refreshAccount = () => {
    allCloudsAccounts.value = getAllAccount();
};

const filterClouds = computed(() => {
    return allCloudsAccounts.value.filter(item => {
        let key = searchKey.value.toString().toLowerCase();
        return item.tag.toLowerCase().includes(key) ||
            item.cloud_key.toLowerCase().includes(key) ||
            item.cloud_info.title.includes(key);
    });
});
const changeCloud = (key) => {
    const cloudInfo = getDomainBaseCloud(key);
    form.tokens = cloudInfo.tokens.map(item => {
        item.value = "";
        return item;
    });
    form.desc = cloudInfo.desc;
};

const editCloudSetting = (item) => {
    isEdit.value = true;
    form._id = item._id;
    form.tag = item.tag;
    form.cloud_key = item.cloud_key;
    form.tokens = item.tokens;
    keySwitch.value = true;
};

const addCloudAccount = () => {
    isEdit.value = false;
    form._id = "";
    form._rev = "";
    form.tag = "";
    form.key = "";
    form.cloud_key = "ali";
    form.desc = "";
    form.tokens = getDomainBaseCloud("ali").tokens.map(item => {
        item.value = "";
        return item;
    });
    keySwitch.value = true;
};

const hideKey = (str) => {
    if (!str) return "未设置";
    if (str.length <= 3) return str;
    return str.slice(0, 4) + "********" + str.slice(-4);
};

const copyText = (text, msg) => {
    if (text) {
        utools.copyText(text);
        message.success(msg || "复制成功");
    }
};

const {proxy} = getCurrentInstance();

const saveSetting = () => {
    const tag = form.tag.toString().trim();
    if (!tag) {
        message.error("请填写账号标签");
        return;
    }

    let tokens = form.tokens.map(item => ({
        key: item.key,
        value: item.value.trim()
    }));


    // 全都为空的情况下 才提示 填写任意一项
    if (tokens.every(item => !item.value.trim())) {
        message.error("请填写账号信息");
        return;
    }


    let data = {
        cloud_key: form.cloud_key,
        tag: form.tag,
        tokens: tokens,
        cloud_info: cloudsData.find(f => f.key === form.cloud_key)
    };

    data.account_key = saveSettingDb(data, isEdit.value ? form._id : null);
    keySwitch.value = false;
    message.success(`保存成功`);
    refreshAccount();

    getDnsService(data.account_key, form.cloud_key, tokens, true);

    afterCommon(data, () => {
        proxy.$eventBus.emit("refresh-domain-list");
    });
};

const clearSetting = () => {
    form.tag = "";
    form.tokens = form.tokens.map(item => {
        item.value = "";
        return item;
    });
};

const deleteAccount = (item) => {
    Modal.confirm({
        title: '删除账号',
        content: h('div', null, [
            h('div', {style: {margin: '10px 0'}}, [
                '确定删除 ',
                h('span', {style: {color: item.cloud_info.color || token.value.colorPrimary}}, `${item.cloud_info.title}-${item.tag}`),
                ' 么?'
            ]),
            h('div', null, '删除前需要解绑域名')
        ]),
        onOk() {
            deleteAccountDo(item);
        }
    });
};

const deleteAccountDo = (item) => {
    let bindDomains = getAllDomains().filter(f => f.account_key === item._id);
    let bindPrivateZones = getAllPrivateZones().filter(f => f.account_key === item._id);
    if (bindDomains.length > 0 || bindPrivateZones.length > 0) {
        let vnodes = [];
        bindDomains.forEach(item => {
            vnodes.push(h('div', null, item.domain));
        });
        bindPrivateZones.forEach(item => {
            vnodes.push(h('div', null, `私有解析: ${item.zone_name}`));
        });
        notification.error({
            message: '删除失败',
            description: h('div', null, [
                h('div', null, '请先解绑域名或私有 Zone，已绑定资源:'),
            ].concat(vnodes)),
        });
        return false;
    }
    utools.dbStorage.removeItem(item._id);
    message.success(`${item.cloud_info.title}-${item.tag} 删除成功`);
    refreshAccount();
};

const downloadDomains = (item) => {
    afterCommon({
        cloud_key: item.cloud_key,
        tag: item.tag,
        tokens: item.tokens,
        cloud_info: item.cloud_info,
        account_key: item._id
    }, () => {
        proxy.$eventBus.emit("refresh-domain-list");
    });
}

const supportPrivateDns = (item) => ['ali', 'tencent', 'aws', 'huawei', 'volcengine'].includes(item.cloud_key);

const downloadPrivateZones = async (item) => {
    const hide = message.loading('正在拉取私有 Zone...', 0);
    try {
        const dns = getPrivateDnsService(item._id, item.cloud_key, item.tokens, true);
        const zones = await dns.listZones();
        zones.forEach(zone => {
            savePrivateZone({
                ...zone,
                cloud: item.cloud_key,
                account_key: item._id,
                vpc_bindings: zone.vpc_bindings || [],
            });
        });
        message.success(`成功拉取 ${zones.length} 个私有 Zone`);
    } catch (e) {
        notification.error({
            message: '拉取私有 Zone 失败',
            description: e.toString(),
            duration: 10
        });
    } finally {
        hide();
    }
}

// 确保 HTML 内容安全
const safeDesc = computed(() => {
    return form.desc || '';
});

</script>

<template>
    <div class="box">
        <div class="header" :style="{ backgroundColor: token.colorBgElevated }">
            <a-space>
                <div class="title" :style="{ color: token.colorText }">
                    账号管理
                </div>
                <div class="desc" :style="{ color: token.colorTextTertiary }">
                    管理各平台账号信息
                </div>
            </a-space>
            <a-space>
                <a-tooltip title="各平台参数说明文档">
                    <a-button type="link"
                              @click="openDoc('https://feedback.esion.xyz/#/plugin/1863098983146651648/faqs-more?id=1866660741069336576')">
                        说明文档
                    </a-button>
                </a-tooltip>
                <a-input v-model:value="searchKey" placeholder="输入关键字检索" style="width: 180px;"/>
                <a-button type="primary" @click="addCloudAccount">添加账号</a-button>

            </a-space>
        </div>

        <div class="cards_box">
            <a-card
                v-for="(i, index) in filterClouds"
                :key="index"
                size="small"
                hoverable
                :bordered="true"
                @click="editCloudSetting(i)"
            >
                <template #title>
                    <a-flex align="center" justify="space-between" gap="10">
                        <a-flex align="center" gap="16">
                            <img :src="i.cloud_info.icon" alt="" style="height: 18px;">
                            <a-typography-text v-if="i.cloud_info.name">{{ i.cloud_info.name }}</a-typography-text>
                            <a-tag :color="i.cloud_info.color">{{ i.tag }}</a-tag>
                        </a-flex>
                        <a-space size="small">
                            <a-tooltip title="从平台拉取域名">
                                <a-button @click.stop="downloadDomains(i)" type="link"
                                          :icon="h(CloudDownloadOutlined)"></a-button>
                            </a-tooltip>
                            <a-tooltip v-if="supportPrivateDns(i)" title="拉取私有 Zone">
                                <a-button @click.stop="downloadPrivateZones(i)" type="link"
                                          :icon="h(PartitionOutlined)"></a-button>
                            </a-tooltip>
                            <a-button danger @click.stop="deleteAccount(i)" type="link"
                                      :icon="h(DeleteOutlined)"></a-button>
                        </a-space>
                    </a-flex>
                </template>

                <a-space direction="vertical" style="width: 100%">
                    <template v-for="(x, xindex) in i.tokens" :key="xindex">
                        <a-space v-if="x.value">
                            <a-typography-text class="key">{{ x.key }}</a-typography-text>
                            <a-typography-text
                                style="cursor: pointer"
                                @click.stop="copyText(x.value, `${i.cloud_info.title} ${x.key} 复制成功`)"
                                class="value"
                            >
                                {{ hideKey(x.value) }}
                            </a-typography-text>
                        </a-space>
                    </template>
                </a-space>
            </a-card>

            <a-empty v-if="allCloudsAccounts.length === 0">
                <template #description>
                    <p :style="{ color: token.colorTextTertiary }">
                        暂无账号信息
                    </p>
                    <a-button type="primary" @click="addCloudAccount">添加账号</a-button>
                </template>
            </a-empty>
        </div>

        <a-drawer placement="right" v-model:open="keySwitch" width="300px">
            <template #title>
                <a-flex justify="space-between" align="center">
                    <span style="font-size: 16px;">{{ isEdit ? `编辑账号` : '添加账号' }}</span>
                    <a @click="openDoc('https://feedback.esion.xyz/#/plugin/1863098983146651648/faqs-more?id=1866660741069336576')">说明文档</a>
                </a-flex>
            </template>
            <a-form layout="vertical">
                <a-form-item label="选择平台">
                    <a-select show-search v-model:value="form.cloud_key" @change="changeCloud" style="width: 100%">
                        <a-select-option :value="i.key" v-for="i in cloudsData" :key="i.key">
                            <a-space>
                                <a-image :preview="false" height="18px" :src="i.icon"></a-image>
                                {{ i.title }}
                            </a-space>
                        </a-select-option>
                    </a-select>
                </a-form-item>
                <a-form-item label="账号标签">
                    <a-input
                        v-model:value="form.tag"
                        :maxlength="10"
                        placeholder="账号标签 例如 个人、公司等"
                    />
                </a-form-item>
                <a-form-item v-if="form.desc" label="参数说明">
                    <transition name="fade">
                        <div class="desc-container" v-html="safeDesc"
                             :style="{'--key-color': token.colorPrimary}"></div>
                    </transition>
                </a-form-item>
                <a-form-item
                    v-for="(token, index) in form.tokens"
                    :label="token.key"
                    :key="index"
                >
                    <a-input
                        v-model:value="token.value"
                        :name="token.key"
                        :placeholder="token.key"
                    />
                </a-form-item>
                <a-form-item>
                    <a-space>
                        <a-button type="primary" @click="saveSetting">保存</a-button>
                        <a-button @click="clearSetting">清空</a-button>
                    </a-space>
                </a-form-item>
            </a-form>
        </a-drawer>
    </div>
</template>

<style scoped lang="scss">
.box {
    height: 100vh;
    box-sizing: border-box;
    display: flex;
    flex-direction: column;
    overflow: hidden;

    .header {
        height: 60px;
        display: flex;
        justify-content: space-between;
        align-items: center;
        padding: 0 16px;
        border-bottom: 1px dashed v-bind('token.colorBorder');

        .title {
            font-size: 20px;
            font-weight: 500;
        }

        .desc {
            font-size: 12px;
        }
    }

    .cards_box {
        padding: 16px;
        height: calc(100vh - 60px);
        display: grid;
        overflow: auto;
        grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
        grid-auto-rows: min-content;
        gap: 16px;
        max-width: 100%;
        justify-content: center;

        :deep(.ant-card) {
            height: fit-content;
        }

        @media screen and (max-width: 1000px) {
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
        }

        :global(.content-expanded) & {
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
        }

        // 当只有一个卡片时限制宽度和高度
        &:has(> :only-child) {
            display: flex;
            justify-content: flex-start;
            align-items: flex-start;

            :deep(.ant-card) {
                width: 45%;
                flex-shrink: 0;
            }
        }

        // 当显示 Empty 组件时的样式
        &:has(> .ant-empty) {
            display: flex;
            justify-content: center;
            align-items: center;
        }
    }
}

.key {
    color: v-bind('token.colorTextSecondary');
}

.value {
    color: v-bind('token.colorText');
}

.desc-header {
    display: flex;
    align-items: center;
    gap: 8px;
    margin-bottom: 8px;
    font-weight: 500;
    color: v-bind('token.colorTextSecondary');

    .anticon {
        color: v-bind('token.colorPrimary');
    }
}

.desc-container {
    border-radius: 4px;
    padding: 12px;
    font-size: 12px;
    line-height: 1.5;
    box-shadow: 0 1px 2px rgba(0, 0, 0, 0.05);
    border: 1px solid #D9D9D9;

    :deep(.key) {
        color: var(--key-color) !important;
    }
}

// 添加过渡动画
.fade-enter-active,
.fade-leave-active {
    transition: opacity 0.3s ease;
}

.fade-enter-from,
.fade-leave-to {
    opacity: 0;
}
</style> 
