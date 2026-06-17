import {defineStore} from 'pinia';
import {ref} from 'vue';

const defaultConfig = {
    menuExpand: false, // 菜单是否展开
    domainListView: 'card', // 域名页面 显示模式
    privateDnsRecordColumns: ['Name', 'Type', 'RecordLine', 'Value', 'TTL', 'Status', 'Remark', 'CreatedAt', 'UpdatedAt', 'operation'],
    showExpiredWarn: true, // 是否显示过期提醒
    alarmDays: 10, // 过期提醒天数
    notifications: {
        wechat: '',
        dingtalk: '',
        serverChan: '',
        anPush: '',
        custom: '',
        feishu: "",
    },
    ssl: {
        dns_verify: 'tcpmk', // local 或者 local 或者 tcpmk
        auto_acme: true, // 是否自动开始acme验证
    },
    ca: {
        default_ca: 'letsencrypt', // 默认的ca
        google_kid: '', // google eid
        google_hmacKey: '', // google key
        google_proxy: '', // 代理地址 仅支持http代理
        zerossl_kid: '', // zerossl eid
        zerossl_hmacKey: '', // zerossl key
    }
};

// 从 utools.db 获取配置
const getConfig = () => {
    let config = utools.dbStorage.getItem('dh_config');
    if (!config) {
        // 如果没有配置，使用默认配置并保存
        utools.dbStorage.setItem('dh_config', defaultConfig);
        return defaultConfig;
    }

    // 合并默认配置和已保存的配置，确保所有字段都存在
    const mergedConfig = {...defaultConfig, ...config};
    // 重新保存合并后的配置
    utools.dbStorage.setItem('dh_config', mergedConfig);
    return mergedConfig;
};

export const useThemeStore = defineStore('theme', () => {
    // 主题相关 - 使用独立的 key 存储
    const themeColor = ref(utools.dbStorage.getItem("custome_theme") || '#1677ff');
    const showMode = ref(utools.dbStorage.getItem("theme") || 'auto');

    // 其他配置 - 统一使用 dh_config 存储
    const config = ref(getConfig());

    // 主题相关的 actions
    function setThemeColor(color) {
        themeColor.value = color;
        utools.dbStorage.setItem('custome_theme', color);
    }

    function setShowMode(mode) {
        showMode.value = mode;
        utools.dbStorage.setItem('theme', mode);
    }

    // 配置相关的 actions
    function updateConfig(newConfig) {
        // 深度合并配置
        const mergeDeep = (target, source) => {
            for (const key in source) {
                if (source[key] instanceof Object && !Array.isArray(source[key])) {
                    if (!target[key]) Object.assign(target, {[key]: {}});
                    mergeDeep(target[key], source[key]);
                } else {
                    Object.assign(target, {[key]: source[key]});
                }
            }
            return target;
        };

        // 更新响应式状态
        config.value = mergeDeep({...config.value}, newConfig);
        // 在存储前将 Proxy 对象转换为普通对象
        const plainConfig = JSON.parse(JSON.stringify(config.value));
        utools.dbStorage.setItem('dh_config', plainConfig);
    }

    return {
        themeColor,
        showMode,
        config,
        setThemeColor,
        setShowMode,
        updateConfig
    };
});
 
