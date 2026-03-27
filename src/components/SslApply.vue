<script setup>
import {computed, ref, reactive, getCurrentInstance, onMounted, h, onBeforeUnmount} from "vue";
import {congratulations, getAllDomains, getDomain, getItem, getRootDomain, saveSslInfo} from "@/utils/tool";
import "loaders.css/loaders.min.css"
import {message, notification, theme} from "ant-design-vue";
import {getDnsService} from "@/service/DnsService";
import {useRouter} from 'vue-router';
import {SSL_STATUS, saveSslRecord, updateSslRecord} from '@/utils/sslStatus'

const open = ref(false);
const successModal = ref(false);
const confirmLoading = ref(false);
const {proxy} = getCurrentInstance();
import {onErrorCaptured} from 'vue';
import {
    CloudUploadOutlined,
    QuestionCircleOutlined,
    PlusOutlined,
    DeleteOutlined
} from "@ant-design/icons-vue";


const okText = ref("开始申请")
const applyTask = reactive({
    id: 0,
    canceled: false,
});
const ABORT_ERROR_CODE = "APPLY_ABORTED";

onErrorCaptured((err, vm, info) => {
    // 处理错误，比如记录日志、展示通知等
    //console.error('Vue error captured:', err, info);
    // 返回false以停止错误传播或返回true以继续传播错误
    return false;
});

const labelCol = {style: {width: '80px'}, span: 5};


const formDomains = ref([])

const EA = [
    "ECC-256",
    "ECC-384",
    "ECC-521",
    "RSA-2048",
    "RSA-3072",
    "RSA-4096",
];


onMounted(() => {
    proxy.$eventBus.on("open-ssl-apply", openModal)
    proxy.$eventBus.on("open-ssl-renew", renewSsl)
    proxy.$eventBus.on("verifyACME", acmeDo)
    proxy.$eventBus.on("verifyDNS", verifyDns)
})
onBeforeUnmount(() => {
    proxy.$eventBus.off("open-ssl-apply", openModal)
    proxy.$eventBus.off("open-ssl-renew", renewSsl)
    proxy.$eventBus.off("verifyACME", acmeDo)
    proxy.$eventBus.off("verifyDNS", verifyDns)
})
import {useThemeStore} from '@/stroes/themeStore.js';
import AcmeClient from "@/utils/ssl";

const themeStore = useThemeStore();
const sysConfig = themeStore.config;
const form = reactive({
    email: "",
    ea: "ECC-256",
    ca: sysConfig.ca.default_ca,
})
const colorPrimary = computed(() => themeStore.themeColor);


const {useToken} = theme;
const {token} = useToken();

const isDoing = ref(false)
const emit = defineEmits(["openapi"])


const allDomains = ref([])

const initAllDomains = () => {
    allDomains.value = getAllDomains()
}
const sslInfo = ref(null)

const sslKey = ref('')
const SUB_DOMAIN_REGEX = /^(@|\*|\*\.(?:[a-zA-Z0-9](?:[a-zA-Z0-9_-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9_-]{0,61}[a-zA-Z0-9])?)*)?|(?:[a-zA-Z0-9](?:[a-zA-Z0-9_-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9_-]{0,61}[a-zA-Z0-9])?)*))$/;

const getCaExt = (ca) => {
    if (ca === "google") {
        return {
            kid: sysConfig.ca.google_kid,
            proxy: sysConfig.ca.google_proxy,
            hmacKey: sysConfig.ca.google_hmacKey,
        }
    }
    if (ca === "zerossl") {
        return {
            kid: sysConfig.ca.zerossl_kid,
            hmacKey: sysConfig.ca.zerossl_hmacKey,
        }
    }
    return {}
}

const acmeClientMap = new Map()

const initAcmeClient = async (accountKey = null, accountUrl = null, ca = null, email = null) => {
    try {
        const acmeDb = new DbAcmeAccount();
        ca = ca || form.ca;
        const acmeAccount = acmeDb.getAccount(ca, {accountKey, accountUrl});
        accountKey = accountKey || acmeAccount.accountKey;
        accountUrl = accountUrl || acmeAccount.accountUrl;
        const acmeClientKey = `${ca}_${accountUrl || accountKey || "new"}`;
        if (acmeClientMap.has(acmeClientKey)) {
            return acmeClientMap.get(acmeClientKey);
        }

        const acmeClient = new AcmeClient();

        const accountEmail = email || form.email;
        const res = await acmeClient.init(accountEmail, accountKey, accountUrl, ca, getCaExt(ca));

        if (accountKey !== res.accountKey) {
            acmeDb.saveAccount(ca, {accountKey: res.accountKey, accountUrl: res.accountUrl});
        }

        acmeClientMap.set(`${ca}_${res.accountUrl || res.accountKey || "new"}`, acmeClient);
        return acmeClient;
    } catch (error) {
        console.error('Error initializing AcmeClient:', error);
        throw error;
    }
};

const beginApplyTask = () => {
    applyTask.id += 1;
    applyTask.canceled = false;
    return applyTask.id;
};

const createAbortError = () => {
    const err = new Error("申请任务已停止");
    err.code = ABORT_ERROR_CODE;
    return err;
};

const assertTaskActive = (taskId) => {
    if (applyTask.canceled || taskId !== applyTask.id) {
        throw createAbortError();
    }
};

const isAbortError = (error) => error?.code === ABORT_ERROR_CODE;

const cancelApplyTask = () => {
    if (!confirmLoading.value) {
        return;
    }
    applyTask.canceled = true;
    confirmLoading.value = false;
    okText.value = "去验证";
    renderLoging('任务已停止，可在证书管理 > 申请中继续验证', token.value.colorWarning);
    notification.info({
        message: '任务已停止',
        description: '当前申请进度已保留，可稍后继续。',
        duration: 4
    });
};

const removeAcmeDnsRecords = async (sslRecord) => {
    for (const challenge of sslRecord.challenges) {
        const rootDomain = getRootDomain(challenge.domain);
        const account_key = sslRecord.domainCloud?.[rootDomain];
        if (!account_key) {
            continue;
        }
        const dnsServiceInfo = getItem(account_key);
        if (!dnsServiceInfo) {
            continue;
        }
        const dnsService = getDnsService(account_key, dnsServiceInfo.cloud_key, dnsServiceInfo.tokens);
        try {
            await dnsService.deleteAcmeRecord(rootDomain, challenge.domain);
        } catch (e) {
            // 忽略删除失败的错误
        }
    }
};

const normalizeDomainFields = (domainInfo) => {
    const normalizedSub = (domainInfo.sub || "").trim().toLowerCase();
    const normalizedDomain = (domainInfo.domain || "").trim().toLowerCase();
    return {
        ...domainInfo,
        sub: normalizedSub === "*." ? "*" : normalizedSub,
        domain: normalizedDomain
    };
};


// DNS验证操作
const verifyDns = async ({sslId, isOld = false, callback = null, taskId = null}) => {
    const runTaskId = taskId || beginApplyTask();
    // 窗口继续显示
    okText.value = "DNS验证中"
    open.value = true;
    isDoing.value = true;
    confirmLoading.value = true;
    assertTaskActive(runTaskId);
    // 此方法支持继续验证
    const sslRecord = utools.dbStorage.getItem(sslId);
    if (!sslRecord) {
        message.error('未找到对应的证书记录');
        open.value = false;
        confirmLoading.value = false;
        return;
    }

    // 如果是二次申请，需要检查是否过期
    // 过期判断
    if (isOld) {
        const acmeClient = await initAcmeClient(sslRecord.accountKey, sslRecord.accountUrl, sslRecord.ca || "letsencrypt", sslRecord.email);
        isDoing.value = true;
        steps.value = []
        renderLoging('开始验证DNS记录');
        if ((new Date(sslRecord.expires)).getTime() < Date.now()) {
            message.error('申请已过期，请重新申请证书');
            open.value = false;
            confirmLoading.value = false;
            return false;
        }
        // 判断实际订单状态
        const {status} = await acmeClient.getOrderStatus(sslRecord.order)
        if (status === "ready") {
            renderLoging('订单已处于可签发状态，跳过DNS检测', token.value.colorSuccess);
            updateSslRecord(sslId, {
                ...sslRecord,
                status: SSL_STATUS.DNS_VERIFIED
            });
            await acmeDo({
                sslId,
                isOld,
                callback,
                taskId: runTaskId
            });
            return true;
        }
        if (status !== "pending") {
            notification.error({
                message: '证书订单状态异常',
                description: `当前订单状态为 ${status}，建议在证书管理页删除后重新申请。`,
                duration: 8
            });
            open.value = false;
            confirmLoading.value = false;
            return false;
        }
    }

    renderLoging('检测需要一定时间，请耐心等待...', token.value.colorInfo);
    renderLoging('如果DNS检测超时，可前往证书管理页，申请中，继续验证',);
    try {
        for (const item of sslRecord.challenges) {
            assertTaskActive(runTaskId);
            await checkDnsRecord(item.domain, item.keyAuthorization, 240, 10, sysConfig.ssl.dns_verify, (type, info) => {
                if (type === "checkDnsRecord") {

                } else if (type === "checkDnsRecord_success") {
                    renderLoging(`${info.domain} acme DNS 记录生效 🎉`, token.value.colorSuccess);
                }
            }, () => applyTask.canceled || runTaskId !== applyTask.id);
        }
    } catch (e) {
        if (isAbortError(e)) {
            return false;
        }
        notification.error({
            message: 'DNS验证失败',
            description: `${e.toString()}\n请检查 DNS 记录是否生效，可在证书管理 > 申请中继续重试。`,
            duration: 10
        });
        confirmLoading.value = false;
        return;
    }
    assertTaskActive(runTaskId);
    updateSslRecord(sslId, {
        ...sslRecord,
        status: SSL_STATUS.DNS_VERIFIED
    })

    renderLoging('DNS验证成功', token.value.colorSuccess);
    if (sysConfig.ssl.auto_acme) {
        await acmeDo({
            sslId,
            isOld,
            callback,
            taskId: runTaskId
        });
    } else {
        renderLoging('当前为手动验证模式，请手动进行ACME验证');
        renderLoging('建议等待10分钟以上，然后点击下方按钮进行验证');
        renderLoging('此窗口可关闭，验证操作可在证书申请列表中进行');
        confirmLoading.value = false;
        okText.value = "去验证"
    }
}


// 申请证书操作
const acmeDo = async ({sslId, isOld = false, callback = null, taskId = null}) => {
    const runTaskId = taskId || beginApplyTask();
    assertTaskActive(runTaskId);

    // 此方法支持继续验证
    const sslRecord = utools.dbStorage.getItem(sslId);
    if (!sslRecord) {
        message.error('未找到对应的申请记录');
        open.value = false;
        confirmLoading.value = false;
        return;
    }
    okText.value = "ACME验证中"
    // 窗口继续显示
    open.value = true;
    isDoing.value = true;
    confirmLoading.value = true;
    if (isOld) {
        // 来自列表，这里要关闭之前的消息
        steps.value = []
        renderLoging('继续验证证书');
        renderLoging(`${sslRecord.domains.join(', ')}`, colorPrimary.value);
        confirmLoading.value = true;
    }

    const acmeClient = await initAcmeClient(sslRecord.accountKey, sslRecord.accountUrl, sslRecord.ca || "letsencrypt", sslRecord.email);
    // 如果是二次申请，需要检查是否过期
    // 过期判断
    let orderStatus = "";
    if (isOld) {
        if ((new Date(sslRecord.expires)).getTime() < Date.now()) {
            message.error('申请已过期，请重新申请证书');
            open.value = false;
            confirmLoading.value = false;
            return false;
        }
        try {
            okText.value = "检测订单状态"
            // 增加订单状态查询步骤提示
            renderLoging('检测订单状态中...');
            const {status} = await acmeClient.getOrderStatus(sslRecord.order)
            orderStatus = status;
            // 续签的证书，如果不超过有效期，订单可能无需验证
            if (!["ready", "pending"].includes(orderStatus)) {
                notification.error({
                    message: '证书订单状态异常',
                    description: `当前订单状态为 ${orderStatus}，请在证书管理页重新申请。`,
                    duration: 8
                });
                open.value = false;
                confirmLoading.value = false;
                return false;
            }
            renderLoging('订单状态正常', token.value.colorSuccess);
            okText.value = "ACME验证中"
        } catch (e) {
            console.error("获取订单状态失败:", e)
            message.error('获取订单状态失败，请重新申请');
            open.value = false;
            return false;
        }
    }

    try {
        // 开始ACME挑战验证
        sslRecord.status = SSL_STATUS.CHALLENGE_PENDING;
        updateSslRecord(sslId, sslRecord);

        renderLoging('开始 ACME 验证');
        for (const challenge of sslRecord.challenges) {
            assertTaskActive(runTaskId);
            // 如果已经验证过了，跳过
            if (challenge.status === 'completed') {
                continue;
            }
            // 如果订单状态是ready 说明已经验证过了
            if (orderStatus === "ready") {
                challenge.status = 'completed';
                renderLoging(`${challenge.domain} ACME 验证成功 🎉`, token.value.colorSuccess);
                continue;
            }
            try {
                const verified = await acmeClient.verifyDomainChallenge(
                    challenge.authz,
                    challenge.challenge,
                    sslRecord.email,
                    isOld ? 0 : 5, // 自动验证的 额外等待5s
                );
                if (verified) {
                    challenge.status = 'completed';
                    renderLoging(`${challenge.domain} ACME 验证成功 🎉`, token.value.colorSuccess);
                }
            } catch (e) {
                renderLoging(`${challenge.domain} ACME 验证失败: ${e.message}`, token.value.colorError);
                sslRecord.error = e.message;
                sslRecord.status = SSL_STATUS.FAILED;
                updateSslRecord(sslId, sslRecord);
                throw e;
            }
        }

        // 如果所有挑战都完成，进入签发阶段
        if (sslRecord.challenges.every(c => c.status === 'completed')) {
            sslRecord.status = SSL_STATUS.CHALLENGE_VERIFIED;
            updateSslRecord(sslId, sslRecord);
            sslRecord.status = SSL_STATUS.CERT_PENDING;
            updateSslRecord(sslId, sslRecord);
            renderLoging('开始签发证书...');

            assertTaskActive(runTaskId);
            const cert = await acmeClient.finalizeCertificate(
                sslRecord.order,
                sslRecord.domains,
                sslRecord.keyType,
                sslRecord.originSSL
            );

            // 清空续签数据
            renewCsr.csr = null
            renewCsr.key = null

            // 异步删除DNS记录
            setTimeout(async () => {
                await removeAcmeDnsRecords(sslRecord);
            }, 1000);

            // 存储签发证书
            cert.validTo = cert.validTo.getTime();
            cert.validFrom = cert.validFrom.getTime();
            cert.subdomain = sslRecord.domains.join(',')
            cert.ca = sslRecord.ca
            cert.accountKey = sslRecord.accountKey
            cert.accountUrl = sslRecord.accountUrl
            sslInfo.value = cert;
            // 使用第一个域名作为主域名
            sslKey.value = saveSslInfo(sslRecord.formDomains[0].domain, cert.subdomain, cert);
            sslRecord.status = SSL_STATUS.COMPLETED;
            sslRecord.doneTime = Date.now();
            sslRecord.certId = sslKey.value;
            sslRecord.logs = steps.value.map((item) => ({
                msg: item.msg,
                color: item.color,
                time: item.time
            }));
            updateSslRecord(sslId, sslRecord);
            renderLoging('证书签发成功 🎉', token.value.colorSuccess);
            open.value = false;
            congratulations();
            successModal.value = true;
            if (callback) {
                callback();
            }
        }

    } catch (e) {
        if (isAbortError(e)) {
            return false;
        }
        // 删除DNS记录
        await removeAcmeDnsRecords(sslRecord);
        notification.error({
            message: 'SSL证书申请失败',
            description: `${e.toString()}\n你可以在证书管理 > 申请中继续验证，或删除后重建。`,
            duration: 10
        });
        open.value = false;
        return false;
    } finally {
        confirmLoading.value = false;
    }
}


const handleOk = async () => {


    // 检查证书厂商，如果是zerossl 或者 google 要确保已经配置好
    if (form.ca === "zerossl" && (!(sysConfig.ca.zerossl_hmacKey && sysConfig.ca.zerossl_kid))) {
        notification.error({
            message: 'ZeroSSL 未配置',
            description: '请前往系统设置中配置 ZeroSSL 的 kid 和 hmacKey',
            duration: 5
        });
        return;
    }
    if (form.ca === "google" && (!(sysConfig.ca.google_hmacKey && sysConfig.ca.google_kid && sysConfig.ca.google_proxy))) {
        notification.error({
            message: 'Google 未配置',
            description: '请前往系统设置中配置 Google 的 kid 和 hmacKey 及 代理',
            duration: 5
        });
        return;
    }

    if (okText.value === "去验证") {
        open.value = false;
        await router.push({name: 'SslRecords', query: {mode: 'doing'}});
        return;
    }

    const runTaskId = beginApplyTask();
    steps.value = []
    // 检测邮箱是否合法
    if (!form.email) {
        message.error("请输入电子邮箱");
        return;
    }
    // 正则检测邮箱
    if (!/^\w+([-+.]\w+)*@\w+([-.]\w+)*\.\w+([-.]\w+)*$/.test(form.email)) {
        message.error("请输入正确的电子邮箱");
        return;
    }

    // 检查是否有域名
    if (formDomains.value.length === 0) {
        notification.warn({
            message: '请添加申请域名',
            description: h("div", null, [
                h("p", null, "泛域名格式为 *.[xx.]domain.com"),
                h("div", null, "根域名格式为 @.domain.com"),
            ]),
            duration: 10
        });
        return;
    }

    formDomains.value = formDomains.value.map(normalizeDomainFields);

    // 检查每个域名是否合法
    for (const domainInfo of formDomains.value) {
        if (!domainInfo.sub || !domainInfo.domain) {
            message.error(`域名 ${domainInfo.sub}.${domainInfo.domain} 不完整`);
            return;
        }

        if (!SUB_DOMAIN_REGEX.test(domainInfo.sub)) {
            message.error(`域名 ${domainInfo.sub}.${domainInfo.domain} 不合法`);
            return;
        }
    }

    // 检查泛域名冲突
    const domainGroups = {};
    for (const domainInfo of formDomains.value) {
        const rootDomain = domainInfo.domain;
        if (!domainGroups[rootDomain]) {
            domainGroups[rootDomain] = [];
        }
        domainGroups[rootDomain].push(domainInfo);
    }

    // 检查每个根域名下的子域名是否有冲突
    for (const rootDomain in domainGroups) {
        const domains = domainGroups[rootDomain];
        const hasWildcard = domains.some(d => d.sub === '*' || d.sub === '*.');
        const specificDomains = domains.filter(d => d.sub !== '*' && d.sub !== '*.' && d.sub !== '@');

        if (hasWildcard && specificDomains.length > 0) {
            notification.error({
                message: '域名冲突',
                description: h("div", null, [
                    h("p", null, `${rootDomain} 下不能同时包含泛域名和具体子域名`),
                    h("p", null, "例如：*.example.com 和 sub.example.com 不能同时存在"),
                ]),
                duration: 10
            });
            return;
        }
    }

    const dedupDomainSet = new Set();
    for (const domainInfo of formDomains.value) {
        const domainName = domainInfo.sub === "@" ? domainInfo.domain : `${domainInfo.sub}.${domainInfo.domain}`;
        if (dedupDomainSet.has(domainName)) {
            message.error(`域名 ${domainName} 重复，请删除重复项`);
            return;
        }
        dedupDomainSet.add(domainName);
    }

    utools.dbStorage.setItem("user_email", form.email)
    confirmLoading.value = true;

    // 构建域名列表
    const targetDomains = formDomains.value.map(d =>
        d.sub === "@" ? d.domain : `${d.sub}.${d.domain}`
    );


    steps.value = []
    renderLoging(`开始为 ${targetDomains.join(', ')} 申请ssl证书`);
    isDoing.value = true;
    try {
        assertTaskActive(runTaskId);
        const acmeClient = await initAcmeClient(null, null, null, form.email);
        const initResult = await acmeClient.initOrder(targetDomains);
        // 创建DNS记录

        // 要记录每个域名用到的云平台账号 ， 用于后续删除DNS记录
        let domainCloud = {}; // 记录根域名即可
        try {
            for (const challenge of initResult.challenges) {
                assertTaskActive(runTaskId);
                const rootDomain = getRootDomain(challenge.domain);
                const domainInfo = formDomains.value.find(d => d.domain === rootDomain);
                if (!domainInfo) {
                    throw new Error(`${challenge.domain} 未找到对应的根域名配置`);
                }
                const {account_key} = getDomain(`${domainInfo.cloud}/${rootDomain}`);
                if (!account_key) {
                    throw new Error(`${rootDomain} 未找到可用的云平台账号，请先在域名管理中绑定`);
                }
                const dnsServiceInfo = getItem(account_key);
                if (!dnsServiceInfo) {
                    throw new Error(`${rootDomain} 云平台账号信息不存在，请重新配置账号`);
                }
                const dnsService = getDnsService(account_key, dnsServiceInfo.cloud_key, dnsServiceInfo.tokens);

                domainCloud[rootDomain] = account_key;
                try {
                    const recordData = {
                        type: "TXT",
                        name: `_acme-challenge.${challenge.domain}`.replace(`.${rootDomain}`, ""),
                        value: challenge.keyAuthorization,
                    };
                    await dnsService.addRecord(rootDomain, recordData);
                    renderLoging(`${challenge.domain} 创建 acme_challenge DNS记录成功 🎉`, token.value.colorSuccess);
                } catch (e) {
                    throw new Error(`${challenge.domain} : 创建 acme_challenge DNS记录失败: ${e.message}`);
                }
            }
        } catch (e) {
            // 删除DNS记录
            for (const challenge of initResult.challenges) {
                const rootDomain = getRootDomain(challenge.domain);
                const domainInfo = formDomains.value.find(d => d.domain === rootDomain);
                if (!domainInfo) {
                    continue;
                }
                const domainRef = getDomain(`${domainInfo.cloud}/${rootDomain}`);
                const account_key = domainRef?.account_key;
                if (!account_key) {
                    continue;
                }
                const dnsServiceInfo = getItem(account_key);
                if (!dnsServiceInfo) {
                    continue;
                }
                const dnsService = getDnsService(account_key, dnsServiceInfo.cloud_key, dnsServiceInfo.tokens);
                try {
                    await dnsService.deleteAcmeRecord(rootDomain, challenge.domain);
                } catch (e) {
                }
            }
            throw e;
        }


        // 保存初始证书记录
        const sslRecord = {
            domains: targetDomains,
            status: SSL_STATUS.INIT,
            order: initResult.order,
            expires: dayjs(initResult.order.expires).format('YYYY-MM-DD HH:mm:ss'),
            challenges: initResult.challenges,
            createTime: Date.now(),
            email: form.email,
            keyType: form.ea,
            accountKey: initResult.accountKey,
            accountUrl: initResult.accountUrl,
            ca: initResult.ca,
            domainCloud,
            formDomains: formDomains.value.map(d => ({
                sub: d.sub,
                domain: d.domain,
                cloud: d.cloud
            }))
        };
        if (renewCsr.csr) {
            sslRecord.originSSL = {
                csr: renewCsr.csr,
                key: renewCsr.key
            }
            renewCsr.csr = null
            renewCsr.key = null
        }
        const recordId = saveSslRecord(sslRecord);
        renderLoging('证书订单创建成功，已保存到证书申请列表 🎉', token.value.colorSuccess);

        // 自动开始DNS验证
        sslRecord.status = SSL_STATUS.DNS_PENDING;
        updateSslRecord(recordId, sslRecord);
        await verifyDns({
            sslId: recordId,
            isOld: false,
            taskId: runTaskId
        });
    } catch (e) {
        if (isAbortError(e)) {
            return;
        }
        confirmLoading.value = false;
        notification.error({
            message: 'SSL证书申请失败',
            description: `${e.toString()}\n可在证书管理页查看进度并继续操作。`,
            duration: 10
        });
        console.error(e);
        renderLoging(`证书申请失败 ${e.toString()}`, token.value.colorError);
    }
};


const steps = ref([])
const renderLoging = (msg, color = null) => {
    steps.value.push({
        msg,
        color: color || token.value.colorText,
        time: dayjs().format('HH:mm:ss')
    });
}

const renewCsr = reactive({csr: "", key: ""})
const openModal = (domainInfo) => {
    if (Array.isArray(domainInfo)) {
        formDomains.value = domainInfo;
    } else if (typeof domainInfo === "object") {
        formDomains.value = [{
            domain: domainInfo.domain,
            sub: domainInfo.sub || "*",
            cloud: domainInfo.cloud,
        }]
    }

    successModal.value = false;
    confirmLoading.value = false;
    isDoing.value = false;
    form.email = utools.dbStorage.getItem("user_email") || ""
    steps.value = []
    okText.value = "开始申请"
    open.value = true;
    initAllDomains()
}

const renewSsl = async (obj) => {
    if (obj.csr) {
        // 续签操作
        renewCsr.csr = obj.csr
        renewCsr.key = obj.key
        // 重新申请
        successModal.value = false;
        confirmLoading.value = false;
        isDoing.value = false;
        formDomains.value = obj.targetDomains
        form.email = utools.dbStorage.getItem("user_email") || ""
        steps.value = []
        open.value = true;
        initAllDomains()
        okText.value = "开始续签"
        await handleOk();
    } else {
        // 重新申请
        successModal.value = false;
        confirmLoading.value = false;
        isDoing.value = false;
        formDomains.value = obj.targetDomains
        form.email = utools.dbStorage.getItem("user_email") || ""
        steps.value = []
        open.value = true;
        initAllDomains()
        okText.value = "开始申请"
    }
}


const copySslInfo = (type = "key") => {
    const text = sslInfo.value[type]
    utools.copyText(text)
    message.success(`${type} 已复制到剪贴板`)
}

const pushSSL = () => {
    successModal.value = false;
    proxy.$eventBus.emit("open-ssl-push", {
        ...utools.dbStorage.getItem(sslKey.value),
        _id: sslKey.value
    });
}
import {SettingOutlined} from '@ant-design/icons-vue';
import dayjs from "dayjs";
import {checkDnsRecord} from "@/utils/checkDnsRecord";
import {DbAcmeAccount} from "@/utils/dbtool/DbAcmeAccount";

const indicator = h(SettingOutlined, {
    style: {
        fontSize: '30px',
    },
    spin: true,
});
const openSSL = () => {
    successModal.value = false;
    emit("openapi", "ssl")
}

const router = useRouter();

// 添加域名处理函数
const addDomain = () => {
    if (formDomains.value.length >= sslDomainLimit) {
        message.warning(`最多支持 ${sslDomainLimit} 个域名同时申请`);
        return;
    }
    // 确保 allDomains 不为空
    if (allDomains.value.length === 0) {
        message.warning('没有可用的域名');
        return;
    }

    // 添加域名的时候 默认值 优先上一个域名的值
    // 获取上一个域名的值
    if (formDomains.value.length) {
        const lastDomain = formDomains.value[formDomains.value.length - 1];
        formDomains.value.push({
            sub: '',  // 设置默认值为 '*'
            domain: lastDomain.domain,
            cloud: lastDomain.cloud
        })
    } else {
        formDomains.value.push({
            sub: '',  // 设置默认值为 '*'
            domain: allDomains.value[0].domain,  // 确保有默认值
            cloud: allDomains.value[0].cloud
        });
    }
}

// 删除域名处理函数
const removeDomain = (index) => {
    formDomains.value.splice(index, 1);
}


const sslDomainLimit = 10; // 限制域名数量


const setOtherDomain = (index, value) => {
    const domain = allDomains.value.find(d => d.domain === value);
    formDomains.value[index].cloud = domain.cloud
}

const targetDomains = computed(() => {
    return formDomains.value.map(d => d.sub === "@" ? d.domain : `${d.sub}.${d.domain}`)
})
</script>

<template>
    <div class="apply-container">
        <a-modal v-model:open="open" :destroy-on-close="true" title="SSL证书申请"
                 :cancel-button-props="{ disabled: confirmLoading }"
                 :ok-text="okText" cancel-text="取消" :confirm-loading="confirmLoading" @ok="handleOk"
                 width="500px">
            <div style="height: 20px;"></div>
            <a-form :label-col="labelCol" :model="form" v-if="!isDoing">
                <a-form-item label="申请平台">
                    <a-select v-model:value="form.ca">
                        <a-select-option value="letsencrypt">Let's Encrypt</a-select-option>
                        <a-select-option value="google"
                                         :disabled="!(sysConfig.ca.google_hmacKey && sysConfig.ca.google_kid && sysConfig.ca.google_proxy)">
                            Google CA
                            {{
                                !(sysConfig.ca.google_hmacKey && sysConfig.ca.google_kid && sysConfig.ca.google_proxy) ? ' [未配置]' : ''
                            }}
                        </a-select-option>
                        <a-select-option value="zerossl"
                                         :disabled="!(sysConfig.ca.zerossl_hmacKey && sysConfig.ca.zerossl_kid)">ZeroSSL
                            {{ !(sysConfig.ca.zerossl_hmacKey && sysConfig.ca.zerossl_kid) ? ' [未配置]' : '' }}
                        </a-select-option>
                    </a-select>
                </a-form-item>
                <a-form-item label="电子邮箱">
                    <a-input v-model:value="form.email" placeholder="请输电子邮箱，用于创建acme账户"></a-input>
                </a-form-item>
                <a-form-item label="加密算法">
                    <a-flex gap="16">
                        <a-select v-model:value="form.ea" style="flex: 1;">
                            <a-select-option v-for="i in EA" :key="i" :value="i">{{ i }}</a-select-option>
                        </a-select>
                        <a-popover title="算法说明">
                            <template #content>
                                <div>ECC 效率高、安全性强，兼容性略差</div>
                                <div>RSA 效率低，广泛兼容</div>
                                <div>数字越大越安全，速度越慢</div>
                                <div>推荐 ECC-256</div>
                            </template>
                            <QuestionCircleOutlined style="color:#aaaaaa"/>
                        </a-popover>
                    </a-flex>
                </a-form-item>
                <a-form-item label="申请域名">
                    <a-flex style="flex-direction: column" gap="16">
                        <a-flex v-for="(domain, index) in formDomains"
                                :key="index">
                            <a-input-group compact style="flex: 1">
                                <a-input v-model:value="domain.sub" placeholder="支持 @ *" style="width: 40%"/>
                                <a-select show-search v-model:value="domain.domain" style="width: 60%" @change="(event) => {
                                    setOtherDomain(index, event)
                                }">
                                    <a-select-option v-for="d of allDomains" :key="d.domain" :value="d.domain">
                                        .{{ d.domain }}
                                    </a-select-option>
                                </a-select>
                            </a-input-group>
                            <a-button type="text" danger v-if="formDomains.length > 1" @click="removeDomain(index)">
                                <template #icon>
                                    <DeleteOutlined/>
                                </template>
                            </a-button>
                        </a-flex>
                        <a-flex gap="16">
                            <a-button type="default" block @click="addDomain"
                                      :disabled="formDomains.length >= sslDomainLimit">
                                <template #icon>
                                    <PlusOutlined/>
                                </template>
                                添加域名
                            </a-button>
                            <a-popover title="多域名单证书">
                                <template #content>
                                    <div>支持多个域名打到一本证书</div>
                                    <div>最多支持 {{ sslDomainLimit }} 个域名</div>
                                    <div>根域名可以不同</div>
                                    <div>支持泛域名与根域名同一本</div>
                                    <div>例： a.com *.b.com 可以用一本证书</div>
                                </template>
                                <QuestionCircleOutlined style="color:#aaaaaa"/>
                            </a-popover>
                        </a-flex>
                    </a-flex>
                </a-form-item>
            </a-form>
            <div v-else>
                <a-steps direction="vertical" size="small" :current="steps.length ? steps.length - 1 : 0">
                    <a-step v-for="(step, index) in steps" :key="index">
                        <template #title>
                            <span :style="{ color: step.color }">{{ step.msg }}</span>
                        </template>
                        <template #description>
                            <span style="font-size: 12px; color: #999;">{{ step.time }}</span>
                        </template>
                    </a-step>
                </a-steps>
                <div style="width: 100%;text-align: center;padding-top: 20px;" v-if="confirmLoading">
                    <a-spin :indicator="indicator" tip="正在申请中，请勿退出程序"/>
                </div>
                <a-flex v-if="confirmLoading" style="margin-top: 16px;" justify="center">
                    <a-button danger @click="cancelApplyTask">停止本次任务</a-button>
                </a-flex>
            </div>
        </a-modal>
        <a-modal v-model:open="successModal" :destroy-on-close="true" :footer="false" width="400px">
            <template #title>
                <a-flex justify="center">
                    <a-typography-title :level="5">
                        🎉🎉证书签发成功🎉🎉
                    </a-typography-title>
                </a-flex>
            </template>

            <a-space direction="vertical">
                <div>证书有效期: {{ new Date(sslInfo?.validFrom).toLocaleString() }} -
                    {{ new Date(sslInfo?.validTo).toLocaleString() }}
                </div>
                <div>此证书可用于以下域名</div>
                <div :style="{color: colorPrimary}" v-for="(d, i) in sslInfo.subdomain.split(',')" :key="i">{{
                        d
                    }}
                </div>
                <span>cert为证书文件，key为私钥文件</span>
                <span>部署使用这两个文件即可</span>
                <span>可在证书管理中查看申请记录</span>
                <a-space style="margin-top: 10px;">
                    <a-button-group>
                        <a-button @click.stop="copySslInfo('cert')">复制cert</a-button>
                        <a-button @click.stop="copySslInfo('key')">复制key</a-button>
                    </a-button-group>
                    <a-button type="primary" @click.stop="pushSSL" :icon="h(CloudUploadOutlined)">推送</a-button>
                    <a-button @click="openSSL">证书管理</a-button>
                </a-space>
            </a-space>
        </a-modal>
    </div>
</template>

<style scoped lang="scss">
</style>
