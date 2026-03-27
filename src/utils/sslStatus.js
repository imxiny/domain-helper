import {randomString} from "@/utils/tool";

export const SSL_STATUS = {
    INIT: 'init',                    // 初始化状态，已创建订单
    DNS_PENDING: 'dns_pending',      // 等待DNS验证
    DNS_VERIFIED: 'dns_verified',    // DNS记录验证通过
    CHALLENGE_PENDING: 'challenge_pending',    // 等待ACME验证
    CHALLENGE_VERIFIED: 'challenge_verified',  // ACME验证通过
    CERT_PENDING: 'cert_pending',    // 等待证书签发
    COMPLETED: 'completed',          // 完成
    FAILED: 'failed'                 // 失败
}

export const getStatusText = (status) => {
    const statusMap = {
        [SSL_STATUS.INIT]: '初始化',
        [SSL_STATUS.DNS_PENDING]: '等待DNS验证',
        [SSL_STATUS.DNS_VERIFIED]: 'DNS已验证',
        [SSL_STATUS.CHALLENGE_PENDING]: '等待ACME验证',
        [SSL_STATUS.CHALLENGE_VERIFIED]: 'ACME已验证',
        [SSL_STATUS.CERT_PENDING]: '等待签发',
        [SSL_STATUS.COMPLETED]: '已完成',
        [SSL_STATUS.FAILED]: '失败'
    }
    return statusMap[status] || status
}

export const getStatusColor = (status) => {
    const colorMap = {
        [SSL_STATUS.INIT]: 'blue',
        [SSL_STATUS.DNS_PENDING]: 'orange',
        [SSL_STATUS.DNS_VERIFIED]: 'green',
        [SSL_STATUS.CHALLENGE_PENDING]: 'orange',
        [SSL_STATUS.CHALLENGE_VERIFIED]: 'green',
        [SSL_STATUS.CERT_PENDING]: 'orange',
        [SSL_STATUS.COMPLETED]: 'green',
        [SSL_STATUS.FAILED]: 'red'
    }
    return colorMap[status] || 'default'
}

const sslApplyPrefix = 'ssl_apply'
export const saveSslRecord = (record) => {
    const randStr = randomString(6);
    const id = `${sslApplyPrefix}/${Date.now()}_${randStr}`
    utools.dbStorage.setItem(id, record)
    return id
}

export const updateSslRecord = (id, record) => {
    utools.dbStorage.setItem(id, record)
}

export const getSslRecord = (id) => {
    return utools.dbStorage.getItem(id)
}

export const getAllDoingSslRecord = () => {
    const keys = utools.db.allDocs(sslApplyPrefix)
    return keys.map(item => {
        return {
            _id: item._id,
            ...item.value
        };
    }).filter(item => item.status !== SSL_STATUS.COMPLETED).reverse()
}
