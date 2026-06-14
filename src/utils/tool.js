import {cloudsData} from "./data.js";
import {message, notification} from "ant-design-vue";
import JSZip from "jszip";
import psl from 'psl';
import {a} from "./salt.js";
import * as x509 from '@peculiar/x509'
import confetti from 'canvas-confetti';
import {TcpmkDnsTool} from "@/utils/TcpmkDnsTool";

const dns = preload.dns

const crypto = preload.crypto
const Buffer = preload.buffer

// 格式化utc时间为本地时间
export function formatDateLocal(date) {
    const year = date.getFullYear(); // 本地年
    const month = String(date.getMonth() + 1).padStart(2, '0'); // 本地月
    const day = String(date.getDate()).padStart(2, '0'); // 本地日
    const hours = String(date.getHours()).padStart(2, '0'); // 本地时
    const minutes = String(date.getMinutes()).padStart(2, '0'); // 本地分
    const seconds = String(date.getSeconds()).padStart(2, '0'); // 本地秒
    return `${year}-${month}-${day} ${hours}:${minutes}:${seconds}`;
}

export function parseCertificate(certString) {
    const cert = new x509.X509Certificate(certString);
    const derBuffer = Buffer.from(cert.rawData);
    // 计算SHA1指纹
    const sha1 = crypto.createHash('sha1')
        .update(derBuffer)
        .digest('hex')
        .toUpperCase()
        .match(/.{2}/g)
        .join(':');

// 计算SHA256指纹
    const sha256 = crypto.createHash('sha256')
        .update(derBuffer)
        .digest('hex')
        .toUpperCase()
        .match(/.{2}/g)
        .join(':');

    const certJson = JSON.parse(JSON.stringify(cert));
    const subject = transformCertFormat(certJson, 'subjectName');
    const issuer = transformCertFormat(certJson, 'issuerName');
    // 计算天数
    const validity = Math.floor((cert.notAfter - cert.notBefore) / (1000 * 60 * 60 * 24));
    return {
        subject: {
            commonName: subject["CN"] || "",
            country: subject["C"] || "",
            state: subject["ST"] || "",
            locality: subject["L"] || "",
            organization: subject["O"] || "",
            organizationalUnit: subject["OU"] || "",
        },
        issuer: {
            commonName: issuer["CN"] || "",
            country: issuer["C"] || "",
            organization: issuer["O"] || "",
        },
        info: {
            cert_belong: getCertificateType(cert), // 认证类型
            serialNumber: cert.serialNumber,
            ...getCertType(cert), // 证书 用途
            public_key: certJson.publicKey.algorithm.name, // 密钥类型
            public_key_size: certJson.publicKey.algorithm.namedCurve, // 密钥强度
            signatureAlgorithm: certJson.signatureAlgorithm.hash.name, // 签名算法
            cer_signture: Buffer.from(cert.signature).toString('hex'), // 证书签名
            notBefore: formatDateLocal(cert.notBefore),
            notAfter: formatDateLocal(cert.notAfter),
            // 有效期
            validity: validity,
            sha1Fingerprint: sha1,
            sha2Fingerprint: sha256,
            // 备用名
            altNames: certJson.extensions.filter(e => e.type === '2.5.29.17')[0].names.map(s => {
                return s.value;
            }),
            caUrl: certJson.extensions.filter(e => e.type === '1.3.6.1.5.5.7.1.1')[0].caIssuers[0].value,
            ocsp: certJson.extensions.filter(e => e.type === '1.3.6.1.5.5.7.1.1')[0]?.ocsp[0]?.value,
        },
    };
}

function randomInRange(min, max) {
    return Math.random() * (max - min) + min;
}

const flowers = () => {
    // 使用定时器 300ms 播放一次 共播放6次
    let times = 0;
    let timer = setInterval(() => {
        confetti({
            zIndex: 8898989,
            angle: randomInRange(55, 125),
            spread: randomInRange(50, 70),
            particleCount: randomInRange(50, 100),
            origin: {y: 0.6},
            colors: [
                "#ff1744",
                "#d500f9",
                "#651fff",
                "#3d5afe",
                "#00e5ff",
                "#2196f3",
                "#00e676",
                "#ffea00",
                "#ff9100",
                "#ff3d00",
            ],
            shapes: ['square', 'circle', 'star']
        });
        times++;
        if (times >= 6) {
            clearInterval(timer)
            timer = null
        }
    }, 300)
}

// 撒花函数
export function congratulations() {
    flowers()
}


export function getItem(key, initValue = null) {
    let value = utools.dbStorage.getItem(key);
    if (value) {
        return JSON.parse(preload.decrypt(value, a()));
    }
    return initValue;
}

export function setItem(key, value) {
    utools.dbStorage.setItem(key, preload.encrypt(JSON.stringify(value), a()));
}

const prefix = "cloud"

const domainPrefix = "xdomain"

const privateZonePrefix = "private_zone"


const accountPrefix = "account"

const sslPrefix = "ssl"

function getNow() {
    // 返回 ymdhms
    return new Date().toISOString().replace(/[-:]/g, "").replace("T", "").split(".")[0];
}

function getKey(prefix) {
    return `${prefix}/${getNow()}_${randomString(6)}`;
}

export function saveSettingDb(value, key = null) {
    if (!key) {
        key = getKey(accountPrefix);
    }
    setItem(key, value);
    return key;
}

const pushPlatformPrefix = "push_platform"

export function savePushPlatform(value, key = null) {
    if (!key) {
        key = getKey(pushPlatformPrefix);
    }
    setItem(key, value);
    return key;
}


export function getAllPushplatform() {
    const keys = utools.db.allDocs(pushPlatformPrefix)
    return keys.map(item => {
        return {
            _id: item._id,
            ...JSON.parse(preload.decrypt(item.value, a()))
        };
    }).reverse()
}


export function initCloudData() {
    return [];
}

export function getValidCloudData() {
    const data = initCloudData();
    return data.filter(item => item.tokens.some(item => item.value));
}

export function clearCloudDb(key) {
    const dataKey = `${prefix}/${key}`;
    utools.dbStorage.removeItem(dataKey);
}

export function saveDomain(domain, cloud, extra = {}) {
    const dataKey = `${domainPrefix}/${cloud}/${domain}`;
    utools.dbStorage.setItem(dataKey, {
        domain, cloud, ...extra
    });
}

export function getPrivateZoneKey(zone) {
    return `${privateZonePrefix}/${zone.cloud}/${zone.account_key}/${zone.zone_id}`;
}

export function savePrivateZone(zone) {
    if (!zone.zone_id || !zone.cloud || !zone.account_key) {
        throw new Error("私有解析Zone缺少必要标识");
    }
    utools.dbStorage.setItem(getPrivateZoneKey(zone), zone);
    return getPrivateZoneKey(zone);
}

export function deletePrivateZoneDb(zone) {
    utools.dbStorage.removeItem(getPrivateZoneKey(zone));
}

export function getAllPrivateZones() {
    const accounts = getAllAccount();
    const accountMap = accounts.reduce((acc, item) => {
        acc[item._id] = item;
        return acc;
    }, {});
    return utools.db.allDocs(privateZonePrefix).map(item => {
        return {
            _id: item._id,
            ...item.value
        };
    }).map(item => {
        return {
            ...item,
            cloud_info: getDomainBaseCloud(item.cloud),
            account_info: accountMap[item.account_key]
        };
    }).filter(item => item.account_info).sort((a, b) => {
        return (a.zone_name || "").localeCompare(b.zone_name || "");
    });
}

export function getPrivateZone(cloud, accountKey, zoneId) {
    return utools.dbStorage.getItem(`${privateZonePrefix}/${cloud}/${accountKey}/${zoneId}`);
}

export function deleteDomainDb(cloud, domain) {
    const dataKey = `${domainPrefix}/${cloud}/${domain}`;
    utools.dbStorage.removeItem(dataKey);
}

// 获取全部域名
export function getAllDomains() {
    // 获取全部的服务器账号信息
    const accounts = getAllAccount();
    // 改成 key => v
    const accountMap = accounts.reduce((acc, item) => {
        acc[item._id] = item;
        return acc;
    }, {})
    const keys = utools.db.allDocs(domainPrefix)
    let res = keys.map(item => {
        return {
            _id: item._id,
            ...item.value
        }
    }).map(item => {
        return {
            ...item,
            cloud_info: getDomainBaseCloud(item.cloud),
            account_info: accountMap[item.account_key]
        }
    })

    // 按照字母排序
    res.sort((a, b) => {
        return a.domain.localeCompare(b.domain);
    })
    return res;
}


export function getDomainBaseCloud(key) {
    return cloudsData.find(item => item.key === key);
}

export function getDomain(key) {
    const dataKey = `${domainPrefix}/${key}`;
    return utools.dbStorage.getItem(dataKey);
}


export function setDomainExpireTime(key, expireTime, renewLink) {
    const dataKey = `${domainPrefix}/${key}`;
    utools.dbStorage.setItem(dataKey, {
        ...getDomain(key),
        expire_time: expireTime,
        renew_link: renewLink
    });
}

export function xcopyText(value, msg = "复制成功") {
    utools.copyText(value);
    message.success(msg);
}

export function randomString(len = 16) {
    const $chars = 'ABCDEFGHJKMNPQRSTWXYZabcdefhijkmnprstwxyz2345678';
    const maxPos = $chars.length;
    let pwd = '';
    for (let i = 0; i < len; i++) {
        pwd += $chars.charAt(Math.floor(Math.random() * maxPos));
    }
    return pwd;
}

export function getAllAccount() {
    const keys = utools.db.allDocs(accountPrefix)
    return keys.map(item => {
        return {
            _id: item._id,
            ...JSON.parse(preload.decrypt(item.value, a()))
        };
    }).map(item => {
        return {
            ...item,
            cloud_info: getDomainBaseCloud(item.cloud_key)
        }
    }).reverse()
}

export function openDoc(url) {
    utools.ubrowser.goto(url).run({width: 1200, height: 800});
}

export function goScore(pluginName = "域名助手") {
    //utools.redirect(['管理中心', '插件应用市场内搜索'], pluginName)
    utools.shellOpenExternal("utools://域名助手")
}

export function saveSslInfo(domain, subdomain, sslinfo) {
    let key = `${sslPrefix}/${subdomain}`;
    utools.dbStorage.setItem(key, {
        domain, subdomain, ...sslinfo
    });
    return key;
}

export function getAllSslInfo() {
    const keys = utools.db.allDocs(`${sslPrefix}/`)
    return keys.map(item => {
        return {
            _id: item._id,
            ...item.value
        }
    }).sort((a, b) => {
        // 按时间戳排序 降序 validFrom
        return b.validFrom - a.validFrom;
    })
}

export function getAvailableSSL() {
    let all = getAllSslInfo();
    return all.filter(item => item.validTo > new Date().getTime());
}

export function getDnsServer(domain) {
    // 获取DNS服务器 优先使用 tcp.mk服务
    return new Promise(async (resolve, reject) => {
        const nsname = await TcpmkDnsTool.getFirstNsServer(domain);
        if (nsname) {
            resolve({
                nsname: nsname
            });
            return;
        }
        dns.resolveNs(domain, (err, address) => {
            if (err) {
                reject(err);
            } else {
                resolve({
                    nsname: address?.[0] || ""
                });
            }
        });
    });
}


// 根据给定的天数，判断ssl证书 有效期

export function getSomeSsl(days = 0) {
    const now = new Date().getTime();
    return getAllSslInfo().filter(item => {
        return item.validTo - now <= days * 24 * 60 * 60 * 1000;
    })
}

export function containsAnySubstring(array, str) {
    return array.some(substring => str.includes(substring));
}


export function getFullDomainByItem(item, domain = "") {
    return item.Name === "@" ? (item.Domain || domain) : `${item.Name}.${(item.Domain || domain)}`;
}

export function exportSSL(item) {
    const zipFile = JSZip()
    let prefix = item.domain
    // 检测如果域名是泛域名，那么证书文件名加上_wildcard 去掉 * 号
    if (prefix.startsWith("*.")) {
        prefix = prefix.replace("*.", "") + "_wildcard"
    }
    zipFile.file(`${prefix}.csr`, item.csr, {binary: false});
    zipFile.file(`${prefix}.key`, item.key, {binary: false});
    zipFile.file(`${prefix}.cert`, item.cert, {binary: false});
    zipFile.generateAsync({type: "uint8array"}).then(file => {
        preload.saveFile({
            title: '导出ssl证书',
            buttonLabel: '导出',
            defaultPath: utools.getPath('downloads') + `/${prefix}_ssl证书.zip`,
            filters: [{name: 'Zip File', extensions: ['zip']}]
        }, file).then((path) => {
            message.success("证书导出成功")
            utools.shellShowItemInFolder(path)
        }).catch(err => {
            if (err.toString() === "用户取消下载") {
                message.info("用户取消下载")
            } else {
                notification.error({
                    message: '导出失败', description: err.toString(), duration: 10
                });
            }
        })
    });
}

export function getRootDomain(domain) {
    // 如果是泛域名 干掉泛域名前缀
    if (domain.indexOf('*') !== -1) {
        domain = domain.replace('*.', '');
    }
    return psl.get(domain);
}

export function goUrl(url) {
    utools.shellOpenExternal(url);
}

const EV_OIDS = new Set([
    '2.16.840.1.114412.2.1', // DigiCert EV
    '1.3.6.1.4.1.34697.2.1', // GlobalSign EV
    '1.3.6.1.4.1.14370.1.6', // GeoTrust EV
]);

function getCertificateType(cert) {
    try {
        // 1. 检查扩展字段中的策略 OID
        const policies = cert.extensions
            .find(ext => ext.name === 'Certificate Policies')
            ?.value.match(/(\d+\.)+\d+/g) || [];
        // 判断 EV（优先级最高）
        if (policies.some(oid => EV_OIDS.has(oid))) {
            return 'EV';
        }
        // 判断 OV/DV 的标准策略 OID
        if (policies.includes('2.23.140.1.2.2')) {
            return 'OV';
        } else if (policies.includes('2.23.140.1.2.1')) {
            return 'DV';
        }
        // 2. 回退：检查主题字段中的组织信息
        const hasOrganization = cert.subject.includes('O=');
        return hasOrganization ? 'OV' : 'DV';
    } catch (error) {
        console.error('证书解析失败:', error);
        return 'Unknown';
    }
}
function getCertType(certJson) {
    // 判断证书类型
    const isCA = certJson.extensions.filter(e => e.type === '2.5.29.19')[0].ca
    const keyUsages = certJson.extensions.filter(e => e.type === '2.5.29.37')[0].usages || []
    // 类型判断逻辑
    let certType = '其他证书';
    if (!isCA && keyUsages.includes(x509.ExtendedKeyUsage.serverAuth)) {
        certType = '服务器证书';
    } else if (isCA) {
        certType = 'CA证书';
    }
    // 提取证书用途
    /*
        serverAuth = "1.3.6.1.5.5.7.3.1",
    clientAuth = "1.3.6.1.5.5.7.3.2",
    codeSigning = "1.3.6.1.5.5.7.3.3",
    emailProtection = "1.3.6.1.5.5.7.3.4",
    timeStamping = "1.3.6.1.5.5.7.3.8",
    ocspSigning = "1.3.6.1.5.5.7.3.9"
     */
    const purposes = [];
    keyUsages
        .map(usage => {
            switch (usage) {
                case x509.ExtendedKeyUsage.serverAuth:
                    purposes.push('serverAuth');
                    break;
                case x509.ExtendedKeyUsage.clientAuth:
                    purposes.push('clientAuth');
                    break
                case x509.ExtendedKeyUsage.codeSigning:
                    purposes.push('codeSigning');
                    break;
                case x509.ExtendedKeyUsage.emailProtection:
                    purposes.push('emailProtection');
                    break;
                case x509.ExtendedKeyUsage.timeStamping:
                    purposes.push('timeStamping');
                    break;
                case x509.ExtendedKeyUsage.ocspSigning:
                    purposes.push('ocspSigning');
                    break;
                default:
                    return null;
            }
        });
    return {
        certType,
        purposes,
    };
}

function transformCertFormat(input, key) {
    // 创建累积结果字典
    const accumulator = new Map();

    // 遍历所有subject条目
    (input?.[key] || []).forEach(subject => {
        // 遍历每个字段
        Object.entries(subject || {}).forEach(([field, values]) => {
            // 标准化为数组格式
            const normalized = Array.isArray(values) ? values : [values];

            // 过滤空值并累积结果
            normalized.filter(Boolean).forEach(value => {
                const current = accumulator.get(field) || new Set();
                current.add(value);
                accumulator.set(field, current);
            });
        });
    });

    // 转换为最终结果对象
    return Array.from(accumulator.entries()).reduce((result, [field, values]) => {
        // 自动展开单元素数组
        const finalValues = Array.from(values);
        result[field] = finalValues.length > 1 ? finalValues : finalValues[0];
        return result;
    }, {});
}
