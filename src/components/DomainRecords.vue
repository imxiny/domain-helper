<script setup>
import { message, Modal, notification, theme } from "ant-design-vue";
import {
  computed,
  h,
  onMounted,
  onBeforeUnmount,
  reactive,
  ref,
  createVNode,
  getCurrentInstance,
} from "vue";
import {
  DeleteOutlined,
  SyncOutlined,
  FormOutlined,
  SafetyCertificateOutlined,
  MonitorOutlined,
  ExclamationCircleOutlined,
  CloseOutlined,
  UploadOutlined,
  DownloadOutlined,
  VerifiedOutlined,
  HistoryOutlined,
  CloudUploadOutlined,
} from "@ant-design/icons-vue";
import { getAllDomains, getAllSslInfo, xcopyText } from "@/utils/tool";
import { getDnsService } from "@/service/DnsService";
import AddDomainRecord from "./AddDomainRecord.vue";
import { RecordTypes } from "@/utils/data";
import { useThemeStore } from "@/stroes/themeStore.js";
import {
  addSslMonitor,
  batchAddSslMonitorLogic,
  getAllSslMonitor,
} from "@/utils/sslMonitor";
import router from "@/router";
import { ArrayUtils } from "@/utils/ArrayUtils";

const themeStore = useThemeStore();

const colorPrimary = computed(() => themeStore.themeColor);
const { useToken } = theme;
const { token } = useToken();

const allDomains = ref([]);

const refreshAllDomains = () => {
  allDomains.value = getAllDomains();
};
onMounted(() => {
  refreshAllDomains();
});
const nowDomainInfo = ref({
  domain: "",
  cloud: "",
  account_key: "",
  cloud_info: {
    name: "",
    key: "",
    title: "",
    color: "",
    icon: "",
    tokens: [
      {
        key: "ID",
        value: "",
      },
      {
        key: "Secret",
        value: "",
      },
    ],
    columns: [],
  },
  account_info: {
    _id: "",
    cloud_key: "",
    tag: "",
    tokens: [
      {
        key: "ID",
        value: "",
      },
      {
        key: "Secret",
        value: "",
      },
    ],
    cloud_info: {
      name: "",
      key: "",
      title: "",
      color: "",
      icon: "",
      tokens: [
        {
          key: "ID",
          value: "",
        },
        {
          key: "Secret",
          value: "",
        },
      ],
    },
  },
});
// const emit = defineEmits(['close-domain']);
const records = ref([]);
const count = ref(0);
const loading = ref(false);

// 添加计算属性来统计不同类型的记录数量
const recordTypeCounts = computed(() => {
  const typeCounts = {};
  records.value.forEach((record) => {
    typeCounts[record.Type] = (typeCounts[record.Type] || 0) + 1;
  });
  return typeCounts;
});

// 获取监控中的所有记录
const allMonitorRecords = ref([]);

const getAllMonitorRecords = () => {
  allMonitorRecords.value = getAllSslMonitor();
};

const refreshRecords = () => {
  selectedRecords.value = [];
  getAllMonitorRecords();
  const dbsService = getDnsService(
    nowDomainInfo.value.account_key,
    nowDomainInfo.value.cloud,
    nowDomainInfo.value.account_info.tokens
  );
  loading.value = true;
  dbsService
    .listRecords(nowDomainInfo.value.domain)
    .then((r) => {
      count.value = r.count;
      //records.value = r.list

      // 获取当前域名下的所有ssl证书
      let allSsl = getAllSslInfo().filter((i) =>
        i.subdomain.includes(nowDomainInfo.value.domain)
      );
      // 为 r.list 附加 ssl 证书信息 只有 A AAAA CNAME 类型的记录才有证书
      const now = Date.now();
      records.value = r.list.map((i) => {
        let fulldomain =
          i.Name === "@"
            ? nowDomainInfo.value.domain
            : i.Name + "." + nowDomainInfo.value.domain;
        if (["A", "AAAA", "CNAME"].includes(i.Type)) {
          i.ssl = allSsl.find((j) => j.subdomain.includes(fulldomain));
          // 计算证书有效期
          if (i.ssl) {
            i.ssl.expired = Math.floor(
              (i.ssl.validTo - now) / 1000 / 60 / 60 / 24
            );
          }
          i.monitor = allMonitorRecords.value.find((j) => j.uri === fulldomain);
          // 计算监控证书有效期
          if (i.monitor) {
            i.monitor.expired = Math.floor(
              (i.monitor.expire_time - now) / 1000 / 60 / 60 / 24
            );
          }
        }
        return i;
      });
    })
    .catch((e) => {
      notification.error({
        message: "获取解析记录失败",
        description: e.toString(),
        duration: 10,
      });
      records.value = [];
    })
    .finally(() => {
      loading.value = false;
    });
};

const initRecords = (domainInfo) => {
  nowDomainInfo.value = domainInfo;
  refreshAllDomains();
  refreshRecords();
};

// 接收domain-info prop
const props = defineProps({
  domainInfo: {
    type: Object,
    required: true,
  },
});

onMounted(() => {
  initRecords(props.domainInfo);
});

const { proxy } = getCurrentInstance();
const createSsl = (record) => {
  console.log(record);
  proxy.$eventBus.emit("open-ssl-apply", {
    domain: nowDomainInfo.value.domain,
    sub: record.Name,
    cloud: nowDomainInfo.value.cloud,
    account_key: nowDomainInfo.value.account_key,
  });
};

const deleteRecord = (record) => {
  Object.assign(deleteNowRecord, {
    RecordId: record.RecordId,
    Name: record.Name,
    Value: record.Value,
    TTL: record.TTL,
    Type: record.Type,
  });
  Modal.confirm({
    title: "删除记录",
    icon: createVNode(ExclamationCircleOutlined),
    content: h("div", null, [
      h("span", null, "确认删除记录"),
      h(
        "span",
        {
          style: {
            color: colorPrimary.value,
            marginLeft: "10px",
          },
        },
        record.Name === "@"
          ? nowDomainInfo.value.domain
          : record.Name + "." + nowDomainInfo.value.domain
      ),
    ]),
    okText: "确认",
    cancelText: "取消",
    onOk: deleteRecordDo,
  });
};
const deleteNowRecord = reactive({
  RecordId: "",
  Name: "",
  Value: "",
  TTL: 0,
  Type: "",
});
const deleteRecordDo = () => {
  loading.value = true;
  const dbsService = getDnsService(
    nowDomainInfo.value.account_key,
    nowDomainInfo.value.cloud,
    nowDomainInfo.value.account_info.tokens
  );
  dbsService
    .deleteRecord(
      nowDomainInfo.value.domain,
      deleteNowRecord.RecordId,
      deleteNowRecord
    )
    .then((r) => {
      message.success(`记录 ${deleteNowRecord.Name} 删除成功`);
      initRecords(nowDomainInfo.value);
    })
    .catch((e) => {
      notification.error({
        message: "删除记录失败",
        description: e.toString(),
        duration: 10,
      });
      loading.value = false;
    });
};

const searchForm = reactive({
  type: null,
  keyword: "",
  isMonitoring: null,
  status: null,
});

const calcRecords = computed(() => {
  const key = searchForm.keyword.toString().toLowerCase();

  // 如果没有任何过滤条件，直接返回所有记录
  if (
    !key &&
    !searchForm.type &&
    !searchForm.isMonitoring &&
    !searchForm.status
  ) {
    return records.value;
  }

  let filteredRecords = (records.value || []).filter((item) => {
    const matchKeyword =
      item.Name.toLowerCase().includes(key) ||
      item.Value.toLowerCase().includes(key);
    const matchType = !searchForm.type || item.Type === searchForm.type;
    const matchMonitoring = !searchForm.isMonitoring || item.monitor;
    const matchStatus =
      !searchForm.status || item.Status === (searchForm.status === "true");
    return matchKeyword && matchType && matchMonitoring && matchStatus;
  });

  if (!key) {
    return filteredRecords;
  }
  const columns = ["Name", "Value"];
  return ArrayUtils.sortByRelevance(filteredRecords, key, columns);
});

const monitoringRecords = computed(() => {
  return records.value.filter((i) => i.monitor);
});

defineExpose({
  initRecords,
});

const baseColumns = [
  {
    title: "主机记录",
    dataIndex: "Name",
    key: "Name",
    fixed: "left",
    align: "center",
  },
  {
    title: "类型",
    dataIndex: "Type",
    key: "Type",
    width: 90,
    align: "center",
  },
  {
    title: "记录值",
    dataIndex: "Value",
    key: "Value",
    align: "center",
  },
  {
    title: "TTL",
    dataIndex: "TTL",
    key: "TTL",
    align: "center",
    width: 76,
  },
];

const actionColumn = {
  title: "操作",
  key: "operation",
  // fixed: 'right',
  width: 110,
};

const columns = computed(() => {
  const base = baseColumns;
  const special = nowDomainInfo.value.cloud_info.columns || [];
  return [...base, ...special, actionColumn];
});
// 使用计算属性 获取body的高度
const xbody = ref(null);
const height = ref(0);
let resizeObserver = null;
const updateHeight = () => {
  if (xbody.value) {
    height.value = xbody.value.clientHeight - 56;
  }
};
onMounted(() => {
  resizeObserver = new ResizeObserver(updateHeight);
  if (xbody.value) {
    resizeObserver.observe(xbody.value);
    updateHeight(); // 初始化时获取一次高度
  }
});

onBeforeUnmount(() => {
  if (resizeObserver && xbody.value) {
    resizeObserver.unobserve(xbody.value);
  }
});
const addDomainRecordModal = ref(null);

const addRecord = () => {
  if (addDomainRecordModal.value) {
    addDomainRecordModal.value.openModal(
      nowDomainInfo.value,
      null,
      records.value
    );
  }
};

const copyDomain = (name) => {
  if (name === "@") {
    xcopyText(nowDomainInfo.value.domain, "完整域名已复制");
  } else {
    xcopyText(name + "." + nowDomainInfo.value.domain, "完整域名已复制");
  }
};
const selectDomain = (value) => {
  const domain = allDomains.value.find((i) => i._id === value);
  if (domain) {
    nowDomainInfo.value = domain;
    refreshRecords();
  }
};

const changeStatus = (value, e, record) => {
  Modal.confirm({
    title: "修改状态",
    icon: createVNode(ExclamationCircleOutlined),
    content: h("div", null, [
      h("span", null, "确认修改记录"),
      h(
        "span",
        { style: { color: colorPrimary.value, marginLeft: "10px" } },
        record.Name
      ),
      h("span", { style: { marginLeft: "10px" } }, "状态为"),
      h(
        "span",
        { style: { color: value ? "#40c057" : "#f03e3e", marginLeft: "10px" } },
        value ? "启用" : "暂停"
      ),
    ]),
    okText: "确认",
    cancelText: "取消",
    onOk: () => {
      const dnsService = getDnsService(
        nowDomainInfo.value.account_key,
        nowDomainInfo.value.cloud,
        nowDomainInfo.value.account_info.tokens
      );
      dnsService
        .changeRecordStatus(nowDomainInfo.value.domain, record.RecordId, {
          Status: value,
        })
        .then((r) => {
          message.success(`记录 ${record.Name} 修改状态成功`);
          record.Status = value;
          refreshRecords();
        })
        .catch((e) => {
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
const editRecord = (record) => {
  if (addDomainRecordModal.value) {
    addDomainRecordModal.value.openModal(
      nowDomainInfo.value,
      record,
      records.value
    );
  }
};

const monitorRecordSsl = (record) => {
  const fullUrl =
    record.Name === "@"
      ? nowDomainInfo.value.domain
      : record.Name + "." + nowDomainInfo.value.domain;
  addSslMonitor({
    uri: `https://${fullUrl}`,
    type: record.Type,
    address: record.Value,
    remark: record.Remark,
    domain: nowDomainInfo.value.domain,
    cloud: nowDomainInfo.value.cloud,
    account_key: nowDomainInfo.value.account_key,
  })
    .then((r) => {
      message.success(`监控 ${fullUrl} 成功`);
    })
    .catch((e) => {
      console.error(e);
      notification.error({
        message: "监控失败",
        description: e.toString(),
        duration: 10,
      });
    });
};

const handleMenuClick = (key, record) => {
  if (key === "applySSL") {
    createSsl(record);
  } else if (key === "deleteRecord") {
    deleteRecord(record);
  } else if (key === "renewSSL") {
    router.push({ name: "SslRecords", query: { ssl: record.ssl._id } });
  } else if (key === "createSSL") {
    createSsl(record);
  } else if (key === "monitorSSL") {
    monitorRecordSsl(record);
  } else if (key === "pushSSL") {
    proxy.$eventBus.emit("open-ssl-push", record.ssl);
  }
};

const selectedRecords = ref([]);
const selectedRowKeys = ref([]);
const rowSelection = {
  selectedRowKeys: selectedRowKeys,
  onChange: (keys, selectedRows) => {
    selectedRowKeys.value = keys;
    // 过滤 NS 和 SOA 类型 不能删除
    selectedRecords.value = selectedRows.filter(
      (i) => !["NS", "SOA"].includes(i.Type)
    );
  },
};
const batchDelete = () => {
  Modal.confirm({
    title: "批量删除记录",
    icon: createVNode(ExclamationCircleOutlined),
    content: h("div", { style: { marginBottom: "10px" } }, [
      h("div", null, "确认删除选中的记录"),
      selectedRecords.value.map((i) =>
        h(
          "div",
          { style: { color: colorPrimary.value } },
          i.Name === "@"
            ? nowDomainInfo.value.domain
            : `${i.Name}.${nowDomainInfo.value.domain}`
        )
      ),
      h("div", { style: { color: "red", marginTop: "10px" } }, "请谨慎操作"),
    ]),
    okText: "确认",
    cancelText: "取消",
    onOk: () => {
      loading.value = true;
      const dnsService = getDnsService(
        nowDomainInfo.value.account_key,
        nowDomainInfo.value.cloud,
        nowDomainInfo.value.account_info.tokens
      );
      Promise.all(
        selectedRecords.value.map((i) =>
          dnsService.deleteRecord(nowDomainInfo.value.domain, i.RecordId, i)
        )
      )
        .then((r) => {
          message.success(
            `记录 ${selectedRecords.value
              .map((i) => i.Name)
              .join(", ")} 删除成功`
          );
          refreshRecords();
        })
        .catch((e) => {
          notification.error({
            message: "删除记录失败",
            description: e.toString(),
            duration: 10,
          });
        });
    },
  });
};

const batchMonitor = () => {
  const canMonitor = selectedRecords.value.filter((i) =>
    ["A", "CNAME", "AAAA"].includes(i.Type)
  );
  if (canMonitor.length === 0) {
    message.warning("无效记录，请选择A、CNAME、AAAA类型的记录");
    return;
  }
  Modal.confirm({
    title: "批量监控SSL",
    icon: createVNode(ExclamationCircleOutlined),
    content: h("div", { style: { marginBottom: "10px" } }, [
      h("div", null, "确认监控选中的记录"),
      selectedRecords.value.map((i) =>
        h(
          "div",
          { style: { color: colorPrimary.value } },
          i.Name === "@"
            ? nowDomainInfo.value.domain
            : `${i.Name}.${nowDomainInfo.value.domain}`
        )
      ),
      h(
        "div",
        {
          style: {
            color: token.value.colorTextLabel,
            marginTop: "10px",
          },
        },
        "监控后，证书过期时间会自动更新到SSL监控列表中"
      ),
    ]),
    okText: "确认",
    cancelText: "取消",
    onOk: () => {
      selectedRowKeys.value = [];
      batchAddSslMonitorLogic(
        canMonitor.map((i) => ({
          uri:
            i.Name === "@"
              ? nowDomainInfo.value.domain
              : i.Name + "." + nowDomainInfo.value.domain,
          type: i.Type,
          address: i.Value,
          domain: nowDomainInfo.value.domain,
          remark: i.Remark,
          cloud: nowDomainInfo.value.cloud,
          account_key: nowDomainInfo.value.account_key,
        }))
      );
    },
  });
};

// 修改返回
const handleBack = () => {
  // 模拟点击 esc
  utools.simulateKeyboardTap("esc");
};

// 添加导出记录函数
const exportRecords = async (format = "json") => {
  // 创建要导出的数据
  const exportData = selectedRecords.value.map((record) => ({
    Name: record.Name,
    Type: record.Type,
    Value: record.Value,
    TTL: record.TTL,
    Remark: record.Remark,
    Status: record.Status,
  }));

  let content = "";
  let fileName = "";
  let filters = [];

  if (format === "json") {
    content = JSON.stringify(exportData, null, 2);
    fileName = `${nowDomainInfo.value.domain}_records.json`;
    filters = [{ name: "JSON", extensions: ["json"] }];
  } else if (format === "csv") {
    // CSV 表头
    const headers = ["主机记录", "记录类型", "记录值", "TTL", "备注", "状态"];
    const rows = exportData.map((record) => [
      record.Name,
      record.Type,
      record.Value,
      record.TTL,
      record.Remark || "",
      record.Status ? "启用" : "暂停",
    ]);

    // 添加 BOM 以支持中文
    content =
      "\ufeff" +
      [
        headers.join(","),
        ...rows.map((row) =>
          row
            .map((cell) => {
              // 如果单元格包含逗号、换行或引号，需要用引号包裹并处理引号
              if (/[,\n"]/.test(cell)) {
                return `"${cell.replace(/"/g, '""')}"`;
              }
              return cell;
            })
            .join(",")
        ),
      ].join("\n");

    fileName = `${nowDomainInfo.value.domain}_records.csv`;
    filters = [{ name: "CSV", extensions: ["csv"] }];
  }

  try {
    const res = await window.xSaveFile(
      {
        title: "保存解析记录",
        defaultPath: fileName,
        filters: filters,
      },
      content
    );
    Modal.confirm({
      title: "🎉🎉导出成功🎉🎉",
      icon: createVNode(DownloadOutlined),
      content: h("div", null, [h("span", null, "是否需要打开文件夹？")]),
      okText: "打开",
      cancelText: "取消",
      onOk: () => {
        utools.shellShowItemInFolder(res);
      },
    });
  } catch (error) {
    if (error === "用户取消下载") {
      return;
    }
    notification.error({
      message: "导出失败",
      description: error.toString(),
      duration: 10,
    });
  }
};

// 添加导入记录函数
const importRecords = async () => {
  try {
    // 打开文件选择对话框
    const filePath = utools.showOpenDialog({
      title: "选择记录文件",
      filters: [{ name: "JSON 或者 CSV", extensions: ["json", "csv"] }],
      properties: ["openFile"],
    });

    if (!filePath || !filePath[0]) return;
    // 读取文件内容
    const content = (await readLocalFile(filePath[0])).toString();
    let records;
    const fileExt = filePath[0].toLowerCase().split(".").pop();
    if (fileExt === "json") {
      records = JSON.parse(content);
    } else if (fileExt === "csv") {
      // 移除 BOM
      const csvContent = content.replace(/^\uFEFF/, "");
      const lines = csvContent.split("\n");
      const headers = lines[0].split(",");

      records = lines
        .slice(1)
        .filter((line) => line.trim())
        .map((line) => {
          const values = line.split(",").map((value) => {
            // 处理带引号的值
            if (value.startsWith('"') && value.endsWith('"')) {
              return value.slice(1, -1).replace(/""/g, '"');
            }
            return value;
          });

          return {
            Name: values[0],
            Type: values[1],
            Value: values[2],
            TTL: parseInt(values[3]),
            Remark: values[4],
            Status: values[5] === "启用",
          };
        });
    } else {
      throw new Error("不支持的文件格式");
    }

    if (!records || !records.length) {
      throw new Error("文件内容为空");
    }

    // 过滤掉MX类型的记录
    const filteredRecords = records.filter((record) => record.Type !== "MX");
    const mxCount = records.length - filteredRecords.length;
    if (mxCount > 0) {
      message.warning(`已跳过 ${mxCount} 条MX类型记录，暂不支持导入`);
    }

    // 确认导入
    Modal.confirm({
      title: "导入记录",
      icon: createVNode(ExclamationCircleOutlined),
      content: h("div", null, [
        h("p", null, `确认导入 ${filteredRecords.length} 条记录？`),
        h("p", { style: { color: "red" } }, "注意：相同记录将被跳过"),
      ]),
      okText: "确认",
      cancelText: "取消",
      async onOk() {
        loading.value = true;
        const dnsService = getDnsService(
          nowDomainInfo.value.account_key,
          nowDomainInfo.value.cloud,
          nowDomainInfo.value.account_info.tokens
        );

        // 获取当前所有记录用于比对
        const currentRecords = await dnsService.listRecords(
          nowDomainInfo.value.domain
        );
        const results = [];

        // 逐条处理记录
        for (const record of filteredRecords) {
          try {
            // 检查是否存在完全相同的记录
            const exists = currentRecords.list.some(
              (r) =>
                r.Name === record.Name &&
                r.Type === record.Type &&
                r.Value === record.Value &&
                r.TTL === record.TTL
            );

            if (exists) {
              results.push({
                record,
                status: "skipped",
                message: "记录已存在",
              });
              continue;
            }

            // 添加记录
            await dnsService.addRecord(nowDomainInfo.value.domain, {
              name: record.Name,
              type: record.Type,
              value: record.Value,
              ttl: record.TTL,
              remark: record.Remark || "",
            });
            results.push({
              record,
              status: "success",
              message: "添加成功",
            });
          } catch (error) {
            results.push({
              record,
              status: "error",
              message: error.toString(),
            });
          }
        }

        // 统计结果
        const successCount = results.filter(
          (r) => r.status === "success"
        ).length;
        const skipCount = results.filter((r) => r.status === "skipped").length;
        const errorCount = results.filter((r) => r.status === "error").length;

        // 显示结果对话框
        Modal.info({
          title: "导入结果",
          width: 600,
          content: h("div", null, [
            h("div", { style: { marginBottom: "10px" } }, [
              h(
                "span",
                { style: { color: token.value.colorSuccess } },
                `成功: ${successCount} 条`
              ),
              h(
                "span",
                {
                  style: {
                    marginLeft: "10px",
                    color: token.value.colorWarning,
                  },
                },
                `跳过: ${skipCount} 条`
              ),
              h(
                "span",
                {
                  style: {
                    marginLeft: "10px",
                    color: errorCount > 0 ? token.value.colorError : "inherit",
                  },
                },
                `失败: ${errorCount} 条`
              ),
            ]),
            h(
              "div",
              {
                style: {
                  maxHeight: "400px",
                  overflow: "auto",
                  border: "1px solid #d9d9d9",
                  borderRadius: "4px",
                  padding: "8px",
                },
              },
              results.map(({ record, status, message }) =>
                h(
                  "div",
                  {
                    style: {
                      marginBottom: "8px",
                      color:
                        status === "error"
                          ? token.value.colorError
                          : status === "skipped"
                          ? token.value.colorWarning
                          : token.value.colorSuccess,
                    },
                  },
                  [
                    h(
                      "div",
                      null,
                      `${record.Name} | ${record.Type} | ${record.Value} | ${record.TTL}`
                    ),
                    h("div", { style: { fontSize: "12px" } }, message),
                  ]
                )
              )
            ),
          ]),
          okText: "确定",
        });

        refreshRecords();
      },
      onCancel() {
        loading.value = false;
      },
    });
  } catch (error) {
    notification.error({
      message: "导入失败",
      description: error.toString(),
      duration: 10,
    });
  } finally {
    loading.value = false;
  }
};
const getMonitorColor = (days) => {
  if (days <= 10) {
    return token.value.colorError;
  } else if (days < 30) {
    return token.value.colorWarning;
  } else {
    return token.value.colorSuccess;
  }
};
</script>

<template>
  <div class="box_record">
    <a-flex class="h_header" align="center" gap="16px">
      <a-space :size="12">
        <div style="width: 100px; text-align: center">
          <img
            :src="nowDomainInfo.cloud_info.icon"
            alt=""
            style="height: 17px"
          />
        </div>
        <a-select
          show-search
          :value="nowDomainInfo._id"
          @change="selectDomain"
          style="width: 240px"
        >
          <a-select-option
            v-for="(i, index) in allDomains"
            :key="index"
            :value="i._id"
            >{{ i.cloud_info.title }}-{{ i.domain }}
          </a-select-option>
        </a-select>
        <a-space :size="8" style="min-width: 200px; margin: 0 auto">
          <a-tooltip>
            <template #title>
              <div v-for="(count, type) in recordTypeCounts" :key="type">
                {{ type }}: {{ count }}条
              </div>
            </template>
            <a-space :size="4">
              <a-typography-text>解析记录</a-typography-text>
              <a-typography-text
                style="font-weight: 500; font-family: fantasy sans-serif"
                :style="{ color: token.colorPrimary }"
                >{{ count }}
              </a-typography-text>
              <a-typography-text>条</a-typography-text>
            </a-space>
          </a-tooltip>
          <a-divider type="vertical" />
          <a-tooltip>
            <a-space :size="4">
              <a-typography-text>证书监控</a-typography-text>
              <a-typography-text
                style="font-weight: 500; font-family: fantasy sans-serif"
                :style="{ color: token.colorPrimary }"
                >{{ monitoringRecords.length }}
              </a-typography-text>
              <a-typography-text>条</a-typography-text>
            </a-space>
          </a-tooltip>
        </a-space>
      </a-space>
      <a-space :size="12">
        <a-button
          :icon="h(SyncOutlined)"
          @click="initRecords(nowDomainInfo)"
        ></a-button>
        <a-button type="primary" @click="handleBack">
          <template #icon>
            <CloseOutlined />
          </template>
        </a-button>
      </a-space>
    </a-flex>
    <a-flex
      class="header"
      :style="{ backgroundColor: token.colorBgContainer }"
      justify="space-between"
    >
      <a-flex align="baseline" gap="12">
        <a-select
          v-model:value="searchForm.type"
          allow-clear
          placeholder="解析类型"
          style="width: 160px"
        >
          <a-select-option
            v-for="(i, index) in RecordTypes"
            :key="index"
            :value="i"
            >{{ i }}</a-select-option
          >
        </a-select>
        <a-select
          v-model:value="searchForm.status"
          allow-clear
          placeholder="解析状态"
          style="width: 120px"
        >
          <a-select-option value="true">启用</a-select-option>
          <a-select-option value="false">暂停</a-select-option>
        </a-select>
        <a-input-search
          v-model:value="searchForm.keyword"
          placeholder="输入关键字检索"
          style="width: 200px"
        ></a-input-search>
        <a-checkbox v-model:checked="searchForm.isMonitoring">
          监控中
        </a-checkbox>
      </a-flex>
      <a-space :size="12">
        <a-button type="primary" @click="addRecord"> 添加记录 </a-button>

        <a-dropdown>
          <a-tooltip title="导出解析记录">
            <a-button :disabled="selectedRecords.length === 0">
              <template #icon>
                <DownloadOutlined />
              </template>
            </a-button>
          </a-tooltip>
          <template #overlay>
            <a-menu
              :disabled="selectedRecords.length === 0"
              @click="({ key }) => exportRecords(key)"
            >
              <a-menu-item key="json">JSON格式</a-menu-item>
              <a-menu-item key="csv">CSV格式</a-menu-item>
            </a-menu>
          </template>
        </a-dropdown>
        <a-tooltip>
          <template #title>
            <div>导入解析记录</div>
            <div>参考导出的JSON、CSV</div>
            <div>平台过多，测试未完整</div>
            <div>如遇BUG，可反馈</div>
          </template>
          <a-button @click="importRecords">
            <template #icon>
              <UploadOutlined />
            </template>
          </a-button>
        </a-tooltip>
        <a-tooltip title="批量删除记录">
          <a-button
            danger
            @click="batchDelete"
            :icon="h(DeleteOutlined)"
            :disabled="selectedRecords.length === 0"
          ></a-button>
        </a-tooltip>
        <a-tooltip title="批量监控SSL" placement="left">
          <a-button
            @click="batchMonitor"
            :icon="h(MonitorOutlined)"
            :disabled="selectedRecords.length === 0"
          ></a-button>
        </a-tooltip>
      </a-space>
    </a-flex>
    <div class="body" ref="xbody">
      <a-table
        :row-selection="rowSelection"
        :locale="{ emptyText: '暂无解析记录' }"
        sticky
        :scroll="{ y: 'calc(100vh - 172px)' }"
        :pagination="false"
        :row-key="(record) => record.RecordId"
        :loading="{
          spinning: loading,
          tip: '加载中...',
        }"
        :columns="columns"
        :data-source="calcRecords"
      >
        <template #headerCell="{ column }">
          <template v-if="column.key === 'operation'">
            <a-flex justify="center" align="center">操作</a-flex>
          </template>
          <template v-if="column.key === 'ProxyStatus'">
            <a-flex justify="center" align="center">代理状态</a-flex>
          </template>
        </template>

        <template #bodyCell="{ column, record }">
          <template v-if="column.key === 'Name'">
            <div class="name" @click="copyDomain(record.Name)">
              <a-space :size="4">
                <a-tooltip v-if="record.ssl">
                  <template #title>
                    <div>本地证书</div>
                    <div>
                      {{
                        record.ssl.expired > 0
                          ? `有效期 ${record.ssl.expired} 天`
                          : "证书已过期"
                      }}
                    </div>
                  </template>
                  <SafetyCertificateOutlined
                    :style="{ color: getMonitorColor(record.ssl.expired) }"
                  />
                </a-tooltip>
                <a-tooltip v-if="record.monitor">
                  <template #title>
                    <div>证书监控中</div>
                    <div>有效期 {{ record.monitor.expired }} 天</div>
                  </template>
                  <MonitorOutlined
                    :style="{ color: getMonitorColor(record.monitor.expired) }"
                  />
                </a-tooltip>
                <div class="name">{{ record.Name }}</div>
              </a-space>
            </div>
          </template>
          <template v-if="column.key === 'Remark'">
            <div class="name">
              {{ record.Remark }}
            </div>
          </template>
          <template v-if="column.key === 'Value'">
            <div class="name" @click="xcopyText(record.Value)">
              {{ record.Value }}
            </div>
          </template>
          <template v-if="column.key === 'Status'">
            <template v-if="column.canEdit">
              <a-switch
                @change="(k, e) => changeStatus(k, e, record, column)"
                v-model:checked="record.Status"
                un-checked-children="暂停"
                :checked-value="true"
                :un-checked-value="false"
                checked-children="启用"
              ></a-switch>
            </template>
            <template v-else>
              <a-tag v-if="record.Status" color="success">启用</a-tag>
              <a-tag v-else color="error">暂停</a-tag>
            </template>
          </template>
          <template v-if="column.key === 'ProxyStatus'">
            <a-flex
              justify="center"
              align="center"
              v-if="record.ProxyStatus"
              :size="5"
            >
              <img alt="" style="height: 10px" src="/icon/1.svg" />
              <span style="font-size: 12px">已代理</span>
            </a-flex>
            <a-flex justify="center" align="center" v-else>
              <img style="height: 12px" src="/icon/2.svg" alt="" />
              <span style="font-size: 12px">仅DNS</span>
            </a-flex>
          </template>
          <template v-if="column.key === 'operation'">
            <a-dropdown-button @click.stop="editRecord(record)">
              <a-space size="small" style="font-size: 14px">
                <FormOutlined />
              </a-space>
              <template #overlay>
                <a-menu @click="({ key }) => handleMenuClick(key, record)">
                  <template v-if="['A', 'AAAA', 'CNAME'].includes(record.Type)">
                    <a-menu-item key="createSSL">
                      <a-space size="small">
                        <VerifiedOutlined />
                        申请证书
                      </a-space>
                    </a-menu-item>
                    <a-menu-item key="renewSSL" v-if="record.ssl">
                      <a-space size="small">
                        <HistoryOutlined />
                        续签证书
                      </a-space>
                    </a-menu-item>
                    <a-menu-item
                      key="pushSSL"
                      v-if="record.ssl && record.ssl.expired > 5"
                    >
                      <a-space size="small">
                        <CloudUploadOutlined />
                        推送证书
                      </a-space>
                    </a-menu-item>
                    <a-menu-item key="monitorSSL">
                      <a-space size="small">
                        <MonitorOutlined />
                        {{ record.monitor ? "更新监控" : "监控证书" }}
                      </a-space>
                    </a-menu-item>
                  </template>
                  <a-menu-item key="deleteRecord" danger>
                    <a-space size="small">
                      <DeleteOutlined />
                      删除记录
                    </a-space>
                  </a-menu-item>
                </a-menu>
              </template>
            </a-dropdown-button>
          </template>
        </template>
      </a-table>
    </div>
    <AddDomainRecord
      ref="addDomainRecordModal"
      @refresh="refreshRecords"
    ></AddDomainRecord>
  </div>
</template>

<style scoped lang="scss">
.box_record {
  box-sizing: border-box;
  height: 100%;
  overflow: auto;
  position: relative;

  .h_header {
    box-sizing: border-box;
    height: 65px;
    border-bottom: 1px dashed v-bind("token.colorBorder");
    padding: 0 16px;
    justify-content: space-between;
  }

  .header {
    box-sizing: border-box;
    padding: 10px 16px;
    position: sticky;
    top: 0;
    z-index: 99;
  }

  .body {
    box-sizing: border-box;
    height: calc(100% - 117px);
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
}

.name {
  //max-width: 150px;
  cursor: pointer;
  // 允许换行 允许拆分单词
  white-space: normal;
  word-break: break-all;
}
</style>
