<script setup>
import {computed, reactive, ref} from "vue";
import {message, notification} from "ant-design-vue";
import {getPrivateDnsService} from "@/service/PrivateDnsService";
import {RecordTypes} from "@/utils/data";

const open = ref(false);
const confirmLoading = ref(false);
const emit = defineEmits(["refresh"]);
const zoneInfo = ref(null);
const originRecord = ref(null);
const form = reactive({
    RecordId: "",
    SubDomain: "",
    RecordType: "A",
    Value: "",
    TTL: 600,
    MX: 10,
    Remark: "",
});

const title = computed(() => form.RecordId ? "修改解析记录" : "添加解析记录");

const openModal = (zone, record = null) => {
    zoneInfo.value = zone;
    originRecord.value = record;
    form.RecordId = record?.RecordId || "";
    form.SubDomain = record?.Name || "";
    form.RecordType = record?.Type || "A";
    form.Value = record?.Value || "";
    form.TTL = record?.TTL || 600;
    form.MX = record?.MX || 10;
    form.Remark = record?.Remark || "";
    open.value = true;
};

defineExpose({openModal});

const handleOk = () => {
    if (!form.SubDomain) {
        message.error("请输入主机记录");
        return;
    }
    if (!form.Value) {
        message.error("请输入记录值");
        return;
    }
    confirmLoading.value = true;
    const dns = getPrivateDnsService(zoneInfo.value.account_key, zoneInfo.value.cloud, zoneInfo.value.account_info.tokens);
    const payload = {
        id: form.RecordId,
        name: form.SubDomain,
        type: form.RecordType,
        value: form.Value,
        ttl: form.TTL,
        mx: form.MX,
        remark: form.Remark,
        originRecord: originRecord.value,
    };
    const request = form.RecordId
        ? dns.updateRecord(zoneInfo.value, payload)
        : dns.addRecord(zoneInfo.value, payload);
    request.then(() => {
        message.success(`${zoneInfo.value.zone_name} ${form.RecordId ? "修改" : "添加"}解析记录成功`);
        open.value = false;
        emit("refresh");
    }).catch(e => {
        notification.error({
            message: `${form.RecordId ? "修改" : "添加"}解析记录失败`,
            description: e.toString(),
            duration: 10,
        });
    }).finally(() => {
        confirmLoading.value = false;
    });
};
</script>

<template>
    <a-modal v-model:open="open" :destroy-on-close="true" :confirm-loading="confirmLoading" @ok="handleOk" ok-text="保存" cancel-text="取消" width="450px">
        <template #title>
            <div style="text-align: center">{{ title }}</div>
        </template>
        <div style="height: 20px;"></div>
        <a-form :model="form" :label-col="{style: {width: '80px'}}">
            <a-form-item label="主机记录">
                <a-input v-model:value="form.SubDomain" placeholder="主机记录 @ 代表根域名">
                    <template #addonAfter>.{{ zoneInfo?.zone_name }}</template>
                </a-input>
            </a-form-item>
            <a-form-item label="记录类型">
                <a-select v-model:value="form.RecordType">
                    <a-select-option v-for="item in RecordTypes" :key="item" :value="item">{{ item }}</a-select-option>
                </a-select>
            </a-form-item>
            <a-form-item label="　记录值">
                <a-textarea v-model:value="form.Value" placeholder="记录值" :auto-size="{minRows: 1, maxRows: 4}"></a-textarea>
            </a-form-item>
            <a-form-item label="　　TTL">
                <a-input-number style="width: 100%" v-model:value="form.TTL" :min="1"></a-input-number>
            </a-form-item>
            <a-form-item label="MX优先级" v-if="form.RecordType === 'MX'">
                <a-input-number style="width: 100%" v-model:value="form.MX" :min="1" :max="65535"></a-input-number>
            </a-form-item>
            <a-form-item label="　　备注" v-if="zoneInfo?.cloud !== 'aws'">
                <a-input v-model:value="form.Remark" placeholder="备注"></a-input>
            </a-form-item>
        </a-form>
    </a-modal>
</template>
