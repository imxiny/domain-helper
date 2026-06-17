import {createRouter, createWebHashHistory} from 'vue-router'
import {
    GlobalOutlined,
    VerifiedOutlined,
    SettingOutlined,
    MonitorOutlined,
    UserOutlined,
    CloudUploadOutlined,
    AlertOutlined,
    PartitionOutlined
} from '@ant-design/icons-vue';

// 核心功能直接导入
import DomainList from '@/components/DomainList.vue'
import SslRecords from '@/components/SslRecords.vue'

const routes = [
    {
        path: '/',
        redirect: '/domains'
    },
    {
        path: '/domains',
        name: 'DomainList',
        component: DomainList,  // 核心功能直接导入
        meta: {
            title: '域名列表',
            icon: GlobalOutlined
        }
    },
    {
        path: '/domain/:id/records',
        name: 'DomainRecords',
        component: () => import('@/components/DomainRecords.vue'),
        meta: {
            title: '域名解析',
            hidden: true
        }
    },
    {
        path: '/ssl/records',
        name: 'SslRecords',
        component: SslRecords,  // 核心功能直接导入
        meta: {
            title: 'SSL证书',
            icon: VerifiedOutlined
        }
    },
    {
        path: '/ssl/monitor',
        name: 'SslMonitor',
        component: () => import('@/components/SslMonitor.vue'),  // 次要功能保持动态导入
        meta: {
            title: 'SSL监控',
            icon: MonitorOutlined
        }
    },
    {
        path: '/private-dns',
        name: 'PrivateDns',
        component: () => import('@/components/PrivateDnsList.vue'),
        meta: {
            title: '私有解析',
            icon: PartitionOutlined
        }
    },
    {
        path: '/account',
        name: 'AccountManage',
        component: () => import('@/components/AccountManager.vue'),  // 次要功能保持动态导入
        meta: {
            title: '账号管理',
            icon: UserOutlined
        }
    },
    {
        path: '/push-platform',
        name: 'PushPlatform',
        component: () => import('@/components/PushPlatform.vue'),  // 次要功能保持动态导入
        meta: {
            title: '推送平台',
            icon: CloudUploadOutlined
        }
    },
    {
        path: '/settings',
        name: 'Settings',
        component: () => import('@/components/Settings.vue'),  // 次要功能保持动态导入
        meta: {
            title: '插件设置',
            icon: SettingOutlined
        }
    },
    {
        path: '/notifications',
        name: 'Notifications',
        component: () => import('@/components/NotificationList.vue'),  // 次要功能保持动态导入
        meta: {
            title: '系统通知',
            icon: AlertOutlined
        }
    }
]

const router = createRouter({
    history: createWebHashHistory(),
    routes
})

export default router 
