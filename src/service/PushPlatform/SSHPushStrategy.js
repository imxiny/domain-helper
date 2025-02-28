import {IPushStrategy} from './IPushStrategy.js';
import {randomString} from "@/utils/tool";

const NodeSSH = xNodeSSH.NodeSSH;

export class SSHPushStrategy extends IPushStrategy {
    constructor() {
        super();
        this.ssh = new NodeSSH();
    }

    async validate(config) {
        try {
            await this.ssh.connect({
                host: config.host,
                port: config.port || 22,
                username: config.username,
                password: config.password,
                privateKey: config.privateKey
            });
            return true;
        } catch (error) {
            throw new Error(`SSH连接验证失败: ${error.message}`);
        }
    }

    async push(config, certData, oncall = null) {
        try {
            // 连接服务器
            await this.validate(config);
            oncall && oncall('connected', {msg: '连接服务器成功 🎉'});
            const sftp = await this.ssh.requestSFTP();


            // 执行前置命令
            if (config.beforePushCommand) {
                oncall && oncall('beforePushCommand', {msg: '开始执行命令'});
                await this.ssh.execCommand(config.beforePushCommand);
                oncall && oncall('afterPushCommand', {msg: '命令执行成功 🎉'});
            }

            oncall && oncall('beforePush', {msg: '开始推送证书文件'});
            await this.writeContentToFile(sftp, certData.cert, config.certPath);
            await this.writeContentToFile(sftp, certData.key, config.keyPath);

            oncall && oncall('afterPush', {msg: '证书文件推送成功 🎉'});

            // 执行重启命令
            if (config.restartCommand) {
                oncall && oncall('beforeCommand', {msg: '开始执行命令'});
                await this.ssh.execCommand(config.restartCommand);
                oncall && oncall('afterCommand', {msg: '命令执行成功 🎉'});
            }
            oncall && oncall('success',  {msg: '证书推送完成 🎉'});
            await this.ssh.dispose();
            return true;
        } catch (error) {
            console.error('SSHPushStrategy push error:', error);
            oncall && oncall('error', {msg: error.toString()});
            throw new Error(`推送失败: ${error.message}`);
        }
    }

    writeContentToFile(sftp, content, path) {
        console.log("sftp 推送")
        return new Promise((resolve, reject) => {
            sftp.writeFile(path, content, (err) => {
                if (err) {
                    return reject(err);
                }
                resolve();
            });
        });
    }
} 