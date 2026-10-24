# canlog-inspector

对离线 CAN 日志做快速统计和异常筛选：支持常见 candump 文本与 timestamp,id,data CSV，识别未知 ID、单位时间突发、空数据和非法十六进制。

使用：python canlog.py examples/sample.log --known-id 0x123 --known-id 0x124。

现场日志量大、网络环境又经常不稳定，工程师需要先在本地回答哪些帧异常、什么时候发生、是否有未知发送者。该工具无需数据库或硬件，输出确定性 JSON，适合作为更复杂分析管线的第一步。

## 许可证

MIT
