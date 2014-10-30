::使用pcapfix 修复pcap文件. 该命令工具需自行下载, 并加入到系统变量中.
::https://f00l.de/pcapfix/
setlocal enabledelayedexpansion
for %%f in (*.pcap) do (
	pcapfix %%f
	)

pause
