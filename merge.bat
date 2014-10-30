::批量合并pcap文件. 将该bat放入需要merger的文件夹中.
setlocal enabledelayedexpansion
set foo=
for %%f in (*.pcap) do set foo=!foo! %%f
	mergecap -w all.pcap %foo%
pause
