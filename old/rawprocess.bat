setlocal enabledelayedexpansion
set outputFormat=.txt
for %%f in (*.pcap) do (
	tshark -r %%f -o tcp.calculate_timestamps:true -n -T fields -e ip.src -e ip.dst -e ip.proto -e udp.length -e tcp.len -e tcp.time_delta -e http.request.uri >%%f%outputFormat%
)