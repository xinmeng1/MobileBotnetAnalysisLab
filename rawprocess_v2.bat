::V2   10th November 2014
::include the stream index and change the tcp.delta to the frame.delta
::考虑将数据包按照 stream进行分组

setlocal enabledelayedexpansion
set outputFormat=.txt
for %%f in (*.pcap) do (
	tshark -r %%f -o tcp.calculate_timestamps:true -n -T fields -e ip.src -e ip.dst -e ip.proto -e frame.time_delta -e udp.length -e udp.stream -e tcp.len -e tcp.stream -e http.request.uri >%%f%outputFormat%
)

::tshark -r 2014_10_10.pcap -o tcp.calculate_timestamps:true -n -T fields -e ip.src -e ip.dst -e ip.proto -e udp.length -e tcp.len -e tcp.time_delta -e http.request.uri > 2014_10_10.pcap.txt