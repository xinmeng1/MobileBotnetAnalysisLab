tshark -r 2014_10_10.pcap -o tcp.calculate_timestamps:true -n -T fields -e ip.src -e ip.dst -e ip.proto -e udp.length -e tcp.len -e tcp.time_delta -e http.request.uri > 2014_10_10.pcap.txt


mergecap -w 2014_10_09.pcap 2014_10_09_120427.pcap 2014_10_09_125753.pcap 2014_10_09_173957.pcap
