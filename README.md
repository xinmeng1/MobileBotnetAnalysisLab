MobileBotnetAnalysisLab (MBAL)
=======================

##0 简介

该程序包使用Python和Tshark提取手机捕获的traffic文件中的特征, 并且进行处理.
从而生成适合WEKA使用的Machine Learning的数据集.

本程序包处理的原始数据为 pcap 文件. 最终生成WEKA可以识别的csv文件. 具体如何处理及原始文件要求参见下面内容.

##1 原始数据要求

本程序包目标是处理原始pcap流量数据包文件,生成可以用于Weka的数据集文件, 然后进行Machine Learning 分析.

目前程序使用surprised Machine Learning, 所以需要对数据包进行标记. 所以原始数据pcap文件至少包含两个文件,

1. PD0: Normal Pcap 数据包, 所有流量均为正常软件生成的流量数据
2. PD1: Infected Pcap数据包, 流量包含了正常的软件流量数据及malware applications 生成的流量数据

本程序包的工作尽可能的在PD1中分离出和PD0相似的数据包, 然后进行标记为normal,剩下的标记为infected.

此处主要使用IP进行筛选, 是否合理? 

该筛选的依据是PD0和PD1采集的环境, 设当前手机环境为S0, Normal Application集合为 APP0, Malware Application集合为 APP1. 那么DP0采集的环境为S0+APP0, 而DP1采集的环境为S0+APP0+APP1. 而且以上环境均未对S0,APP0,APP1进行任何的操作, 采集到的流量均为background流量. 

此处假设所有的Malware Application均会自动实施malware Action, 即使用户没有任何操作, Malware Application同样会实施malware Action.(是否合理, 直观上是合理的)

##2 数据处理流程

###2.1 Tshark处理

我们首先使用Tshark对PCAP信息进行提取, 生成使用空格分隔的TXT文件, 每一行代表一个packet, 空格隔离单条packet的属性. 例如: ip protocol size ....

这里也会用到pcap合并的命令等.

###2.2 Python处理

该处理过程为主要处理过程, 分析TXT文件, 然后生成CSV文件, 其中关键问题是, 如何对数据包进行标记(Normal or Infected)
