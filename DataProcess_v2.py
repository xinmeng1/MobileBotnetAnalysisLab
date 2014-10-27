# -*- coding: utf-8 -*-
#############################################
##Sample data procesee V1.0
##Author:Xin Meng
##Data:  2014 Oct 12th
##Description: 
#############################################

# 处理Normal Background Traffic txt文件, 将所有packet存入数组, 并且进行标记label 0 写入CSV文件
# 
# 处理Malware Background Traffic txt文件
#    1.首先将packet和Normal数据数组进行查找比对,如果存在则表示 其为normal ,标记labe 0
#    2.如果没有则标记为label 1
# 问题:
#    1. 属性补全,有些参数没有获取到,就需要后面补全为0
#    2. 需要分析Malware Background数据, 生成统计报告

import os
import csv
#import win32process
import subprocess
import string
#WorkingPath = os.path.normcase("H:/Dropbox/[1]CITY_Research/1_MalwareLab/");
WorkingPath = os.path.normcase("C:/Users/mengxin/Dropbox/[1]CITY_Research/1_MalwareLab/");
#H:/Dropbox/[1]CITY_Research/1_MalwareLab/
#C:/IOT@Work_Project/tshark/
#C:/Users/mengxin/Dropbox/[1]CITY_Research/1_MalwareLab
SampleDir = os.path.normcase("SampleV2/");
OutputDir = os.path.normcase("OutputV2/");
NormalSampleDir = os.path.normcase("0");
MalwareSampleDir = os.path.normcase("1");
NormalFileName = os.path.normcase("2014_10_08_120147.pcap.txt/");
MalwareFileName = os.path.normcase("");
sampleDataExt = ".txt"
separater = "\\"
csvoutput = "SampleData2Class.csv"
SampleDataPath = WorkingPath+SampleDir;
OutputDataPath = WorkingPath+OutputDir;
targetLabeledtxtPath = OutputDataPath+csvoutput;

def Ip2Int(ip):
    import struct,socket
    return struct.unpack("!I",socket.inet_aton(ip))[0]

def Int2Ip(i):
    import socket,struct
    return socket.inet_ntoa(struct.pack("!I",i))

def compare(a,b):
    if (a[0]==b[0] and a[1]==b[1] and a[2]==b[2]):
        return 1;
    else:
        return 0;
        

def processSampleDataDir(dir,file):
    #log
    file.write('The SampleDataTXT Directory:')
    file.write(dir + '\n')
    filenum = 0
    infectedNum = 0
    normalNum = 0
    NormalFilePacketNum = 0
    #log end
    list = os.listdir(dir)  #列出目录下的所有文件和目录
    #store normal packet 用于比较malware是否中是否为normal, 二维数组, 每一个row为一个packet记录
    # 每个packet字段数目为 8个
    normal_list = [[0 for col in range(8)] for row in range(0)];
    
    with open(targetLabeledtxtPath, 'wSb+') as csvfile:
        spamwriter = csv.writer(csvfile, dialect='excel')
        spamwriter.writerow(['IP source','IP dest','Protocol','UDP size','TCP size', 'TCP duration', 'Argument Count', 'Lable'])
    #遍历 SampleDir 下的所有文件和目录
    for line in list:
        filepath = os.path.join(dir,line)
        #Debug# print(filepath)
        #如果为目录则遍历目录内部的文件
        if os.path.isdir(filepath):
            #log
            file.write('   ' + line + '\\'+'\n')
            #log end
            #遍历分类文件夹下的源数据文件
            for li in os.listdir(filepath):
                #DEBUG# print(li)
                #读取文件内容, 分析文件内容
                #labeltxtoutput = open(targetLabeledtxtPath+"\\"+li, 'w+')
                #print SampleDataPath+line+"\\"+li
                #遍历文件中每一行
                for txtline in open(SampleDataPath+line+"\\"+li):
                    #DEBUG# print txtline
                    txtarray=txtline.split()
                    #print txtarray
                    #print len(txtarray)
                    #print line;
                    if line == '0':
                        #如果是处理Normal文件夹, 先处理生成csv文件,然后加入到 normal_list
                        #首先判断IP地址是不是IPv6
                        #print txtarray;
                        #print len(txtarray);
                        #print len(txtarray[0]);
                        if len(txtarray[0])<=15:
                            #IP地址长度大于255.255.255.255,则为IPv6
                            intIPsource = Ip2Int(txtarray[0]);
                            txtarray[0] = intIPsource;
                            intIPdest = Ip2Int(txtarray[1]);
                            txtarray[1] = intIPdest;
                            
                            if txtarray[2] != '17':    
                                #TCP 6 UDP 17
                                #if not UDP, 自动将udp size置为0
                                txtarray.insert(3,'0');
                                #print txtarray;
                            if txtarray[2] != '6':
                                txtarray.insert(4,'0');
                                txtarray.insert(5,'0');
                                txtarray.insert(6,'0');
                            else:
                                print len(txtarray);
                                if len(txtarray)==7:
                                    #include the HTTP request uri
                                    arg_num = txtarray.pop(6).count('=')
                                    #print arg_num
                                    #txtarray.pop(2)
                                    #insert the number of argument
                                    txtarray.insert(6,str(arg_num));
                                else:
                                    arg_num = 0;
                                    txtarray.insert(6,str(arg_num));
                            txtarray.insert(7,'normal')
                            normal_list = [txtarray]+normal_list;
                            NormalFilePacketNum = NormalFilePacketNum+1;
                            #write the files
                            #写入CSV文件,如果tcp size为0 就不写如到文件中
                            
                            with open(targetLabeledtxtPath, 'ab+') as csvfile:
                                spamwriter = csv.writer(csvfile, dialect='excel');
                                spamwriter.writerow(txtarray);

                    if line == '1':
                        if len(txtarray[0])<=15:
                            #IP地址长度大于255.255.255.255,则为IPv6
                            intIPsource = Ip2Int(txtarray[0]);
                            txtarray[0] = intIPsource;
                            intIPdest = Ip2Int(txtarray[1]);
                            txtarray[1] = intIPdest;
                            if txtarray[2] != '17':    
                                #TCP 6 UDP 17
                                #if not UDP, 自动将udp size置为0
                                txtarray.insert(3,'0');
                            if txtarray[2] != '6':
                                txtarray.insert(4,'0');
                                txtarray.insert(5,'0');
                                txtarray.insert(6,'0');
                            else:
                                if len(txtarray)==7:
                                    #include the HTTP request uri
                                    arg_num = txtarray.pop(6).count('=')
                                    print arg_num
                                    #txtarray.pop(2)
                                    #insert the number of argument
                                    txtarray.insert(6,str(arg_num));
                                else:
                                    arg_num = 0;
                                    txtarray.insert(6,str(arg_num));
                            status = 0;
                            for i in normal_list:
                                if(compare(i,txtarray)==1):
                                    status = 1;
                                    break;
                            if(status == 1):
                                txtarray.insert(7,'infected');
                                infectedNum=infectedNum+1;
                            else:
                                txtarray.insert(7,'normal');
                                normalNum = normalNum+1;
                            #write the files
                            #写入CSV文件,如果tcp size为0 就不写如到文件中
                            
                            with open(targetLabeledtxtPath, 'ab+') as csvfile:
                                spamwriter = csv.writer(csvfile, dialect='excel');
                                spamwriter.writerow(txtarray);

                                                
                        #将array转化为string,写入文件
                        #str_txtarray = ' '.join(txtarray)
                        #labeltxtoutput.writelines(str_txtarray)
                        #labeltxtoutput.writelines("\n")
                    print txtarray
                   
                        
                #while 1:
                #    txtline = txtfile.readline()
                #    #DEBUG#
                #    print txtline
                #    if not line:
                #        break
                #    pass # do something
                #labeltxtoutput.close()
                file.write('     '+li + '\n')
                filenum = filenum + 1
        elif os.path:               #如果filepath是文件，直接列出文件名
            file.write('   '+line + '\n') 
            filenum = filenum + 1
    file.write('The sum of the file processed '+ str(filenum)+'\n');
    file.write('The sum of the normal packet in Normal file: '+ str(NormalFilePacketNum)+'\n');
    file.write('The sum of the infected packet in the infect file: '+ str(infectedNum)+'\n');
    file.write('The sum of the normal packet in the infect file: '+ str(normalNum)+'\n');
    
dir = SampleDataPath
report = open(OutputDataPath+'report.txt','w')
processSampleDataDir(dir,report)




