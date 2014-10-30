# -*- coding: utf-8 -*-
#############################################
##Sample data process V2.0
##Author:Xin Meng
##Data:  2014 Oct 29th
##Description: 
#############################################
import logging #Log modurler
import os
import csv
import subprocess
import string
import sys

###################################################
###variable
###################################################
#configuration variable
OutputCSVDir = ""
ReportDir = ""
NormalDBDir = ""
InputNormalDir = ""
InputInfectDir = ""

output_csv_dir = ""
report_dir = ""
normal_db_dir = ""
input_normal_dir = ""
input_infect_dir = ""

#Current Path (the Script)
path = os.path.split(os.path.realpath(__file__))[0]
#The Scan Information
num_normal_input_file = 0
num_infect_input_file = 0
normal_input_file = []
infect_input_file = []

####################################################
########## FUNCTION3: Load Configuration
########## RETURN: InputNormalDir
##########         InputInfectDir
##########         OutputCSVDir
##########         ReportDir
##########         NormalDBDir
####################################################   


def load_conf():
    #from __future__ import with_statement  
    #DataProcess.cfg
    import ConfigParser
    config = ConfigParser.ConfigParser()
    with open(path+"\DataProcess.cfg", "r") as cfgfile:
        config.readfp(cfgfile)  
        input_dir = config.get("DIR", "InputDir")
        normal_dir = config.get("DIR", "NormalDir")
        infect_dir = config.get("DIR", "InfectDir")
        
        output_csv_dir = os.path.normcase(config.get("DIR", "OutputDir"))
        report_dir = os.path.normcase(config.get("DIR", "ReportDir"))
        normal_db_dir = os.path.normcase(config.get("DIR", "NormalDB"))

    input_normal_dir = os.path.normcase(input_dir+normal_dir)
    input_infect_dir = os.path.normcase(input_dir+infect_dir)

    #return (InputNormalDir,InputInfectDir,OutputCSVDir,ReportDir,NormalDBDir)
####################################################
########## FUNCTION2: Scan the Input Data directory
####################################################    


def scan_input_data():
    #Load Configuration File to get parameters
    load_conf()
    #List the normal and infect files
    normal_list = os.listdir(input_normal_dir)
    infect_list = os.listdir(input_infect_dir)
    print(normal_list)
    print(infect_list)
####################################################
########## FUNCTION1: Show Help Infomation
####################################################      


def show_help_info():
    print("================================================\n")
    print("=========MobileBotnetAnalysisLab (MBAL)=========\n")
    print("=========Version: V2.0                 =========\n")
    print("=========Develop: Xin Meng             =========\n")
    print("=========Date: 2014 Oct. 29th          =========\n")
    print("================================================\n")
    print("Help Information:\n")
    print("0: Scan the configuration and Show the information\n")
    print("1: Process the Normal Traffic File and contruct the Normal Database\n")
    print("2: Process the Infect Traffic File\n")
    print("3: Show the Help Information\n")
    print("4: extensions\n")
    print("9: Quit\n")
    print("================================================\n")    

####################################################
##########Logger Configuration
####################################################
# 创建一个logger
logger = logging.getLogger('mainlogger')
logger.setLevel(logging.DEBUG)

# 创建一个handler，用于写入日志文件
fh = logging.FileHandler(path+'/mainlog.log')
fh.setLevel(logging.DEBUG)

# 再创建一个handler，用于输出到控制台
ch = logging.StreamHandler()
ch.setLevel(logging.DEBUG)

# 定义handler的输出格式
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
fh.setFormatter(formatter)
ch.setFormatter(formatter)

# 给logger添加handler
logger.addHandler(fh)
logger.addHandler(ch)

# 记录一条日志
logger.info('Test mainlog')
# Set Level of the logger, 
# NOTSET < DEBUG < INFO < WARNING < ERROR < CRITICAL
#logger.setLevel(logging.WARNING)    #Show Debug Information
#logger.setLevel(logging.INFO)    #Show Debug Information
logger.setLevel(logging.DEBUG)
#logger.setLevel(logging.NOTSET)  #Not show Any Information


####################################################
##########The main interactive of the Data Process
####################################################
show_help_info()
exitFlag = 0
while 1:
    #获得用户输入
    userInput = raw_input("Please Enter your Choice:")
    if userInput == '0':
        scan_input_data()
        print("Scanning...")
    elif userInput == '1':
        print("Proceing Normal files...")
    elif userInput == '2':
        print("Proceing Infect files...")
    elif userInput == '3':
        print("Showing Help Information...")
        show_help_info()
    elif userInput == '4':
        print("Showing Help Information...")
        show_help_info()
    elif userInput == '9':
        print("Exit...")
        exitFlag = 1
    else:
        print("Not Valid Input, Please Try Again...")
        show_help_info()
    #Quit the programme
    if exitFlag == 1:
        ch.release()
        fh.release()
        break









