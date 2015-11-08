# coding=utf-8
from utils.log import get_logger
from utils.network import *
import logging
import logging.handlers

__author__ = 'Xin Meng'
# ########################################################
# 可复用日志输出
# 可配置内容:
# 1. LOG_FILE name
# 2. fmt 格式
# 3. logger名称
# 4. 显示级别
# ########################################################
# 日志文件名
# LOG_FILE = 'test.log'
# # 创建一个输出到文件的 handler
# handler_file = logging.handlers.RotatingFileHandler(LOG_FILE, maxBytes=1024 * 1024, backupCount=5)
# # 创建一个输出到控制台的 handler
# handler_console = logging.StreamHandler()
# # 配置显示格式,并实例化
# fmt = '%(asctime)s - %(filename)s:%(lineno)s - %(name)s - %(message)s'
# formatter = logging.Formatter(fmt)
# # 为handler加载显示格式
# handler_file.setFormatter(formatter)
# handler_console.setFormatter(formatter)
# # 获取名为TEST的logger
# logger = logging.getLogger('TEST')
# # 为logger添加handler
# logger.addHandler(handler_file)
# logger.addHandler(handler_console)
# # 配置显示级别
# logger.setLevel(logging.DEBUG)
# ########################################################
logger = get_logger('test.log', 'TEST')

a = ip2int("192111111119999999999999999999")
b = int2ip(a)

logger.debug(a)
logger.debug(b)
ip_sub_mask_str = ('216.239.32.0/19 '
                   , '64.233.160.0/19'
                   , '66.249.80.0/20'
                   , '2.14.192.0/18'
                   , '209.85.128.0/17'
                   , '66.102.0.0/20'
                   , '74.125.0.0/16'
                   , '64.18.0.0/20'
                   , '207.126.144.0/20'
                   , '173.194.0.0/16')

ip_min, ip_max = subnet_mask_to_ip_range(ip_sub_mask_str[0])
logger.debug(ip_min)
logger.debug(ip_max)
ip_min, ip_max = subnet_mask_to_ip_range(ip_sub_mask_str[1])
logger.debug(ip_min)
logger.debug(ip_max)
ip_min, ip_max = subnet_mask_to_ip_range(ip_sub_mask_str[2])
logger.debug(ip_min)
logger.debug(ip_max)
ip_min, ip_max = subnet_mask_to_ip_range(ip_sub_mask_str[3])
logger.debug(ip_min)
logger.debug(ip_max)
ip_min, ip_max = subnet_mask_to_ip_range(ip_sub_mask_str[4])
logger.debug(ip_min)
logger.debug(ip_max)
ip_min, ip_max = subnet_mask_to_ip_range(ip_sub_mask_str[5])
logger.debug(ip_min)
logger.debug(ip_max)
ip_min, ip_max = subnet_mask_to_ip_range(ip_sub_mask_str[6])
logger.debug(ip_min)
logger.debug(ip_max)
ip_min, ip_max = subnet_mask_to_ip_range(ip_sub_mask_str[7])
logger.debug(ip_min)
logger.debug(ip_max)
ip_min, ip_max = subnet_mask_to_ip_range(ip_sub_mask_str[8])
logger.debug(ip_min)
logger.debug(ip_max)
ip_min, ip_max = subnet_mask_to_ip_range(ip_sub_mask_str[9])
logger.debug(ip_min)
logger.debug(ip_max)

