# coding=utf-8
import logging
import logging.handlers

__author__ = 'Xin Meng'


# ########################################################
# 可复用日志输出, 使用方法
# logger = get_logger('test.log', 'TEST')
# logger.debug(str)
# 可配置内容:
# 1. LOG_FILE name
# 2. fmt 格式
# 3. logger名称
# 4. 显示级别
# ########################################################
def get_logger(file_name, logger_name):
    # 日志文件名
    log_file = file_name
    # 创建一个输出到文件的 handler
    handler_file = logging.handlers.RotatingFileHandler(log_file, maxBytes=1024 * 1024, backupCount=5)
    # 创建一个输出到控制台的 handler
    handler_console = logging.StreamHandler()
    # 配置显示格式,并实例化
    fmt = '%(asctime)s - %(filename)s:%(lineno)s - %(name)s - %(message)s'
    formatter = logging.Formatter(fmt)
    # 为handler加载显示格式
    handler_file.setFormatter(formatter)
    handler_console.setFormatter(formatter)
    # 获取名为TEST的logger
    logger = logging.getLogger(logger_name)
    # 为logger添加handler
    logger.addHandler(handler_file)
    logger.addHandler(handler_console)
    # 配置显示级别
    logger.setLevel(logging.DEBUG)
    return logger
