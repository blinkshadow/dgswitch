#!/usr/bin/python2.6
# -*- coding: utf-8 -*-
# @Author: zhanghao
# @Date:   2017-07-24 16:06:16
# @Last Modified by:   zhanghao
# @Last Modified time: 2017-12-14 15:21:06
# python startup file
# author     c zhanghao
# function   b oracle dg failover
# version    a python 2.7
# 
# 监控脚本依赖带外管理，
# 
# 
# 
# 每5s ping 主库和备库ip  
# 机器例行维护时需要关闭该脚本
# 1 ping 主机ip 情况
# 1.1、主库ping 通 备库ping 不通   不做操作
# 1.2、主库ping不通 备库ping通   
#     1.2.1继续ping主  连续尝试30s以后确定主不能ping 并且不能创建数据库连接 
#     1.2.2或创建连接后不能执行update操作，则执行failover操作。
# 1.3、主ping不通 备ping不通 
#     不做任何操作
# 
# 存在多个库
# 
# 要求以及准备工作：
# 1521监听叫listener 
# 
# 能访问带外服务器的机器 SWITCHPARAM.MANAGER_IP  安装ipmi包  
# yum install ipmitool
# 本机安装互信的包
# paramiko
# yum install python-paramiko.noarch
# 
# 主库创建监控表
# create tablespace TBS_APPADMIN_DATA datafile size 10g;
# create table appadmin.HEART_BEAT_MONITOR  (monitor_date date) tablespace  TBS_APPADMIN_DATA;
# grant insert,update,select,delete on appadmin.HEART_BEAT_MONITOR to appadmin;
# grant resource to appadmin;
# 定期可以truncate table
# 
# 规范：
# ORACLE_HOME需要为: /u01/app/oracle/product/11.2.0/dbhome_1
# 
# 需要备库到主库配置互信
# 主库执行 
# ssh-keygen -t rsa
# 执行
# ssh oracle@备库ip cat ~/.ssh/*.pub >> ~/.ssh/authorized_keys
# 
# 备库到SWITCHPARAM.MANAGER_IP节点配置互信（因为密码会定时修改，所以通过互信来操作）
# 
# paramiko 报需要安装 暂时使用python 2.6
# 确认备库可以执行
# select scn_to_timestamp(current_scn) from v$database; 
#
# zabbix 要监控asm磁盘组里redo 的状态
# 主备库的service name 要保持一致
# 增加了数据文件，需要配置在 SWITCHPARAM.py中
#
# 
import cx_Oracle
import sys
import os
import argparse
import subprocess
import re
import paramiko
import threading
import logging
import time
import fcntl
import commands
import SWITCHPARAM


CONNECT_FAILED=0
TYPE_INSERT='INSERT'
TYPE_SELECT='SELECT'
TYPE_ALTER='ALTER'
STANDBY_MAX_LAG=60
CHECK_CONTINUE='continue'
CHECK_SWITCH='switch'
CHAECK_GATEWAY='gateWay'
CHAECK_IFLAG='iflag'

PRIMARY_VALID=1
PRIMARY_FAILURE=2
INSTANCE_VALID=3
INSTANCE_FAILURE=4
LISTENER_VALID=5
LISTENER_FAILURE=6
PROCESS_VALID=7
PROCESS_FAILURE=8
SGA_VALID=9
SGA_FAILURE=10
KILL_SUCCESS=11
KILL_FAILURE=111
START_LISTENER_FAILURE=12
START_LISTENER_SUCCESS=13
STOP_DATABASE_FAILURE=14
STOP_DATABASE_SUCCESS=15
START_DATABASE_FAILURE=16
START_DATABASE_SUCCESS=17
REPAIR_SUCCESS=18
REPAIR_FAILURE=19
IP_VALID=20
IP_FAILD=21
CREATE_SSH_CONN_FAILD=22
CHECK_MANAGER_VALID=23
CHECK_MANAGER_FAILD=24
POWER_OFF_FAILD=25
POWER_OFF_SUCCESS=26
SWITCH_WITH_SHARESTORAGE=27
SWITCH_WITHOUT_SHARESTORAGE=28


logging.basicConfig(level=logging.DEBUG,
                format='%(asctime)s %(filename)s[line:%(lineno)d] %(levelname)s %(message)s',
                datefmt='%a, %d %b %Y %H:%M:%S',
                filename='monitor.log',
                filemode='w')


def excuteOSCMD(cmd):
    try:
        return os.system(cmd)
    except Exception ,e:
        logging.info(e)


#检测网络
def NetCheck(ip):
   logging.info('check  NetCheck %s ' %(ip))
   try:
    p = subprocess.Popen(["ping -c 1 -w 1 "+ ip],shell=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    out=p.stdout.read()
    outsecond =p.stderr.read()
    regex=re.compile('100% packet loss')
    regexsecond=re.compile('unreachable') 
    logging.info('end check  NetCheck %s ' %(ip))
    if len(regex.findall(out)) == 0 and len(regexsecond.findall(outsecond)) == 0:
        logging.info(ip + ': host up')
        return IP_VALID
    else:
        logging.info(ip + ': host down')
        return IP_FAILD
   except:
    logging.info('NetCheck work error!')
    return IP_FAILD

#检测数据库状态
# 创建连接
def getConnectByTns(username, password, tns):
    logging.info('begin getConnectByTns %s' %(tns))
    #conn = cx_Oracle.connect(user=username,password=passwd,dsn=tns ,mode=cx_Oracle.SYSDBA )
    conn = ''
    try:
        conn = cx_Oracle.connect('%s/%s@%s'%(username,password,tns) ,mode=cx_Oracle.SYSDBA )
        logging.info('end getConnectByTns  %s' %(tns))
    except Exception, dberror:
        logging.info(dberror)
        logging.info('connect %s failed ' %(tns))
        return CONNECT_FAILED
    return conn

# 创建连接
def getConnectByTnsNoSys(username, password, tns):
    logging.info('begin getConnectByTns %s' %(tns))
    #conn = cx_Oracle.connect(user=username,password=passwd,dsn=tns ,mode=cx_Oracle.SYSDBA )
    conn = ''
    try:
        conn = cx_Oracle.connect('%s/%s@%s'%(username,password,tns))
        logging.info('end getConnectByTns  %s' %(tns))
    except Exception, dberror:
        logging.info(dberror)
        logging.info('connect %s failed ' %(tns))
        return CONNECT_FAILED
    return conn

# 创建ssh 链接 要求互信
def createSshConnect(host):
    result = CREATE_SSH_CONN_FAILD
    try:
        pkey = paramiko.RSAKey.from_private_key_file('/home/oracle/.ssh/id_rsa')
        # 建立连接
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy()) 
        #logging.info(host
        ssh.connect(hostname=host,port=22,username='oracle',pkey=pkey)
        result = ssh
    except Exception, dberror:
        logging.info(dberror)
        logging.info('createSshConnect  %s failed ' %(host))
    return result

# 创建ssh 链接 要求互信
def createSshConnectForRoot(host):
    result = CREATE_SSH_CONN_FAILD
    try:
        pkey = paramiko.RSAKey.from_private_key_file('/home/oracle/.ssh/id_rsa')
        # 建立连接
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy()) 
        #logging.info(host
        ssh.connect(hostname=host,port=22,username='root',pkey=pkey)
        result = ssh
    except Exception, dberror:
        logging.info(dberror)
        logging.info('createSshConnect  %s failed ' %(host)) 
    return result


#  检测数据库进程
def checkDB(ssh,instance_name):
    try:
        logging.info("begin checkDB %s" %(instance_name))
        checkprocessCmd = 'ps -ef | grep [o]ra_ckpt | grep oracle | grep -i {0} | wc -l'
        checkprocessCmd = checkprocessCmd.format(instance_name)
        logging.info(checkprocessCmd)
        #检测oracle 进程
        stdin, stdout, stderr = ssh.exec_command(checkprocessCmd)
        #logging.info(stdout.read().decode())
        #logging.info(stderr.read().decode())
        instanceCount=int(stdout.read().decode() ,10)
        
        logging.info("begin checkDB %s instance count is %s" %(instance_name,instanceCount))
    
        if instanceCount > 0:
           logging.info("实例 %s 存在" %(instance_name))
           return INSTANCE_VALID
        else :
           logging.info("实例 %s 不存在" %(instance_name))
           return INSTANCE_FAILURE
    except Exception, e:
        logging.info(e)
        return INSTANCE_FAILURE

    

def checkListener(ssh,switchType):
    try:
        checkListenerCmd = ''
        if switchType == SWITCH_WITH_SHARESTORAGE:
            checkListenerCmd = 'ps -ef | grep [L]ISTENER | grep tnslsnr | grep grid |wc -l'
        else:
            checkListenerCmd = 'ps -ef | grep [L]ISTENER |grep -v grep| grep tnslsnr |wc -l'
        logging.info('checkListenerCmd is %s' %(checkListenerCmd))
        stdin, stdout, stderr = ssh.exec_command(checkListenerCmd)
        gridListenerCount = int(stdout.read().decode(),10)

        if gridListenerCount == 1:
            logging.info('数据库监听存在不需要修复监听')
            return LISTENER_VALID
        else:
            logging.info('数据库监听不存在')
            return LISTENER_FAILURE
    except Exception, e:
        logging.info(e)
        return LISTENER_FAILURE
    
    
    
    

def checkMonitor():
    #result = excuteOSCMD('ps -ef | grep [m]onitor.py | grep -v grep  |wc -l')
    output = commands.getoutput('ps -ef | grep [m]onitor.py | grep -v grep  |wc -l')  
    return int(output)


#def  getAlertPath(service_name):
#
#    conn = getConnectByTns('sys', 'oracle', 'SH')
#
#    getAlertSql = ''' select 'tail -100 '||a.value||'/alert_'||b.instance_name||'.log' from v$paramea ,    #v$instance b where a.name='background_dump_dest' '''
#    
#    #[('tail -1000f /u01/app/oracle/diag/rdbms/sh/SH/trace/alert_SH.log',)]
#    alertPath = excuteSql(conn,getAlertSql,TYPE_SELECT)[0][0]
#
#    return alertPath

def  checkProcess(ssh,alertPath,username, password, tns):
    try:
        getProcessCMD = 'tail -100 '+alertPath+'|'+'grep ORA-00020'+ '|'+'wc -l'
        logging.info(getProcessCMD)
        stdin, stdout, stderr = ssh.exec_command(getProcessCMD)
        result = int(stdout.read().decode(),10)
        #conn = getConnectByTns(username, password, tns)
        logging.info(result)
        #if result == 0 or conn != CONNECT_FAILED:
        if result == 0 :
            return PROCESS_VALID
        else:
            logging.info('ORA-00020: maximum number of processes')
            return PROCESS_FAILURE
    except Exception, e:
        return PROCESS_FAILURE

    
    
    
    
    
    
    
    
    
    
    
        

#def checkSGA(ssh,alertPath):
#
#    checkSGACmd = 'tail -100 '+alertPath+'|'+'grep ORA-04031'+ '|'+'wc -l'
#
#    stdin, stdout, stderr = ssh.exec_command(checkSGACmd)
#    result = int(stdout.read().decode(),10)
#    logging.info(result
#    if result > 0:
#        logging.info('ORA-04031:'
#        return SGA_FAILURE
#    else:
#        return SGA_VALID

def killSession(ssh,instance_name):
    try:
        logging.info('begin killSession')
        killSessionCmd='''ps -ef|grep "LOCAL=NO"|grep -v grep| grep %s | awk '{ logging.info($2 }'|xargs kill -9''' %(instance_name)
        logging.info(killSessionCmd)
        #killSessionCmd = killSessionCmd.format(instance_name)
        stdin, stdout, stderr = ssh.exec_command(killSessionCmd)
        logging.info('end killSession')
        return KILL_SUCCESS
    except Exception, e:
        logging.info(e)
        return KILL_FAILURE
    
    
    
    
    
    
    
###
def startListener(ssh,switchType):
    try:
        logging.info('begin startListener')

        startListenerCmd = ''
        if switchType == SWITCH_WITH_SHARESTORAGE :
            startListenerCmd=''' export ORACLE_HOME=/u01/app/oracle/product/11.2.0/dbhome_1;
        /u01/app/oracle/product/11.2.0/dbhome_1/bin/srvctl start listener -l listener'''
        else:
            startListenerCmd='''export ORACLE_HOME=/u01/app/oracle/product/11.2.0/dbhome_1;
            /u01/app/oracle/product/11.2.0/dbhome_1/bin/lsnrctl start listener'''
        
        stdin, stdout, stderr = ssh.exec_command(startListenerCmd)
        logging.info(startListenerCmd)
        result = stderr.read().decode()
        logging.info(result)
        logging.info(stdout.read().decode())
    
        
        checkListenerResult = checkListener(ssh,switchType)
        if checkListenerResult == LISTENER_FAILURE:
            return START_LISTENER_FAILURE
        else:
            return START_LISTENER_SUCCESS
    except Exception, e:
        logging.info(e)
        return START_LISTENER_FAILURE
    

def registerListener(ssh):
    #注册监听
    registerListenerCmd=''' source /home/oracle/.bash_profile;sqlplus / as sysdba << EOF
    alter system register;
    exit;
EOF'''
    logging.info(registerListenerCmd)
    stdin, stdout, stderr = ssh.exec_command(registerListenerCmd)
    result = stderr.read().decode()
    logging.info(result)
    logging.info(stdout.read().decode())


#def shutdownDataBase(ssh,db_unique_name,instance_name):
#    logging.info('begin shutdownDataBase')
#    cmd=''' export ORACLE_HOME=/u01/app/oracle/product/11.2.0/db_1;/u01/app/oracle/product/11.db_1/    bin/#srvctl stop database -d  {0}'''
#    shutdownDataBaseCmd = cmd.format(db_unique_name)
#
#    stdin, stdout, stderr = ssh.exec_command(shutdownDataBaseCmd)
#
#    result = stderr.read().decode()
#    dbResult = checkDB(ssh,instance_name)
#
#    logging.info('end shutdownDataBase')
#    if dbResult == INSTANCE_FAILURE:
#        return STOP_DATABASE_SUCCESS
#    else:
#        return STOP_DATABASE_FAILURE


#def startupDatabase(ssh,db_unique_name):
#    logging.info('begin startupDatabase')
#    #logging.info('begin repair startupDatabase')
#    cmd='''export ORACLE_HOME=/u01/app/oracle/product/11.2.0/db_1;
#    /u01/app/oracle/product/11.2.0/db_1/bin/srvctl start database -d {0}'''
#
#    startDatabaseCmd = cmd.format(db_unique_name)
#
#    logging.info(startDatabaseCmd
#
#    stdin, stdout, stderr = ssh.exec_command(startDatabaseCmd)
#
#    result = stderr.read().decode()
#    logging.info(result
#    logging.info(stdout.read().decode()
#
#    registerListener(ssh)
#
#    conn = getConnectByTns('sys',SWITCHPARAM.SYS_PASSWD,SWITCHPARAM.PROD_TNS)
#    sql='''select status from v$instance'''
#    startResult = excuteSql(conn,sql,TYPE_SELECT)[0][0]
#    
#    #logging.info('end repair startupDatabase')
#    logging.info('end startupDatabase')
#    if(startResult == 'OPEN'):
#        logging.info('startupDatabase success ')
#        return START_DATABASE_SUCCESS
#    else:
#        return START_DATABASE_FAILURE


#def startupDatabase(ssh,tns):
#    operationResult=START_DATABASE_FAILURE
#    
#    cmd ='''
#    source /home/oracle/.bash_profile
#    sqlplus sys/{0}@{1} as sysdba << EOF
#    startup;
#    alter system register;
#    exit;
#EOF'''
#    try:
#        startDatabaseCmd = cmd.format(SWITCHPARAM.SYS_PASSWD,tns)
#        logging.info(startDatabaseCmd
#        stdin, stdout, stderr = ssh.exec_command(startDatabaseCmd)
#
#        result = stderr.read().decode()
#        logging.info(result
#        logging.info(stdout.read().decode()
#
#        conn = getConnectByTns('sys',SWITCHPARAM.SYS_PASSWD,tns)
#        sql='''select status from v$instance'''
#        result = excuteSql(conn,sql,TYPE_SELECT)[0][0]
#        logging.info(result
#        if(result == 'OPEN'):
#            operationResult = START_DATABASE_SUCCESS
#    except Exception ,e:
#        logging.info(e
#        return operationResult
#    return  operationResult


def checkHeartBeat(conn):
    try:
        heartBeatListSql='''insert into appadmin.HEART_BEAT_LIST values (sysdate)'''
        heartBeatSql='''update appadmin.HEART_BEAT_MONITOR set monitor_date=sysdate'''
        checkHeartBeat='''select max(monitor_date) from appadmin.HEART_BEAT_MONITOR'''
        InsertCheckCount = excuteSql(conn,heartBeatListSql,TYPE_INSERT)
        HeartCheckDateBegin = excuteSql(conn,checkHeartBeat,TYPE_SELECT)[0][0]
        IncreaseCheckCount = excuteSql(conn,heartBeatSql,TYPE_INSERT)
        HeartCheckDateEnd = excuteSql(conn,checkHeartBeat,TYPE_SELECT)[0][0]
        if HeartCheckDateBegin < HeartCheckDateEnd:
            #主库可用
            logging.info('主库可用')
            return PRIMARY_VALID
        else:
            logging.info('主库不可用')
            return PRIMARY_FAILURE
    except Exception, e:
        return PRIMARY_FAILURE



# 执行查询sql
def excuteSql(conn,sql,type):
    logging.info('begin excuteSql :' + sql)

    result=''
    cur=conn.cursor()
    try:
        cur.execute(sql)
        if type==TYPE_INSERT:
            conn.commit()
            result = True
        else:
            result=cur.fetchall()
        #异常时数据库cur失效，一般是因为数据库宕机，也无需释放
        cur.close()
    except Exception ,e:
        logging.info(e)
        result = False
    finally:
        logging.info('end   excuteSql')
        return result

def repair(host,instance_name,db_unique_name,switchType):
    logging.info('begin repair############################ switchType is %s' %(switchType))
    # 再次尝试失败
    sshConn = createSshConnect(host)

    #
    #
    # 检测监听
    logging.info('begin repair checkListenerResult ############################')
    checkListenerResult  = checkListener(sshConn,switchType)
    logging.info('end repair checkListenerResult ############################')

    # 检测实例
    logging.info('begin repair checkDB ############################')
    checkInstanceResult = checkDB(sshConn,instance_name)
    logging.info('end repair checkDB ############################')

    # 检测process
    logging.info('begin repair checkProcess ############################')
    checkProcessResult = checkProcess(sshConn,SWITCHPARAM.ALERT_PATH,'sys',SWITCHPARAM.SYS_PASSWD,SWITCHPARAM.PROD_TNS)
    logging.info('end repair  checkProcess############################')
    #checkProcess(ssh,alertPath,username, password, tns)

    # 检测SGA 4031
    #checkSGAResult = checkSGA(sshConn,alertPath)

    repairResult = REPAIR_FAILURE
    #repairResult = REPAIR_SUCCESS
    
    if checkListenerResult == LISTENER_FAILURE:
        startListenerResult = startListener(sshConn,switchType)
        if startListenerResult == START_LISTENER_SUCCESS:
            registerListener(sshConn)
            #执行切换脚本
            repairResult = REPAIR_SUCCESS
            logging.info("startListener success")
            
        else:
            logging.info("startListener failure#################################")
            repairResult = REPAIR_FAILURE


            
            
    
    #if checkSGAResult == SGA_FAILURE:
    #    killSession(sshConn)
    #    shutdownDataBase(ssh,db_unique_name,instance_name)
    #    startInstanceResult == startupDatabase(sshConn,db_unique_name,instance_name)
    #    if startInstanceResult == START_DATABASE_FAILURE:
    #        #执行切换脚本
    #        logging.info("restartInstance failure begin switch")
    #        repairResult = REPAIR_FAILURE
    #    else:
    #        logging.info("restartInstance success")
    #
    if checkProcessResult == PROCESS_FAILURE:
        #process 满情况下，直接杀会话即可
        killSession(sshConn,instance_name)
        conn = getConnectByTns('sys',SWITCHPARAM.SYS_PASSWD,SWITCHPARAM.PROD_TNS)
        #logging.info(result ???
        if  conn != CONNECT_FAILED:
            repairResult = REPAIR_SUCCESS
        else :
            logging.info("checkProcess failure#################################")
    
    if checkInstanceResult == INSTANCE_FAILURE:
        #生产网TNS为动态注册，若数据库宕机，需连接数据网监听
        logging.info("checkInstanceResult instance %s is failure" %(instance_name))
    #    startInstanceResult = startupDatabase(sshConn,db_unique_name)
    #    if startInstanceResult == START_DATABASE_SUCCESS:
    #        repairResult = REPAIR_SUCCESS
    #        logging.info("startInstance success")
    #    else: 
    #        #执行切换脚本
    #        logging.info("startInstance failure begin switch")
    # 关库的一瞬间 实例会残留此时检查不到实例 若进程满，
    # 其实已经杀掉了，所以可以通过检测v$instance 来判断实例是否存在
        repairResult = REPAIR_FAILURE
        logging.info("checkInstance failure#################################")
    logging.info("begin switch #################################")   
        
    logging.info('end repair')
    return  repairResult      

def lockFile(file):
    f = open(file,'w')
    logging.info('begin lockFile %s' %file)
    result = fcntl.flock(f.fileno(), fcntl.LOCK_EX)
    logging.info('acquire lock')
    #time.sleep(100)
    logging.info('lock.txt')
    return f

def unlockFile(file):
    f.close()

#def  executeSwitch():
#    if not os.path.exists(INTERPRETER): 
#        log.error("Cannot find INTERPRETER at path \"%s\"." % INTERPRETER) 
#    processor = "switchtest.py" 
#    
#    pargs = [INTERPRETER, processor] 
#    subprocess.call(pargs) 

def checkManagerStatus(manager_ip):
    logging.info('begin to checkManagerStatus %s' %(manager_ip)) 
    result = CHECK_MANAGER_VALID
    #异常处理
    ssh = createSshConnect(manager_ip)

    if ssh == CREATE_SSH_CONN_FAILD:
        result = CHECK_MANAGER_FAILD
        logging.info('连接带外服务器失败')
        #再次尝试五次
        for i in range (1,5):
            ssh = createSshConnect(manager_ip)
            if ssh == CREATE_SSH_CONN_FAILD:
                logging.info('再次连接带外服务器失败')
                time.sleep(5)
                continue
            else:
                logging.info('再次连接带外服务器成功')
                result = CHECK_MANAGER_VALID
                break
    else:
        logging.info('带外服务器检测可用')
        result = CHECK_MANAGER_VALID

    return result

#共享存储架构下需要关闭原主库
def poweroff():
    
    poweroffResult = POWER_OFF_FAILD
    #若机器已经关闭
    #异常处理
    ssh = createSshConnect(SWITCHPARAM.MANAGER_IP)
    if ssh == CREATE_SSH_CONN_FAILD:
        logging.info('连接带外服务器失败，不能重启原库')
        return poweroffResult
    #待修改
    #poweroffCMD = '''ipmitool -H XXX -I lanplus -U admin -P XXX power off'''
    
    poweroffCMD = '''ipmitool -H {0} -I lanplus -U {1} -P {2} power off'''

    poweroffCMD = poweroffCMD.format(SWITCHPARAM.DAIWAI_IP,SWITCHPARAM.DAIWAI_USER,SWITCHPARAM.DAIWAI_PASSWD)
    #出错重试 8次
    #
    #[root@D1D11U9-25-37 ~]# ipmitool -H XXX -I lanplus -U admin -P XXX power off
    #Error in open session response message : insufficient resources for session
    #
    #Error: Unable to establish IPMI v2 / RMCP+ session
    #[root@D1D11U9-25-37 ~]# ipmitool -H XXX -I lanplus -U admin -P XXX power status
    #Chassis Power is on
    #[root@D1D11U9-25-37 ~]# ipmitool -H XXX -I lanplus -U admin -P XXX power off
    #Chassis Power Control: Down/Off
    try:
        stdin, stdout, stderr = ssh.exec_command(poweroffCMD)

        logging.info('ipmi first poweroff stdout #########################')
        out = stdout.read().decode()
        logging.info(out)


        logging.info('ipmi first poweroff stderr #########################')
        err = stderr.read().decode()
        logging.info(err)


        logging.info('err  first is %s #########################' %(err))


        if err.find('Error') != -1:
            #报错重试
            for i in range (1,10):
                if err.find('Error') != -1:
                    logging.info('第 %s 次关机失败 #########################' %(i))
                    time.sleep(10)
                    stdin, stdout, stderr = ssh.exec_command(poweroffCMD)

                    out = stdout.read().decode()
                    logging.info('ipmi poweroff stdout # # # # # #')
                    logging.info(out)

                    err = stderr.read().decode()
                    logging.info('ipmi poweroff stderr # # # # # #')
                    logging.info(err)


                    logging.info('err %s is %s #########################' %(i,err))
                    #关闭成功则中断循环
                    if err.find('Down') != -1:
                        poweroffResult=POWER_OFF_SUCCESS
                        logging.info('关机成功 #########################')
                        break
        else:
            poweroffResult=POWER_OFF_SUCCESS
            logging.info('关机成功 #########################')
    except Exception, e:
        logging.info(e)
        poweroffResult=POWER_OFF_FAILD
    finally:
        return poweroffResult

    #加入判断


#共享存储架构下需要关闭原主库
#待写
def powerstatus():
    
    poweroffResult = POWER_OFF_FAILD
    #若机器已经关闭
    #异常处理
    ssh = createSshConnect(SWITCHPARAM.MANAGER_IP)
    if ssh == CREATE_SSH_CONN_FAILD:
        logging.info('连接带外服务器失败，不能重启原库')
        return poweroffResult
    #待修改
    #poweroffCMD = '''ipmitool -H XXX -I lanplus -U admin -P XXX power off'''
    
    poweroffCMD = '''ipmitool -H {0} -I lanplus -U {1} -P {2} power status'''

    poweroffCMD = poweroffCMD.format(SWITCHPARAM.DAIWAI_IP,SWITCHPARAM.DAIWAI_USER,SWITCHPARAM.DAIWAI_PASSWD)

    stdin, stdout, stderr = ssh.exec_command(poweroffCMD)
    
    out = stdout.read().decode()

    err = stderr.read().decode()


# 获取数据库角色
def getRole(conn):
    logging.info('begin getRole')
    sql = '''
        select database_role from v$database
        '''
    result = excuteSql(conn, sql)

    rolestatus = ''
    if result:
        rolestatus = result[0][0]
    logging.info('end getRole')
    return rolestatus

#有注释
def executeSwitch(host,switchType,ifTest):
    logging.info('begin executeSwitch ###############################')


    #无共享存储则直接切换
    if switchType == SWITCH_WITHOUT_SHARESTORAGE:
        logging.info('开始切换######################################')
        ##########################可以先注释掉，测试一下，防止错切换
        if ifTest == 'NO':
            logging.info('begin execute switch ！！！！！！！！！！！！')
            # os.system(SWITCHPARAM.SCRIPT)
        else:
            logging.info('测试情况下，开始跑入切换流程')

        return
    

    checkManagerResult = checkManagerStatus(SWITCHPARAM.MANAGER_IP)
    
    #带外可用，带共享存储则通过带外进行关机
    if checkManagerResult == CHECK_MANAGER_VALID and switchType == SWITCH_WITH_SHARESTORAGE:
        # 判断备库控制文件是否被覆盖成主库的控制文件，若未被覆盖，持久化备库数据文件和归档路径

        logging.info('带外服务器开始关闭目标机器 %s' %(host))
        ###########################可以先注释掉，测试一下，防止错切换
        #poweroffResult = poweroff()
        poweroffResult = POWER_OFF_FAILD
        if poweroffResult == POWER_OFF_FAILD:
            #带外关闭异常可能是服务器本身已经关机
            logging.info('带外服务器关闭目标机异常')
        else:
            logging.info('带外服务器关闭目标机正常')
    else:
        logging.info('带外服务器不可用')
    #检测原主库是否关机成功
    netCheckResult = NetCheck(host)

    if netCheckResult == IP_VALID:
    
        primayStatus = IP_VALID
        logging.info('主库 %s %s 尚未关机完成' %(host,switchType))
        for i in range (1,5):
            time.sleep(10)
            netCheckResult = NetCheck(host)
            if netCheckResult == IP_FAILD:
                primayStatus = IP_FAILD
                logging.info('第 %s 次检查 主库关机完成开始切换')
                logging.info('第 %s 次检查 开始切换######################################')
                ############################可以先注释掉，测试一下，防止错切换
                if ifTest == 'NO':
                    logging.info('begin execute switch ！！！！！！！！！！！！')
                    # os.system(SWITCHPARAM.SCRIPT)
                else:
                    logging.info('测试情况下，开始跑入切换流程')
                break
            else :
                logging.info('第 %s 次检查主库仍然开机，无法进行切换 请手动使用带外服务器关闭主库' %(i))
        #if  primayStatus== IP_VALID   
    else:
        logging.info('主库关机完成开始切换')
        logging.info('开始切换######################################')
        ############################可以先注释掉，测试一下，防止错切换
        if ifTest == 'NO':
            logging.info('begin execute switch ！！！！！！！！！！！！')
            # os.system(SWITCHPARAM.SCRIPT)
        else:
            logging.info('测试情况下，开始跑入切换流程')


#检测备库延迟通过scn和systimestamp 比较
def checkStandbyLag(std_dns):
    logging.info('begin checkStandbyLag ####################')
    StandbyLagMin=-1
    try:
        checkStandbyLagSql = '''SELECT round((to_date(to_char(systimestamp, 'yyyy-mm-dd hh24:mi:ss'), 
        'yyyy-mm-dd hh24:mi:ss') -
        to_date(to_char(scn_to_timestamp(current_scn),
        'yyyy-mm-dd hh24:mi:ss'), 
        'yyyy-mm-dd hh24:mi:ss')) * 24 * 60) gap_min
        FROM v$database'''

        conn = getConnectByTns('sys', SWITCHPARAM.SYS_PASSWD, std_dns)

        result = excuteSql(conn,checkStandbyLagSql,TYPE_SELECT)
        #备库延迟分钟数
        StandbyLagMin = result[0][0]

        logging.info('checkStandbyLag StandbyLagMin is %s' %(StandbyLagMin))
    except Exception as e:
        logging.info(e) 
        logging.info('checkStandbyLag StandbyLagMin is %s' %(StandbyLagMin))
        StandbyLagMin = -1
    logging.info('end checkStandbyLag ####################')
    return StandbyLagMin
    

#检测备库SCN是否改变
def checkScnChange(std_dns):
    logging.info('begin checkScnChange ####################')
    scnChange=-1
    try:
        checkScnChangeSql = '''SELECT current_scn FROM v$database'''

        conn = getConnectByTns('sys', SWITCHPARAM.SYS_PASSWD, std_dns)

        resultBefore = excuteSql(conn,checkScnChangeSql,TYPE_SELECT)
        #备库延迟分钟数
        scnBefore = resultBefore[0][0]
        
        time.sleep(5)

        resultAfter = excuteSql(conn,checkScnChangeSql,TYPE_SELECT)

        scnAfter = resultAfter[0][0]

        scnChange = scnAfter-scnBefore
        logging.info('checkScnChange scnChange is %s' %(scnChange)) 
    except Exception as e:
        logging.info(e)
        logging.info('checkScnChange scnChange is %s' %(scnChange)) 
        scnChange = -1
    logging.info('end checkScnChange ####################')
    return scnChange

def checkMrpStatus(std_dns):
    logging.info('begin checkScnChange ####################')

    checkMrpSql='''select count(*) from v$managed_standby where process='MRP0' '''

    conn = getConnectByTns('sys', SWITCHPARAM.SYS_PASSWD, std_dns)

    if conn == CONNECT_FAILED:
        logging.info('begin checkScnChange conn failed ####################')
        logging.info('end checkScnChange ####################')
        return False


    result = excuteSql(conn,checkMrpSql,TYPE_SELECT)

    mrpResult = result[0][0]

    if mrpResult == 1:
        logging.info('checkMrpStatus mrp 存在')
        return True
    else :
        logging.info('checkMrpStatus mrp 不存在')
        return False

    logging.info('end checkScnChange ####################')

def getDataArchiveFilePath(std_dns):
    try:
        logging.info('begin getDataArchivefilePath ####################')

        getPathSql = '''
        select distinct(substr(name,instr(name,'/',1,1),instr(name,'/',-1,1))) from v$datafile union select distinct(substr(name,instr(name,'/',1,1),instr(name,'/',-1,1))) from v$ARCHIVED_LOG
        '''
        logging.info(getPathSql)

        conn = getConnectByTns('sys', BJPARAM.SYS_PASSWD, std_dns)

        if conn == CONNECT_FAILED:
            logging.info('getDataArchivefilePath conn failed  %s ####################' % (std_dns))
            logging.info('end getDataArchivefilePath ####################')
            return False

        result = excuteSql(conn, getPathSql, TYPE_SELECT)

        pathList = []
        for i in result:
            if i[0] != None:
                pathList.append(i[0])
        logging.info('end getDataArchivefilePath ####################')
        return pathList
    except Exception as e:
        logging.info(e)
        logging.info('end getDataArchiveFilePath    %s ####################' % (std_dns))
        return False


def persistentDataArchivePath(pathList, pathfile):
    try:
        logging.info('begin persistentDataArchivePath    %s ####################' % (pathfile))
        # 覆盖前目录
        foBefore = open(pathfile)
        pathBefore = foBefore.read()

        logging.info('覆盖前目录为%s' % (pathBefore))

        liststr = "^".join(pathList)
        # list3 = liststr.split("^")
        logging.info('新写入目录为%s' % (liststr))

        print pathfile
        fo = open(pathfile, 'w+')

        fo.write(liststr)
        fo.close()

        foafter = open(pathfile)
        pathAfter = foafter.read()
        logging.info('新写入目录为%s' % (pathAfter))
        logging.info('end persistentDataArchivePath    %s ####################' % (pathfile))
        return True
    except Exception as e:
        logging.info(e)
        logging.info('end persistentDataArchivePath    %s ####################' % (pathfile))
        return False



# 根据
# 1、备库SCN是否增长     
# 2、延迟是否大于60分钟  （延迟大于60分 ，需要手工确认，不执行自动切换）
# 返回True ： 不进行切换  （SCN在增长  或者延迟过高，不进行切换）
# 返回False： 进行切换
# 判断循环是否跳出

def checkLag():

    ifContinue = False
    #加入standby 延迟检测	


    scnChange = checkScnChange(SWITCHPARAM.STANDBY_TNS)
    
    if scnChange > 0:
        logging.info('备库SCN在增长，主库状态正常')
        ifContinue = True
        return ifContinue

    checkStdyLag = checkStandbyLag(SWITCHPARAM.STANDBY_TNS)


    

    if checkStdyLag > STANDBY_MAX_LAG:
        logging.info('备库延迟过高，请确认是否有断档')
        ifContinue = True
        return ifContinue
    
    return ifContinue

#
# return continue
#        switch 
# 网关检测
def checkSwitchWithGateWay(gateway,host,instance_name,db_unique_name,switchType):

    checkSwitchStatus = CHECK_CONTINUE
    gateWayStatus = NetCheck(gateway)
    hostStatus = NetCheck(host)
    logging.info('hostStatus  is %s ' %(hostStatus)) 

    if gateWayStatus == IP_FAILD:
        #若ping不通网关，不中断循环，继续监测
        #网关暂时不通
        logging.info('网关暂时不通')
        checkSwitchStatus = CHECK_CONTINUE
    #网关通 ip不通则直接切换
    elif hostStatus == IP_FAILD:
        logging.info('网关通IP不通执行切换')
        checkSwitchStatus = CHECK_SWITCH
        #executeSwitch(host,switchType)
    #网关通，ip通尝试修复
    else:
        repairResult = repair(host,instance_name,db_unique_name,switchType)
        if repairResult == REPAIR_SUCCESS:
            conn = getConnectByTnsNoSys(SWITCHPARAM.MONITOR_USER, SWITCHPARAM.MONITOR_PASS, SWITCHPARAM.PROD_TNS)
            logging.info('repair 1 time')
            checkSwitchStatus = CHECK_CONTINUE
        #若恢复失败执行切换
        else:
            #再次检测
            #executeSwitch(host,switchType)
            checkSwitchStatus = CHECK_SWITCH
    return checkSwitchStatus

# 心跳+网关检测
def checkSwitchWithHeartBeat(conn,host,instance_name,db_unique_name,switchType):
    checkSwitchStatus = CHECK_CONTINUE
    checkresult = checkHeartBeat(conn)
    #可以检测到心跳
    if checkresult == PRIMARY_VALID:
        conn.close()
        checkSwitchStatus = CHECK_CONTINUE
    #检测心跳失败
    else:
        #再次尝试五次
        checkAgain = 0
        for i in range (1,5):
            time.sleep(10)
            checkresult = checkHeartBeat(conn)
            if checkresult == PRIMARY_VALID:
                checkAgain = 1
                break

        # 再次尝试心跳测试成功
        if checkAgain == 1:
            #整个循环继续
            checkSwitchStatus = CHECK_CONTINUE
        # 再次尝试心跳测试失败
        else:
            checkSwitchStatus = CHAECK_IFLAG


    return checkSwitchStatus

# host           对应主库主机ip              #用来创建ssh连接
# instance_name  对应需要检测的实例名        #用来判断进程是否存在
# db_unique_name 需要检测数据库的unique_name #用来让srvctl 操作数据库
# gateway        本机的网关                  #用来判断是否可以连接交换机
# 超时时间

def executeCheck(host,instance_name,db_unique_name,gateway,switchType,ifTest):

    #防止重复执行
    result = checkMonitor()
    logging.info(result)
    if result > 1:
        logging.info('请勿重复执行脚本')
        return
    #lockFile('/tmp/lock.txt')
    #logging.info('end executeCheck2')
    #conn = getConnectByTns('sys', SWITCHPARAM.SYS_PASSWD, SWITCHPARAM.PROD_TNS)
    while(True):
        #监听关闭不会影响原有链接，所以每10秒要检测一次连接是否正常

        time.sleep(10)
        conn = getConnectByTnsNoSys(SWITCHPARAM.MONITOR_USER, SWITCHPARAM.MONITOR_PASS, SWITCHPARAM.PROD_TNS)
        
        #连接创建失败
        if conn == CONNECT_FAILED:
            
            ifContinue = checkLag()

            if  ifContinue == True:
                continue
         
            #ping 网关看是否是机器自身问题并尝试修复
            checkResult = checkSwitchWithGateWay(gateway,host,instance_name,db_unique_name,switchType)  

            if checkResult == CHECK_CONTINUE:
                conn = getConnectByTnsNoSys(SWITCHPARAM.MONITOR_USER, SWITCHPARAM.MONITOR_PASS, SWITCHPARAM.PROD_TNS)
                continue
            if checkResult == CHECK_SWITCH:
                executeSwitch(host,switchType,ifTest)
                break
        #连接创建成功        
        if conn != CONNECT_FAILED:
            #检测心跳
            checkResult = checkSwitchWithHeartBeat(conn,host,instance_name,db_unique_name,switchType)

            if checkResult == CHECK_CONTINUE:
                continue
            if checkResult == CHAECK_IFLAG:
                ifContinue = checkLag()
                if  ifContinue == True:
                    continue
                else:
                    checkGateWayResult = checkSwitchWithGateWay(gateway,host,instance_name,db_unique_name,switchType)
                    if checkResult == CHECK_CONTINUE:
                        conn = getConnectByTnsNoSys(SWITCHPARAM.MONITOR_USER, SWITCHPARAM.MONITOR_PASS, SWITCHPARAM.PROD_TNS)
                        continue
                    if checkResult == CHECK_SWITCH:
                        executeSwitch(host,switchType,ifTest)
                        break


# python2.6 monitor.py -t YES  测试
# python2.6 monitor.py 正式监控
def parse_args():
    parser = argparse.ArgumentParser(formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    #是否测试monitor 脚本。默认传入YES， 防止误切换
    parser.add_argument('-t', '--test', default='NO', help="ifTest monitor script",
                        required=False)
    args = parser.parse_args()
    logging.info(args)
    return args




if __name__=='__main__':
    #NetCheck('1.1.1.1')
    #conn = getConnectByTns('sys', 'oracle', 'BJ')
    #ssh = createSshConnect('1.1.3.71')
    #checkHeartBeat(conn)
    #executeSwitch()
    #repair('1.1.3.71','SH','SH','/u01/app/oracle/diag/rdbms/sh/SH/trace/alert_SH.log')
    #result = checkDB(ssh,'SH')
    #logging.info(result
    #startupDatabase(ssh,'SH','SH')
    #startListener(ssh)
    #shutdownDataBase(ssh,'SH','SH')
    #result = checkMonitor()
    #logging.info(result
    args = parse_args()
    ifTest = args.test
    executeCheck(SWITCHPARAM.PRIMARY_IP,SWITCHPARAM.PRIMARY_INSTANCE_NAME,SWITCHPARAM.PRIMARY_DB_UNIQUE_NAME,SWITCHPARAM.GATE_WAY,SWITCH_WITH_SHARESTORAGE,ifTest)
    #getConnectByTns('sys', 'oracle', 'SH')
    #f=lockFile('./lock.txt')
    #unlockFile(f)
    #f=lockFile('./lock.txt')
    #logging.info(f 
    #NetCheck('1.1.3.72')
    #register()
    #startListener(ssh)
    #executeSwitch()
    #checkStandbyLag(SWITCHPARAM.STANDBY_TNS)
    #poweroff()
    #checkLag()
    print SWITCHPARAM.SYS_PASSWD


