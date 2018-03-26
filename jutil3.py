import argparse, sys, traceback, datetime, re, time, ftplib, tarfile, os, logging, textwrap, getpass, fnmatch, paramiko, csv, pdb 
import atexit, queue, weakref, cProfile
#from jnpr.jsnapy import SnapAdmin 
#import asyncio
#import uvloop
from netmiko import ConnectHandler
from netmiko.ssh_exception import NetMikoTimeoutException, NetMikoAuthenticationException
from concurrent.futures import _base, ThreadPoolExecutor, ProcessPoolExecutor, TimeoutError
from multiprocessing import Lock, Pool
from pebble import ProcessPool, ProcessExpired
#from multiprocessing.dummy import Pool 
from lxml import etree
from shutil import rmtree, move, copyfileobj
from threading import Thread, BoundedSemaphore 
from threading import Lock as tLock
from scp import SocketTimeout, SCPException
from contextlib import contextmanager
from redo import retry, retriable
from jnpr.junos.device import Device
from jnpr.junos.utils.start_shell import StartShell
from jnpr.junos.utils.fs import FS
from jnpr.junos.utils.scp import SCP
from jnpr.junos.exception import *
from jnpr_cmds import *
from jnpr.junos.op.fpc import FpcHwTable
from jnpr.junos.op.fpc import FpcInfoTable
from jnpr.junos.op.vc import VcMemTable 

cmd_set_shell_Q = {"EX4300"     : ex4300_cmds_shell_Q,
                   "QFX5100"    : qfx5100_cmds_shell_Q,
                   "PTX5000"    : ptx_cmds_shell_Q,
		           "QFX10002"   : qfx10002_cmds_shell_Q,
                   "QFX10008"   : qfx10008_cmds_shell_Q,
                   "QFX10016"   : qfx10008_cmds_shell_Q,
                   "MX"         : mx_cmds_shell_Q}                   
                   #"QFX5100_VXL": qfx5100_vxlan_cmds_shell_Q,
                   #"SRX_BRANCH" : srx_cmds_shell_Q,
                   #"SRX_HIGHEND": srx_cmds_shell_Q}

cmd_set_shell_D = {"EX4300"     : ex4300_cmds_shell_D,
                   "QFX5100"    : qfx5100_cmds_shell_D,
                   "PTX5000"    : ptx_cmds_shell_D,
		           "QFX10002"   : qfx10002_cmds_shell_D,
                   "QFX10008"   : qfx10008_cmds_shell_D,
                   "QFX10016"   : qfx10008_cmds_shell_D,
                   "MX"         : mx_cmds_shell_D}                   
                   #"QFX5100_VXL": qfx5100_vxlan_cmds_shell_D,
                   #"SRX_BRANCH": srx_cmds_shell_D,
                   #"SRX_HIGH"  : srx_cmds_shell_D,


"""
Utility function for RPC calls and absorb errors
"""
@contextmanager
def exec_rpc_handle_errors(rpc, *exceptions, **args):
    logger = args['logger']
    try:
        yield
    except RpcError:
        if rpc == "Zip Collected Data":
            sh, source, dest = args['sh'], args['source'], args['dest']
            sh.run("cli -c 'file archive compress source " + source + ' ' + 'destination ' + dest + "'",timeout=240)
            #TODO: This does not seem to work for CLI commands
            if not sh.last_ok:
                raise Exception
        elif rpc == "Archive /var/log":
            sh, source, dest = args['sh'], args['source'], args['dest']
            sh.run("cli -c 'file archive compress source " + source + ' ' + 'destination ' + dest + "'",timeout=600) 
            if not sh.last_ok:
                logger.error('unable to collect /var/log from Master RE')
    except PermissionError:
        logger.error("{} PermissionErorr: Insufficient Privileges".format(rpc))
    except Exception as ex:
        logger.exception()

def func_exception_decorator(logger):
    """
    A decorator that wraps the passed in function and logs 
    exceptions should one occur
    @param logger: The logging object
    """
    def decorator(func):
        def wrapper(*args, **kwargs):
            try:
                return func(*args, **kwargs)
            except:
                # log the exception
                err = "There was an exception in  "
                err += func.__name__
                logger.exception(err)

            # re-raise the exception
            raise
        return wrapper
    return decorator

def parse_and_run_cmdfile(node, sh, args, uname, rpwd, logfile, logger):
    if args.detail:
        logger.info("--detail ignored as --cmdfile specified")
    
    if not os.path.isfile(args.cmdfile.strip()):
        logger.error('Unable to find cmdfile: {}'.format(args.cmdfile))
        sys.exit(1)
    
    with open(args.cmdfile, 'r') as cmdfile:
        try:
            cmd_type = ''
            cmd_list = []
            #fpcs = []
            for index, comd in enumerate(cmdfile):
                md = comd.strip().split(':')[0]
                if not md:
                    continue
                elif md == 'cli':
                    cmd_type = 'cli'
                    continue 
                elif md in ('shell','vty'):
                    fpcs=[]
                    if md == 'shell':
                        cmd_type = 'shell'
                    if md == 'vty':
                        cmd_type = 'vty'
                     
                    try:
                        ft = comd.strip().split(':')[1]
                    except IndexError:
                        logger.info("FPC not specified for vty command, running against FPC0")
                        fpcs=[0]
                    else:
                        fpcs_hwinfo = FpcHwTable(node).get()
                        fpcs_info = FpcInfoTable(node).get()
                        if ft.lower() == 'fpc':
                            try:
                                fpcs = comd.strip().split(':')[2].split(',')
                                for fpc in fpcs_info:
                                    if fpc.key in fpcs and fpc.state != 'Online':
                                        # Remove any fpcs that are not online and that do not exist on a given platform.
                                        logger.error("Skipping fpc{} because state is {}".format(fpc.key, fpc.state))
                                        fpcs.remove(fpc.key)
                            except IndexError:
                                logger.info("FPC number not specified for vty command, running against FPC0")
                                fpcs=[0]
                        elif ft.lower() == 'model':
                            #populate fpcs based on model match
                            for fpc, fpchw in zip(fpcs_info,fpcs_hwinfo):
                                if fpc.state == 'Online' and fpchw.model in comd.strip().split(':')[2].split(','):
                                    fpcs.append(fpc.key)
                        else:
                            logger.error("Invalid fpc option. EX: vty:fpc:1,2,4 or vty:model:MX-MPC2E-3D")
                            logger.error("Obtain model type from 'show chassis hardware clei-models'")
                    continue
                #elif md.split(':')[0] == 'delay':
                #    logger.info('Sleeping for {} seconds'.format(comd.strip().split(':')[1]))                     
                #    time.sleep(comd.strip().split(':')[1])
                #    continue
                else:
                    if cmd_type == 'cli':
                        element = "cli -c '" + comd.strip() + "'"
                        cmd_list.append(element)
                    elif cmd_type in ('shell','vty'):
                        #if comd has " they need to be escaped \
                        for fpc in fpcs:
                            if cmd_type == 'vty':
                                cmd_list.append("cli -c 'request pfe execute command " + comd.strip().split("#")[0] + " target fpc" + str(fpc)""""'""")
                            else:
                                cmd_list.append("rsh -Ji fpc" + str(fpc) + " " + comd.strip().split("#")[0])
                            continue
                    else:
                        logger.error('Command mode (cli, shell or vty) not specified in command file')
                        sys.exit(1)
                     
            #Execute the command list parsed from the cmdfile
            execute_cmd_list(node, sh, args.force, logfile, cmd_list, logger)
        except IOError as e:
            logger.error('Operation failed: {}'.format(e.strerror))
            sys.exit(1)
        except:
            logger.error('Unexpected error: %s', sys.exc_info()[0])
            sys.exit(1)
        finally:
            cmdfile.close()

def vc_check(node, vc, logger):
    if node.facts['model'] == 'Virtual Chassis':
        fpcs_hwinfo = FpcHwTable(node).get()
        vc_platform = [fpc.model.split('-')[0] for fpc in fpcs_hwinfo]
        
        if vc_platform[0] not in ('QFX5100', 'EX4300'):
            logger.error('Only EX4300 and QFX5100 VC supported')
            return None, False

        # Skip if mixed VC                
        if len(set(vc_platform)) > 1:
            logger.error('Mixed VC not supported')
            return None, False

        vc = set(vc_platform).pop()
        return vc, True

    return None, True

def select_cmd_set(node, vc, logger):
    # TODO: Verify SRX cluster
    person_platform = ('MX', 'SRX_BRANCH', 'SRX_HIGHEND')
    if node.facts['personality'] in person_platform:
        cmd_set = node.facts['personality']
    elif node.facts['model'] == 'Virtual Chassis':
        cmd_set = vc 
    else:
        cmd_set = node.facts['model'].split('-')[0]
#    if args.vxlan:
#        if cmd_set == 'QFX5100':
#            cmd_set = 'QFX5100_VXL'
#        else:
#            logger.error("VXLAN data collection supported only for QFX5100")
    return cmd_set
"""
    elif node.facts['model'] == 'Virtual Chassis':
        fpcs_hwinfo = FpcHwTable(node).get()
        vc_platform = [fpc.model.split('-')[0] for fpc in fpcs_hwinfo]
                        
        # Skip if mixed VC                
        if len(set(vc_platform)) > 1:
            logger.error('Logs from members not supported for mixed VC')
            return 
        elif vc_platform[0].split('-')[0] in ('QFX5100', 'EX4300'):
            #Grab logs from backup members
            vc_mem = VcMemTable(node).get()
            master = 'fpc0'
            
            for mem in vc_mem:
                if mem.role: 
                    cmd_set = fpc.model.split('-')[0]
                    break
        else:
            logger.error('Only EX4300 and QFX5100 VC supported')
        #rsp = node.rpc.get_chassis_inventory()
        #for element in rsp.iter('name'):
        #    if element.text == 'FPC 0':
        #        for elem in element.getparent().getchildren():
        #            if elem.tag == 'model-number': 
        #                cmd_set = elem.text.split('-')[0]
"""
    
def execute_cmd_list(node, sh, force, logfile, cmd_list, logger):
    #for QFX5100 and EX4300, append the following tp cmd_list for SFPs present
    #"""cprod -A fpc0 -c 'show sfp 1'""",
    #"""cprod -A fpc0 -c 'show sfp 1 info'""",
    #"""cprod -A fpc0 -c 'show sfp 1 alarms'""",
    #"""cprod -A fpc0 -c 'show sfp 1 diagnostics all'
    for index, element in enumerate(cmd_list):
        import string
        translation = str.maketrans("", "", string.ascii_letters + string.punctuation + string.whitespace)
        try:
            cmd = element.split('#')[0]
            real_pos = element.split('#')[1].split(':')[0]
            pos = int(real_pos.translate(translation)) + 4 
        except IndexError:
            run_cmd(node, sh, index, element, force, logfile, logger)
        except:
            logger.error('Unexpected error: %s', sys.exc_info()[0])
            raise
        else:
            try:
                real_start = element.split('#')[1].split(':')[1]
                real_end = element.split('#')[1].split(':')[2]
                start = int(real_start.translate(translation))
                end = int(real_end.translate(translation)) + 1
            except IndexError:
                logger.error("Invalid command syntax")
            else:
                try:
                    real_interval = element.split('#')[1].split(':')[3]
                    interval = int(real_interval.translate(translation))
                except IndexError:
                    for i in range(start, end):
                        run_cmd(node, sh, index, ' '.join(cmd.split()[:pos-1]) + ' ' + str(i) + ' ' + ' '.join(cmd.split()[pos:]), force, logfile, logger)
                        index += 1
                else:
                    for i in range(start, end, interval):
                       run_cmd(node, sh, index, cmd.split()[:pos-1] + ' ' + str(i) + ' ' + cmd.split()[pos:], force, logfile, logger)
                       index += 1
                

def collect_gcore(node, sh, fs, args, uname, rpwd, logger):
    logger.info('Collecting {} core....'.format(args.core))
    """
    # write coredump          // this is to take a live core-dump
    """ 
    if args.core=='live':
        #Remove all exisiting live cores
        #TODO: Can accidentally delete useful kernel core
        rt = fs.stat('/var/tmp/vmcore.*')
        while rt is not None:
            logger.info("Removing %s", rt['path'])
            sh.run("rm " + rt['path'])
            rt = fs.stat('/var/tmp/vmcore.*')

        logger.debug('Dumping live core')
        
        # Dump the live core 
        sh.run("cli -c 'request system live-core'", timeout=999)
        tm = 0
        
        # Loop until stat is successful for new vmcore file
        while fs.stat('/var/tmp/vmcore.*') is None:
            # Break from loop if core not available after 5 mins
            if tm >= 300:
                logger.info('Skipping live core after waiting 5 mins')
                break
            logger.info('Waiting 15 seconds while live core is generated')
            tm += 15
            time.sleep(15)
        logger.debug('Moving live core to /var/tmp/data')
        sh.run("mv /var/tmp/vmcore.* /var/tmp/data/")
    else:
        result = sh.run("ps -auxw | grep -w " + args.core.strip() + " | grep /sbin | awk '{print $2}' > /var/tmp/data/pids.log")
        
        with exec_rpc_handle_errors("Read pid file for core", Exception, logger=logger):
            if fs.stat('/var/tmp/data/pids.log') is not None:
                pids = fs.cat('/var/tmp/data/pids.log').splitlines()
         
        if pids:
            # In case multiple pids returned
            for index, pd in enumerate(pids):
                if pd:        
                    filename = "/var/tmp/data/" + args.core.strip() + ".gcore." + str(index)
                    element = "gcore -c " + filename + ' ' + pd.strip()
                    sh.run(element, timeout=999)
                        
                    # Gzip generated core file to save disk space
                    sh.run("gzip " + filename, timeout=120)
                    if fs.stat(filename):
                        fs.rm(filename)
                    
                    logger.info("Core collection completed")
            fs.rm('/var/tmp/data/pids.log')
        else:
            logger.error("Process not running or invalid process")

def archive_rsi_varlog(node, cmd_set, sh, fs, args, uname, rpwd, logger):
    if not args.norsi and verify_load(node, logger, 1.5):       
        # Collect host logs for virtualized platforms
        if cmd_set in ('QFX5100','QFX10002','QFX10008','QFX10016'):
            try:
                collect_host_logs(node, sh, logger)
            except:
                logger.error("Could not retrieve host logs")
        
        logger.info("Collecting RSI.....")
        sh.run("cli -c 'request support information | no-more | save /var/tmp/data/" + node.facts['hostname'] + \
                '@' + datetime.datetime.now().strftime("%m-%d-%Y-%H-%M") + "_rsi.log'", timeout=600)
        logger.info("RSI Completed")
  
        logger.info("Archiving /var/log.....")
        dest = '/var/tmp/data/' + node.facts['hostname'] + '_'+'varlog'+'@' + datetime.datetime.now().strftime("%m-%d-%Y-%H-%M")
        with exec_rpc_handle_errors("Archive /var/log", RpcError, PermissionError, sh=sh, source='/var/log', dest=dest, logger=logger):
            fs.tgz('/var/log', dest)
         
        # For dual RE platforms, get varlog from backup as well
        if node.facts['2RE'] == True:
            fpcs_hwinfo = FpcHwTable(node).get()

            if node.facts['personality'] in ('SRX_BRANCH', 'SRX_HIGHEND'):
                if node.facts['srx_cluster'] == True:
                    pass
            elif node.facts['model'] == 'Virtual Chassis':
                vc_platform = [fpc.model.split('-')[0] for fpc in fpcs_hwinfo]
                
                # Skip if mixed VC                
                if len(set(vc_platform)) > 1:
                    logger.error('Logs from members not supported for mixed VC')
                elif vc_platform[0].split('-')[0] in ('QFX5100', 'EX4300'):
                    #Grab logs from backup members
                    
                    vc_mem = VcMemTable(node).get()
                    master = 'fpc0'
                    
                    for mem in vc_mem:
                        if mem.role and mem.role.rstrip('*').lower() == 'master':
                            master = mem.slot.lstrip('(').rstrip(')').lower().replace(" ", "")
                            break 

                    for mem in vc_mem:
                        if mem.role and mem.role.rstrip('*').lower() != 'master':
                            sh.run("cli -c 'request session member " + mem.id + "'")                        
                            rfilename = mem.model + '_mem' + mem.id + '_' + \
                                datetime.datetime.now().strftime("%m-%d-%Y-%H-%M") + "_rsi.log"
                            vfilename = mem.model + '_mem' + mem.id + '_' + \
                                datetime.datetime.now().strftime("%m-%d-%Y-%H-%M") + "_varlog"
                            
                            logger.info("Collecting RSI from member {}.....".format(mem.id))                     
                            sh.run("cli -c 'request support information | no-more | save " + "/var/tmp/" + rfilename + "'", timeout=600)
                            logger.info("RSI Completed for member {}".format(mem.id))
                            
                            logger.info("Archiving /var/log from {}.....".format(mem.id))
                            dest = master + ":/var/tmp/data/" + vfilename
                            with exec_rpc_handle_errors("Archive /var/log", RpcError, PermissionError, sh=sh, source='/var/log', dest=dest, logger=logger):
                                fs.tgz('/var/log', dest) 
                            
                            logger.info("Moving RSI and var/log from backup to master RE")
                            #TODO: Convert to RPC and add error checking
                            sh.run("cli -c 'file copy " + "/var/tmp/" + rfilename + " " + master + ":/var/tmp/data'", timeout=300)
                            sh.run("cli -c 'file delete " + "/var/tmp/" + rfilename + "'")
                            
                            sh.run("exit")
                            # Without change of permission, zipping of varlog fails
                            sh.run("chmod 755 /var/tmp/data/" + vfilename + ".tgz")
            else:
                ok, got = sh.run("cli -c 'request routing-engine login other-routing-engine'")
                if ok:
                    rfilename = node.facts['hostname'] + '_' + datetime.datetime.now().strftime("%y-%m-%d-%H-%M") + "_bkup_rsi.log"
                    vfilename = node.facts['hostname'] + '_' + "varlog_bkup@" + datetime.datetime.now().strftime("%y-%m-%d-%H-%M")
                    
                    # TODO: Collect only if backup RE is up 
                    logger.info("Collecting RSI from backup RE.....")                     
                    sh.run("cli -c 'request support information | no-more | save " + "/var/tmp/" + rfilename + "'", timeout=600)
                    logger.info("RSI from backup RE Completed")

                    logger.info("Archiving /var/log from backup RE.....")
                    dest = node.facts['master'].lower() + ":/var/tmp/data/" + vfilename
                    sh.run("cli -c 'file archive compress source /var/log " + 'destination ' + dest + "'",timeout=600)

                    #with exec_rpc_handle_errors("Archive /var/log", RpcError, PermissionError, sh=sh, source='/var/log', dest=dest, logger=logger):
                    #    fs.tgz('/var/log', dest) 
                    
                    logger.info("Moving RSI and var/log from backup to master RE")
                    sh.run("cli -c 'file copy " + "/var/tmp/" + rfilename + " " + node.facts['master'].lower() + ":/var/tmp/data'", timeout=300)
                    sh.run("cli -c 'file delete " + "/var/tmp/" + rfilename + "'")
                    
                    sh.run("exit")
                    # Without change of permission, zipping of varlog fails
                    sh.run("chmod 755 /var/tmp/data/" + vfilename + ".tgz")            
                else:
                    logger.error("Unable to connect to backup routing engine")
        
            # For MX also include FPC syslog & nvram
            if node.facts['model'] != 'Virtual Chassis':
                fpcs_info = FpcInfoTable(node).get()
                for fpc, fpchw in zip(fpcs_info,fpcs_hwinfo):
                    if fpc.state == 'Online':
                        logger.info("Collecting syslog info from fpc{} - {}".format(fpc.key, fpchw.model))
                        sh.run_to_file("cli -c 'request pfe execute target fpc" + fpc.key + \
                        """ command "show syslog messages" | no-more'""", fname = "/var/tmp/data/fpc_syslog.txt")

                        if node.facts['personality'] in ('MX','PTX'):
                            logger.info("Collecting nvram info from fpc{} - {}".format(fpc.key, fpchw.model))
                            sh.run_to_file("cli -c 'request pfe execute target fpc" + fpc.key + \
                            """ command "show nvram" | no-more'""", fname = "/var/tmp/data/fpc_nvram.txt")
                            if node.facts['personality'] in ('MX',):
                                sh.run_to_file("cli -c 'request pfe execute target fpc" + fpc.key + \
                                """ command "show hsl2 statistics detail" | no-more'""", fname = "/var/tmp/data/fpc_hsl.txt")

        logger.info("/var/log Completed")
    else:
        logger.debug("Skipping RSI and /var/log")

def zip_collected_data(node, sh, fs, ufname, logger):
    with exec_rpc_handle_errors("Zip Collected Data File", RpcError, PermissionError, sh=sh, source='/var/tmp/data', dest=ufname, logger=logger):
        fs.tgz(ufname, ufname)
    
    with exec_rpc_handle_errors("Zip Collected Data", RpcError, PermissionError, sh=sh, source='/var/tmp/data', dest=ufname, logger=logger):
        fs.tgz('/var/tmp/data', ufname)

def scpprintTotals(filename, size, Transferred):
    if size < 1024^2:
        print("Transferred: {2}K Out of: {1}K of {0}".format(filename, size/1024, Transferred/1024))
    else:
        print("Transferred: {2}M Out of: {1}M of {0}".format(filename, size/(1024*1024), Transferred/(1024*1024)))

def transfer_data_back_to_server(node, fs, ufname, logger):
    logger.info("Transferring {} back to server....".format(ufname.split('/')[3] + '.tgz'))
    
    with SCP(node, progress=True) as scp:
        scp.get(remote_path= ufname + '.tgz', local_path='./', preserve_times=True)

def printTotals(transferred, toBeTransferred):
    print("Transferred: {0}M Out of: {1}M".format(transferred/1024^2, toBeTransferred/1024^2))

def retrieve_and_upload_collected_data(node, sh, fs, log_dir, logger):
    ufname = '/var/tmp/' + node.facts['hostname'] + '_' + datetime.datetime.now().strftime("%m-%d-%Y-%H-%M")
    
    try:
        retry(zip_collected_data, attempts=3, sleeptime=10, max_sleeptime=35, \
            sleepscale=1.1, jitter=0, retry_exceptions=(RpcTimeoutError,), args=(node, sh, fs, ufname, logger))
    except Exception as err:
        logger.error('Unable to archive collected data after 3 attempts: {0}\n'.format(err))
    else:
        sh.run("chmod 777 " + ufname + ".tgz")
        try:
            retry(transfer_data_back_to_server, attempts=3, sleeptime=10, max_sleeptime=35, \
                sleepscale=1.1, jitter=0, retry_exceptions=(Exception,), args=(node, fs, ufname, logger))
        except Exception as err:
            logger.error('Unable to transfer data back from device after 3 attempts: {0}\n'.format(err))
        else:
            logger.info("Done") #Completed file transfer back to server 
             
            # Removing on device log files only if zip
            # file was successfully transferred back to server
            if not fs.rmdir('/var/tmp/data'):
                logger.info("Unable to delete /var/tmp/data on the device. ")
            if not fs.rm(ufname + '.tgz'):
                logger.info("Unable to delete {}.tgz".format(ufname))
             
            # Extract the files into per device folder and remove zip archive
            filename = ufname.split('/')[3] + '.tgz'
            tout = tarfile.open(filename, 'r')
            dfs=filename 
            filename = re.sub('re[0-1][.-]',"",filename)
            #filename=re.sub('-MAINT',"",filename)
            #filename = filename.lower().strip()
            dd = os.path.join(log_dir, filename.split('.')[0])
            os.mkdir(dd)
            tout.extractall(path="./" + dd)
            
            for item in os.listdir(os.path.join(dd, 'var/tmp/data')):
                move(os.path.join(dd, 'var/tmp/data', item), "./"+dd)

            if args.case:
                case_regex = re.compile('20[12]\d\-[01]\d[0-3]\d\-\d{4,4}')
                if case_regex.match(args.case.strip()):
                    if not (args.onedir or args.onefile):
                        paramiko_SSH_exceptions=(paramiko.ssh_exception.SSHException,paramiko.ssh_exception.NoValidConnectionsError,paramiko.ssh_exception.ChannelException)
                        retry(upload_collected_files, attempts=3, sleeptime=10, max_sleeptime=50, \
                            sleepscale=1.5, jitter=0, retry_exceptions=(paramiko_SSH_exceptions), args=(args, dd))
                    else:
                        print("onefile or onedir")
                else:
                    logger.error("Invalid Juniper case number")
            else:
                #if not args.case:
                #    cc = raw_input('Do you want to create a new Juniper ticket (y/n)?')
                #    if cc.lower() == 'y':
                #        if create_case():
                #            args.case = create_case()
                #            logger.info("New Juniper case# %s",args.case)
                #        else:
                #            logger.info("Unable to create new Juniper case#")
                #    else:
                #        logger.info("Files will be saved in the local file system as no Juniper case# specified")
                logger.debug("Skipping uploading of collected logs as Juniper case# not provided")
            
            if not args.case:
                # remove the /var/tmp/data 
                rmtree(os.path.join(dd, 'var'))
            os.remove(dfs)
    finally:
        node.close()

# Assumption is that SSHException: Error reading SSH protocol banner is handled in 
# the retry mechanism - underlying cause is congestion/lack of resources
@retriable(attempts=3, sleeptime=5, max_sleeptime= 20, sleepscale=1.2, jitter=1, retry_exceptions=(ConnectTimeoutError, \
                                    ConnectRefusedError, ConnectClosedError))
def open_connection(node, logger):
    try:
        node.open()
    except ConnectUnknownHostError:
        logger.error("DNS does not resolve")
        raise ConnectUnknownHostError(node)
    except ConnectNotMasterError as err:
        logger.error("Please connect to master RE - {}".format(err))
        raise ConnectNotMasterError(node)
    except ProbeError:
        logger.error("Unable to reach device")
        raise ProbeError(node)

def upload_collected_files(args, dd, location='sftp.juniper.net', port=22):
    # Open sftp connection
    t = paramiko.Transport(location, port)
    t.connect(username = 'anonymous', password = 'anonymous')
    sftp = paramiko.SFTPClient.from_transport(t)
    
    try:
        sftp.chdir('/pub/incoming/' + args.case)  # Test if remote_path exists
    except IOError:
        sftp.mkdir('/pub/incoming/' + args.case)  # Create remote_path
        sftp.chdir('/pub/incoming/' + args.case)
    finally:
        #Upload files individually for JCATS detection
        for item in os.listdir(dd):
            if os.path.isfile(os.path.join(dd, item)):
                if fnmatch.fnmatch(item, '*data*.log'):
                    logging.info("Uploading {} to Juniper SFTP.....".format(item))
                    try:
                        with tarfile.open(item.split('.')[0]+'.tgz', mode='w:gz') as zf:
                            zf.add(os.path.join(dd, item), arcname=item)
                            os.remove(os.path.join(dd, item))
                    except:
                        logging.info("Unable to upload {}".format(item))
                    else:
                        zipitem = item.split('.')[0]+'.tgz' 
                        sftp.put(zipitem, './'+zipitem, confirm=True)
                        os.remove(zipitem)
                        continue
                sftp.put(os.path.join(dd, item), './' + item, confirm=True)              
                #sftp.put('var/tmp/data/' + item, './' + item, confirm=True, callback=printTotals)  
                logging.info("{} upload completed".format(item))
        
        rmtree(dd.split('/')[0])
        sftp.close()

def free_space_avail(node, mount, capacity, logger):
    rsp = node.rpc.get_system_storage()
    for element in rsp.iter('mounted-on'):
        pattern = re.compile(mount)
        if pattern.search(element.text.strip()):
            avail = element.getprevious().getprevious().text
            total = element.getprevious().getprevious().getprevious().getprevious().text
            break
    else:
        logger.info("Unable to verify if disk space available in {}".format(mount))
        return True
    
    if int(avail) < 0:
        return False
     
    if int(avail) < int(total) * capacity/100:
        return False 
    return True

def check_free_space(node, args, logger):
    if node.facts['personality'] == 'SRX_BRANCH':
        path = '/cf/var'
    elif node.facts['personality'] in ('SRX_HIGHEND', 'MX', 'PTX'):
        path = '/var'
    else:
        path = '/var/tmp'
    #TODO: MX seems to have a different FS 15.1+    
    if args.detail:
        cap = 40
    else:
        cap = 25

    if not free_space_avail(node, path, cap, logger):
        logger.error("Less than {}% available in {}....Aborting".format(cap, path))
        return False
    return True

def verify_load(node, logger, load = 2.0):
    for i in range (12):
        rsp = node.rpc.get_route_engine_information()
        for elem in rsp.iter("load-average-one"):
            if float(elem.text) > load:
                logger.info("load-average-one above {}, sleeping for 15 seconds".format(load))
                time.sleep(15)
                break
        else:
            return True
    else:
        logger.error("load-average-one above since the last 3 mins")
        return False

def run_cmd(node, sh, index, element, force, fn, logger):
    if not force:
        # Check system load before each command        
        if not verify_load(node, logger, 1.5):
            logger.error("Aborting due to high system load")
            sys.exit()
     
    logger.info('{:d} {}'.format(index + 1, element))

    got = sh.run_to_file(element, fname = fn, timeout=30) 
        
    #Pacing execution since overriding load check
    if force:
        time.sleep(1)

def become_root(sh,uname,rpwd,logger):
    if rpwd:
        #TODO: Verify check for root user
        if uname == 'root':
            pass
        else:
            sh.run("su", this=':')
            sh.run(rpwd)
            
            if not sh.last_ok:
                logger.error("Incorrect root password. Try again.")
                sys.exit(1)
    else:
        pass
        #logger.info("**** Root password maybe required for certain commands ****")
        #logger.error("Root password mandatory, Try again.")
        #sys.exit(1)

def collect_host_logs(node, sh, logger):
    sh.run("cli -c 'request app-engine host-shell'", this='#')
    if not sh.last_ok:
        logger.error("Could not retrieve host logs")
    else:
        logger.info("Collecting Host Logs")
        sh.run("last -x >> /var/log/last.log", this='#')
        hlog = node.facts['hostname']+'_'+"host-logs"+'@'+datetime.datetime.now().strftime("%y-%m-%d-%H-%M")+".tgz"
        sh.run("tar -cvzf /var/log/" + hlog + " /var/log/*", this='#', timeout=120)
        sh.run("exit")
        sh.run("cli -c 'request app-engine file-copy log from-jhost " + hlog + " to-vjunos /var/tmp/data'", timeout=120)
        sh.run("cli -c 'request app-engine host-shell'", this='#')
        sh.run("rm /var/log/" + hlog, this='#')
        sh.run("exit")

def record_banner(args, node, sh, uname, host, fname):
    sh.run('echo ############################ >> ' + fname)
    opt_dict = {k:v for k, v in vars(args).items() if v}
    opt_str = ''.join('{}:{},'.format(key, val) for key, val in opt_dict.items())
    sh.run('echo # user: ' + uname + '    # >> ' + fname)
    sh.run('echo # hostname: ' + node.facts['hostname'] + '  # >> ' + fname)
    if args.detail:
        sh.run('echo # Detailed Command Set # >> ' + fname)
    #sh.run('echo ' + opt_str + ' >> ' + fname)
    sh.run('echo ############################ >> ' + fname)

"""
def thread_generator(devices,uname,pwd,rpwd,faillock,swlock,hwlock,fail_writer,sw_writer,hw_writer,region_hash,log_dir,th_pool_sem):
    for dev in devices:
        if args.acr:
            try:
                with open('lookup.csv') as f:
                    try:
                        region_hash = {line.split(',')[0]: (line.split(',')[2],line.split(',')[3].strip()) for line in f}
                    except:
                        logger.error("Incorrect file format of lookup.csv")
                        sys.exit(1)
            except IOError:
                logger.error("Unable to find lookup.csv")
                sys.exit(1)
            else:
                t = ExceptionThread(name=dev.strip(), target=getAcrDeviceData, args=(dev,faillock,swlock,hwlock, \
                th_pool_sem,fail_writer,sw_writer,hw_writer,uname,pwd,region_hash))
        else:
            t = ExceptionThread(name=dev.strip(), target=run_cmds, args=(dev,uname,pwd,rpwd.strip(),th_pool_sem,log_dir,faillock,fail_writer))
        yield t
"""
def get_hname(node):
    if node.facts['hostname']:
        t = (('hname', node.facts['hostname']),)
    else:
        t = (('hname', node._hostname),)
    
    return dict((x,y) for x,y in t)


parser = argparse.ArgumentParser(prog='JCOLLECT', formatter_class=argparse.RawTextHelpFormatter, \
        description=textwrap.dedent("""Juniper Data Collection Application 

Example Usage:

Basic command set, RSI & Varlog
/jcollect --host <ip address>

Basic command set, RSI & Varlog plus detailed command set
./jcollect --host <ip address> --detail

Basic and detailed command sets, RSI & Varlog and specified core
./jcollect --host <ip address> --detail --core <proc> 

Basic command set without RSI & Varlog
./jcollect --host <ip address> --norsi

Only RSI & Varlog 
./jcollect --host <ip address> --nocmd

Only core collection
./jcollect --host <ip address> --core <proc> --norsi --nocmd

--host can take multiple white space separated  addresses EX: <ip address> <ip address> ....
Parallel implementation that runs the app across all specified devices simultaneously. 
This is particularly beneficial in scenarios where the "problematic" device is undetermined such as 
multiple devices in a hub site or along affected data path.

./jcollect --ipfile <file path containing single IP/FQDN on each line>
When data needs to be collected from a large number of devices.

--case <xxxx-xxxx-xxxx>
Juniper case# can be provided with any of the above options and if provided, all collected data is uploaded 
to specified Juniper case via SFTP and is available to JTAC almost immediately

./jcollect --ipfile <ip file> --cmdfile <command on each line>
Example cmdfile shown below:
cli
show chassis hardware detail | no-more
shell
jwhoami
df -h
"""))

group = parser.add_mutually_exclusive_group(required=True)
group.add_argument('--host', metavar='IP', nargs='*', help='Target node IP addresses')
group.add_argument('--ipfile', nargs='?', type=argparse.FileType('r'), default=sys.stdin, const=sys.stdin, help='Each line contains single IP address')

cmd_group = parser.add_mutually_exclusive_group()
cmd_group.add_argument('--cmdfile', help='Each line contains single CLI command')
cmd_group.add_argument('--nocmd', action='store_true', default=False, help='Skip running all commands')


parser.add_argument('--detail', action='store_true', default=False, help='Runs comprehensive data collection')
parser.add_argument('--norsi', action='store_true', default=False, help='Skip RSI and /var/log')
parser.add_argument('--core', metavar='<proc name>', dest='core', help='Collect gcore for <proc>')
parser.add_argument('--case', metavar='<case#>', dest='case', help='Juniper case number')
parser.add_argument('--console', dest='console', type=int, nargs='?', const=23, help=argparse.SUPPRESS)
        #help= 'Connect over managment ip or Console Server ip/port')
parser.add_argument('--getfile', metavar='<filename>', dest='file', help='Retrieve specified file from /var')
parser.add_argument('--workers', dest='workers', type=int, default=50, choices=range(50,201,25), help=argparse.SUPPRESS)

parser.add_argument('--onedir', action='store_true', default=False, help='Combines ONLY command output from multiple devices into a single directory')
parser.add_argument('--onefile', action='store_true', default=False, help='Combines ONLY command output from multiple devices into a single file')

parser.add_argument('--flush', action='store_true', default=False, help='Remove stale data collection files if they exist')
parser.add_argument('--version', action='version', version='%(prog)s 1.0')

parser.add_argument('--sm', action='store_true', default=False, help=argparse.SUPPRESS)
parser.add_argument('--smtool', action='store_true', default=False, help=argparse.SUPPRESS)
parser.add_argument('--format', default='text', choices=('text','xml'), help=argparse.SUPPRESS)
parser.add_argument('--acr', action='store_true', default=False, help=argparse.SUPPRESS)
parser.add_argument('--force', action='store_true', default=False, help=argparse.SUPPRESS)
parser.add_argument('--log', metavar='<loglevel>', dest='log', help=argparse.SUPPRESS)
parser.add_argument('--un', metavar='<username>', dest='un', default=None, help=argparse.SUPPRESS)
parser.add_argument('--pd', metavar='<password>', dest='pd', default=None, help=argparse.SUPPRESS)
parser.add_argument('--rpd', metavar='<rpassword>', dest='rpd', default=None, help=argparse.SUPPRESS)
#parser.add_argument('--pr', dest='pr', help=argparse.SUPPRESS)
#parser.add_argument('--vxlan', action='store_true', default=False, help='Execute QFX5100 VXLAN command set')
#parser.add_argument('--jsnap_args', type=str, nargs=argparse.REMAINDER, action='store', help='jsnap arguments', default=None)

#jsnap_group = parser.add_mutually_exclusive_group()
#jsnap_group.add_argument('--snap', action='store_true',help="Take the snapshot for commands specified in test file")
#jsnap_group.add_argument('--check',action='store_true',help="Compare pre & post snapshots based on test operators specified in test file")
#jsnap_group.add_argument("--diff", action="store_true",help="Display difference between two snapshots")
#jsnap_group.add_argument(-snapcheck', action='store_true',help='check current snapshot based on test file')

args, unknown = parser.parse_known_args()
if unknown:
    parser.error("Invalid argument provided {}".format(unknown))
#js = SnapAdmin()
#print js.args
#print {k:v for k, v in vars(js.args).items() if v}



class CustomAdapter(logging.LoggerAdapter):
    """
    This customer adapter expects the passed in dict-like object to have a
    'hname' key, whose value in brackets is prepended to the log message.
    """
    def process(self, msg, kwargs):
        return '[%s] %s' % (self.extra['hname'], msg), kwargs


class ExceptionThread(Thread):  
    """
    Redirect exceptions of thread to an exception handler.  
    """ 
    def __init__(self, group=None, target=None, name=None, args=(), kwargs=None):  
        Thread.__init__(self, group, target, name, args, kwargs)
        if kwargs is None:  
            kwargs = {}
        self._target = target
        self._args = args  
        self._kwargs = kwargs
        self._exc = None  

    def run(self):
        try: 
            if self._target:
                self._target(*self._args, **self._kwargs)
        except BaseException as e:
            self._exc = sys.exc_info()
        except:
            exc_type, exc_value, exc_traceback = sys.exc_info()
            print('{}'.format(repr(traceback.format_exception(exc_type, exc_value, exc_traceback))))
            
            #Avoid a refcycle if the thread is running a function with 
            #an argument that has a member that points to the thread.
            del self._target, self._args, self._kwargs  

    def join(self):  
        Thread.join(self)  
        if self._exc:
            msg = "Thread '%s' threw an exception: %s" % (self.getName(), self._exc[1])
            new_exc = Exception(msg)
            raise new_exc.__class__(new_exc).with_traceback(self._exc[2])
        if self._exc:
            msg = "Thread '%s' threw an exception: %s" % (self.getName(), self._exc[1])
            new_exc = Exception(msg)
            raise new_exc.__class__(new_exc).with_traceback(self._exc[2])

## ExceptionThreadPoolExecutor Implementation ##
_threads_queues = weakref.WeakKeyDictionary()
_shutdown = False

def _python_exit():
    global _shutdown
    _shutdown = True
    items = list(_threads_queues.items())
    for t, q in items:
        q.put(None)
    for t, q in items:
        t.join()

atexit.register(_python_exit)

def _worker(executor_reference, work_queue):
    try:
        while True:
            work_item = work_queue.get(block=True)
            if work_item is not None:
                work_item.run()
                # Delete references to object. See issue16284
                del work_item
                continue
            executor = executor_reference()
            # Exit if:
            #   - The interpreter is shutting down OR
            #   - The executor that owns the worker has been collected OR
            #   - The executor that owns the worker has been shutdown.
            if _shutdown or executor is None or executor._shutdown:
                # Notice other workers
                work_queue.put(None)
                return
            del executor
    except BaseException:
        _base.LOGGER.critical('Exception in worker', exc_info=True)

class ExceptionThreadPoolExecutor(ThreadPoolExecutor):
    def __init__(self, max_workers=None, thread_name_prefix=''):
        """Initializes a new ThreadPoolExecutor instance.

        Args:
        max_workers: The maximum number of threads that can be used to
        execute the given calls.
        thread_name_prefix: An optional name prefix to give our threads.
        """
        if max_workers is None:
            # Use this number because ThreadPoolExecutor is often
            # used to overlap I/O instead of CPU work.
            max_workers = (os.cpu_count() or 1) * 5
        if max_workers <= 0:
            raise ValueError("max_workers must be greater than 0")

        self._max_workers = max_workers
        self._work_queue = queue.Queue()
        self._threads = set()
        self._shutdown = False
        self._shutdown_lock = tLock()
        self._thread_name_prefix = thread_name_prefix

    def _adjust_thread_count(self):
        # When the executor gets lost, the weakref callback will wake up
        # the worker threads.
        def weakref_cb(_, q=self._work_queue):
            q.put(None)
        # TODO(bquinlan): Should avoid creating new threads if there are more
        # idle threads than items in the work queue.
        num_threads = len(self._threads)
        if num_threads < self._max_workers:
            thread_name = '%s_%d' % (self._thread_name_prefix or self,
                            num_threads)
            #t = threading.Thread(name=thread_name, target=_worker,
            #                args=(weakref.ref(self, weakref_cb),
            #                self._work_queue))
            t = ExceptionThread(name=thread_name, target=_worker,
                                args=(weakref.ref(self, weakref_cb),
                                self._work_queue))
            t.daemon = True
            t.start()
            self._threads.add(t)
            _threads_queues[t] = self._work_queue

    def shutdown(self, wait=True):
        with self._shutdown_lock:
            self._shutdown = True
            self._work_queue.put(None)
        if wait:
            for t in self._threads:
                t.join()
    shutdown.__doc__ = _base.Executor.shutdown.__doc__

## Script modified for working through jumpbox. Original class for working with SSH was found somewhere in the Internet, author unknown
class SSHTool():
    def __init__(self, via=None, via_user=None, via_auth=None):
        self.client =paramiko.SSHClient()
        if via:
            self.t0 = paramiko.Transport(via)
            self.t0.start_client()
            self.t0.auth_password(via_user, via_auth)
            self.proxy = via      

    ## Connect to a device
    def connect_via(self, host, user, auth, withkey=True):
        if self.proxy:
            # setup forwarding from 127.0.0.1:<free_random_port> to |host|
            channel = self.t0.open_channel('direct-tcpip', host, ('127.0.0.1', 0))
            self.transport = paramiko.Transport(channel)
        else:
            self.transport = paramiko.Transport(host)
        self.transport.start_client()
        if withkey:
            key = paramiko.pkey.PKey()
            f = open('key.pem','r')     ##===========================================KEY
            s = f.read()
            import StringIO
            keyfile = StringIO.StringIO(s)
            mykey = paramiko.RSAKey.from_private_key(keyfile)
            self.transport.auth_publickey(user,mykey)
        else:
            self.transport.auth_password(user, auth) ##-----------------------Auth via password

    ## This procedure runs single command on the router. No prechecks, no postchecks. 
    ##Risky and unreliable. Use it for show commands only! For everything else use deploy_config()
    def run(self, cmd):
        ch = self.transport.open_session()
        ch.set_combine_stderr(True)
        ch.exec_command(cmd)
        retcode = ch.recv_exit_status()
        buf = ''
        while ch.recv_ready():
            buf += ch.recv(1024).decode("utf-8")
        return (buf, retcode)

    def disconnect(self,param=False):
        self.transport.close()
        if param==False:
            if self.proxy:
                self.t0.transport.close()

