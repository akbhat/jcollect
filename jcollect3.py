############################################################################################
#Copyright 2017 Juniper Networks, Inc. All rights reserved.
#Licensed under the Juniper Networks Script Software License (the "License"). 
#You may not use this script file except in compliance with the License, which is located at 
#http://www.juniper.net/support/legal/scriptlicense/
#Unless required by applicable law or otherwise agreed to in writing by the parties,
#software distributed under the License is distributed on an "AS IS" BASIS,
#WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
############################################################################################

#!/usr/bin/python
# Author: akbhat@juniper.net
# Version 1.0  20170803 

from jutil3 import *

# Globals
fail_wr = None
sw_wr = None
hw_wr = None
faillock=Lock()
swlock=Lock()
hwlock=Lock()
sw_handle = None
hw_handle = None
fail_handle = None
locks=(faillock,swlock,hwlock)
fpc_re=re.compile(r'^FPC (\d*)$')
pic_re=re.compile(r'^PIC (\d*)$')
xvr_re=re.compile(r'^Xcvr (\d*)$')
comp_re=(fpc_re,pic_re,xvr_re)
region_hash={}
l_dir=None

def smtools_output(node):
    node = Device (host = node.strip(), user = user.strip(), passwd = passwd.strip(), normalize=True, port=22)
    
    logger = logging.LoggerAdapter(logging.getLogger("jcollect"), get_hname(node))
    
    faillock,swlock,hwlock=locks

    try:
        open_connection(node, logger)
    except Exception as err:
        logger.error('Cannot connect to device: {0}\n'.format(err))
    else:
        logger.debug("Connection opened successfully")
    finally:
        if not node.connected:
            update_device_failed(node, faillock, fail_handle)
            return
    
    logger = logging.LoggerAdapter(logging.getLogger("jcollect"), get_hname(node))
    
    try:
        if not node.facts['hostname']:
            raise NameError
         
        #if not args.sm:
        if args.format=='xml':
            hw_op=node.rpc.get_chassis_inventory()
            sw_op=node.rpc.get_software_information()
        else:
            hw_op=node.cli("show chassis hardware detail", warning=False)
            sw_op=node.cli("show version detail | match RPD", warning=False)
        """
        else:
            logger.info("Parsing cmdfile")
            if not args.cmdfile:
                logger.error("Please specify cmdfile")
                sys.exit(1)

            if not os.path.isfile(args.cmdfile):
                logger.error('Unable to find cmdfile: {}'.format(args.cmdfile))
                sys.exit(1)
            
            with open(args.cmdfile, 'r') as cmdfile, StartShell(node) as sh:
                logger.debug("Reading command file for execution")
                for index, comd in enumerate(cmdfile):
                    ret, op = sh.run("cli -c '" + comd.strip() + "'", timeout=45)
                    logger.info("Return status {}".format(ret))
                    if ret:
                        logger.info(comd)
                        swlock.acquire()
                        sw_handle.write(user+"@"+node.facts['hostname']+"> ")
                        sw_handle.write(op+"\n")
                        sw_handle.flush()
                        swlock.release()
         """
    except NameError:
        logger.error('Unable to retrieve device hostname')
        update_device_failed(node, faillock, fail_handle)
    except Exception as err:
        logger.error('Unable to retrieve inventory information: {0}\n'.format(err))
        update_device_failed(node, faillock, fail_handle)
    else:
        #if not args.sm:
        if args.format == 'xml':
            hwlock.acquire()
            hw_handle.write(user+"@"+node.facts['hostname']+"> " + "show chassis hardware detail | display xml | no-more\n")
            hw_handle.write(etree.tostring(hw_op, pretty_print=True, encoding='unicode'))
            hw_handle.write("\n\n")
            hwlock.release()
            swlock.acquire()
            sw_handle.write(user+"@"+node.facts['hostname']+"> " + "show version | display xml | no-more\n")
            sw_handle.write(etree.tostring(sw_op, pretty_print=True, encoding='unicode'))
            sw_handle.write("\n\n")
            swlock.release()
        else:
            hwlock.acquire()
            hw_handle.write(user+"@"+node.facts['hostname']+"> " + "show chassis hardware detail | no-more\n")
            hw_handle.write(hw_op+"\n\n")
            hwlock.release()
            swlock.acquire()
            sw_handle.write(user+"@"+node.facts['hostname']+"> " + "show version detail | no-more\n")
            sw_handle.write(sw_op+"\n\n")
            swlock.release()
        sw_handle.flush()
        hw_handle.flush()
        logger.info("Completed")

#@func_exception_decorator(None)
def run_cmds(dev):
    if args.console:
        node = Device(host=dev.strip(), user = uname.strip(), passwd = pwd.strip(), mode='telnet', port=args.console)
    else:
        node = Device (host = dev.strip(), user = uname.strip(), passwd = pwd.strip(), normalize=True, port=22)
    
    logger = logging.LoggerAdapter(logging.getLogger("jcollect"), get_hname(node))
    
    #ssht = SSHTool(via=jumpbox, via_user=user_jumpbox, via_auth=passwd_jumpbox)
    #ssht.connect_via(router, user_router, str(passwd_router), withkey=False)

    try:
        if args.sm:
            node = ConnectHandler(device_type='juniper',ip=dev,username=uname.strip(),password=pwd.strip())
            #node.send_command("set system services netconf ssh")
            #node.disconnect()
        else:
            open_connection(node, logger)
            node.timeout = 120
    except Exception as err:                               
        logger.error('Cannot connect to device: {0}\n'.format(err))
    finally:
        if not node.connected:
            update_device_failed(node, faillock, fail_handle)
            return

    logger = logging.LoggerAdapter(logging.getLogger("jcollect"), get_hname(node))
    
    #Global VC variable
    vc = '' 
     
    #Return if VC checks fail
    vc, status = vc_check(node, vc, logger)
    if not status:
        return
    
    with StartShell(node) as sh:
        if args.nocmd and args.norsi and not args.core:
            pass
        else:
            #Exit if not enough disk space on filesystem for data collection 
            if not check_free_space(node, args, logger):
                sys.exit(1)
        
        #Flush all stale data collection
        if args.flush:
            sh.run("rm -rf /var/tmp/data")
         
        # Handle for file system operations
        fs = FS(node)
        cmd_set = select_cmd_set(node, vc, logger) 
        logger.debug("Command set selected is {}".format(cmd_set))
        
        sh.run("mkdir -p /var/tmp/data")
        
        become_root(sh, uname, rpwd, logger)
        
        # Find specified file and retrieve
        if args.file:
            got = sh.run("find /var -iname '{}'".format(args.file))
            ret_list = [s.strip() for s in got[1].splitlines()]
            if ret_list[-2]:
                fs.cp(ret_list[-2], '/var/tmp/data')
            else:
                logger.error("Unable to find {}".format(args.file))

        if not args.nocmd:
            logfile = "/var/tmp/data/"+node.facts['hostname']+'_'+"data_collection@" + datetime.datetime.now().strftime("%y-%m-%d-%H-%M") + ".log" 
            
            record_banner(args, node, sh, uname, node.facts['hostname'], logfile)
            
            if args.cmdfile:
                parse_and_run_cmdfile(node, sh, args, uname, rpwd, logfile, logger)
            else:
                try:
                    execute_cmd_list(node, sh, args.force, logfile, cmd_set_shell_Q[cmd_set], logger)
                except KeyError:
                    logger.error('Unsupported platform')
                    sys.exit(1)

                if args.detail and verify_load(node, 1.0):
                    logger.info('######################################################')
                    logger.info('Executing detailed command set...')
                    logger.info('######################################################')

                    execute_cmd_list(node, sh, args.force, logfile, cmd_set_shell_D[cmd_set], logger)
        
        # Archive RSI & /var/log
        archive_rsi_varlog(node, cmd_set, sh, fs, args, uname, rpwd, logger)

        # Collect requested core     
        if args.core and verify_load(node, 0.75):
            if not free_space_avail(node, '/var/tmp', 40, logger):
                logger.error("Skipping gcore as less than 40% available in /var/tmp")                
            else:
                collect_gcore(node, sh, fs, args, uname, rpwd, logger)
        else:
            logger.debug("Skipping gcore")
         
        # Zip, retrieve and upload collected data 
        retrieve_and_upload_collected_data(node, sh, fs, l_dir, logger)

def acr_init(sw_writer,hw_writer,lks,swfh,hwfh,failfh,compile_re,uname,pwd,r_hash):
    global fail_wr, sw_wr, hw_wr
    global locks, comp_re, user, passwd, region_hash
    global fail_handle, sw_handle, hw_handle 
    sw_wr,hw_wr = sw_writer,hw_writer
    locks=lks 
    sw_handle=swfh
    hw_handle=hwfh
    fail_handle=failfh
    comp_re=compile_re
    user=uname
    passwd=pwd
    region_hash=r_hash

def collect_init(flock,failfh,user,passwd,rpasswd,log_dir):
    global locks, uname, pwd, rpwd
    global fail_handle, l_dir
    faillock=flock
    fail_handle=failfh
    uname=user
    pwd=passwd
    rpwd=rpasswd
    l_dir=log_dir

def sm_init(lks,swfh,hwfh,failfh,uname,pwd):
    global fail_wr, sw_wr 
    global locks, user, passwd
    global fail_handle, sw_handle, hw_handle
    locks=lks
    sw_handle=swfh
    hw_handle=hwfh 
    fail_handle=failfh
    user=uname
    passwd=pwd

def update_acr_sw_inventory(devObj, region_hash, logger):
    swrow = {}
    hn=re.sub('re[0-1][.-]',"",devObj.facts['hostname'])
    
    for i in range(5):
        if hn:
            hn=re.sub('-MAINT',"",hn)
            hn = hn.lower().strip()
        else:
            devObj.facts_refresh(keys='hostname')
            hn=re.sub('re[0-1][.-]',"",devObj.facts['hostname'])
            continue
        swrow['Device_Name']=hn
        swrow['Platform']=devObj.facts['model']
        swrow['Version']=devObj.facts['version']
        if swrow['Device_Name']:
            break
    else:
        logger.error("Unable to retrieve hostname")
        return swrow, False

    logger.debug("Looking up hostname {}".format(hn))
    
    try:
        swrow['Region']=region_hash[hn][0]
        swrow['Area']=region_hash[hn][1]
    except KeyError:
        swrow['Region']=""
        swrow['Area']=""
        logger.error("{} missing in the hostname to region mapping file".format(hn))

    return swrow, True

def create_acr_output_files(log_dir):
    #Write out SW and HW data to separate CSV files 
    swfname = log_dir + "/software.csv"
    hwfname = log_dir + "/hardware.csv"
     
    #with open(swfname, 'w+') as swfh, open(hwfname, 'w+') as hwfh:
    swfh = open(swfname, 'w+')
    hwfh = open(hwfname, 'w+')
    
    sw_header = 'Device_Name,ipaddr,Platform,Version,Region,Area'.split(',')
    hw_header = 'device,ipaddr,chassis_name,fpc,pic,xcvr,name,version,part_num,serial_num,model_num,description'.split(',')

    hw_writer = csv.DictWriter(hwfh, fieldnames=hw_header)
    hw_header_dict = {}
    for n in hw_header:
        hw_header_dict[n] = n
    hw_writer.writerow(hw_header_dict)
    hwfh.flush()

    sw_writer = csv.DictWriter(swfh, fieldnames=sw_header)
    sw_header_dict = {}
    for n in sw_header:
        sw_header_dict[n] = n
    sw_writer.writerow(sw_header_dict)
    swfh.flush() 
    return sw_writer, swfh, hw_writer, hwfh

def update_device_failed(devObj, faillock, fail_writer):
    if isinstance(devObj, str):
        dev=devObj
    else:
        if devObj.hostname:
            dev=devObj.hostname
        else:
            dev=devObj._hostname
    faillock.acquire()
    fail_writer.write(dev)
    fail_writer.write("\n")
    fail_writer.flush()
    faillock.release()

def getAcrDeviceData(device):
    '''
    log into an individual device and get SW and HW information
    '''
    swrow={}
    devObj = Device (host = device, user = user.strip(), passwd = passwd.strip(), port=22, normalize=True)
     
    logger = logging.LoggerAdapter(logging.getLogger("jcollect"), get_hname(devObj))
     
    faillock,swlock,hwlock=locks
     
    try:
        open_connection(devObj, logger)
    except Exception as err:
        logger.error('Cannot connect to device: {0}\n'.format(err))
    finally:
        if not devObj.connected:
            update_device_failed(devObj,faillock,fail_handle)
            return False

    logger = logging.LoggerAdapter(logging.getLogger("jcollect"), get_hname(devObj))
     
    # Retrieve SW inventory
    swrow, status = update_acr_sw_inventory(devObj, region_hash, logger)
    swrow['ipaddr']=device
    if not status:
        update_device_failed(devObj,faillock,fail_writer) 
        return False
    
    # Retrieve HW inventory 
    try:
        rpc = "<get-chassis-inventory></get-chassis-inventory>"
        result = devObj.execute(rpc)
    except Exception as e:
        logger.error("Could not execute RPC on %s: %s".format(device['device'], str(e)))
        update_device_failed(devObj,faillock,fail_handle)
        return False
    else:
        logger.debug("Successfully retrieved get-chassis-inventory")
    
    #Hostname cleanup
    hn=re.sub('re[0-1][.-]',"",devObj.facts['hostname'])
    for i in range(5):
        if hn:
            hn=re.sub('-MAINT',"",hn)
            hn = hn.lower().strip()
        else:
            devObj.facts_refresh(keys='hostname')
            hn=re.sub('re[0-1][.-]',"",devObj.facts['hostname'])
            continue
    
    rows = []
    def generateRow(tree):
        row = { 'model-number': '', \
                'name': '',\
                'fpc': '', \
                'pic': '', \
                'ipaddr': device, \
                'serial-number': '', \
                'xcvr': '', \
                'version': '', \
                'device': devObj.facts['hostname'], \
                'chassis_name': '',\
                'part-number': '',\
                'description': ''}

        for key in list(row.keys()):
            match = tree.find(key)
            if match is not None:
                row[key] = match.text
        return row
    
    fpc_re,pic_re,xvr_re=comp_re
    for chassis in result.xpath('//chassis'):
        row = generateRow(chassis)
        rows.append(row)

        for module in chassis.xpath('./chassis-module'):
            #for element in module.iter("name", "version"):
            #    print("%s - %s" % (element.tag, element.text))
            #Module row
            row = generateRow(module)
            match = fpc_re.search(row['name'])
            #match = re.match( r'^FPC (\d*)$', row['name'] )
            fpc = ''
            if match:
                fpc = match.group(1)
                row['fpc'] = fpc
            rows.append(row)

            for submodule in module.xpath('./chassis-sub-module'):
                #Submodule row
                row = generateRow(submodule)
                #match = re.match( r'^PIC (\d*)$', row['name'] )
                match = pic_re.search(row['name'])
                pic = ''
                if match:
                    pic = match.group(1)
                    row['fpc'] = fpc
                    row['pic'] = pic
                rows.append(row)

                for subsubmodule in submodule.xpath('./chassis-sub-sub-module'):
                    row = generateRow(subsubmodule)
                    xcvr = ''
                    #match = re.match( r'^Xcvr (\d*)$', row['name'] )
                    match = xvr_re.search(row['name'])
                    if match:
                        xcvr = match.group(1)
                        row['fpc'] = fpc
                        row['pic'] = pic
                        row['xcvr'] = xcvr
                    rows.append(row)
    
    convertKeys = {'model-number'  : 'model_num',
                   'serial-number' : 'serial_num',
                   'part-number'   : 'part_num'}

    for row in rows:
        for (deviceKey, acrKey) in list(convertKeys.items()):
            if deviceKey in list(row.keys()):
                row[acrKey] = row[deviceKey]
                del(row[deviceKey])
    
    #Write SW and HW invetory together to avoid duplicates
    swlock.acquire()
    logger.debug("Writing {}".format(swrow))
    sw_wr.writerow(swrow)
    sw_handle.flush()
    swlock.release()

    hwlock.acquire()
    hw_wr.writerows(rows)
    hw_handle.flush()
    hwlock.release()
     
    devObj.close()
    
    logger.info("Completed")

    return True

def task_done(future):
    iterator = future.result()

    while True:
        try:
            result = next(iterator)
        except StopIteration:
            break
        except TimeoutError as error:
            logging.error("Function took longer than {} seconds".format(error.args[1]))
            #update_device_failed(devObj,faillock,fail_wr)
        except ProcessExpired as error:
            logging.error("{}. Exit code: {}".format(error, error.exitcode))
        except Exception as e:
            logging.error("{}".format(str(e)))
            logging.exception("Exception!")

def main():
    logging.getLogger("paramiko").setLevel(logging.WARNING)
    logging.getLogger("ncclient").setLevel(logging.WARNING)
    
    logger = logging.getLogger("jcollect")
    logger.propagate = False
    ch = logging.StreamHandler()

    if args.log:
        numeric_level = getattr(logging, args.log.upper(), None)
        if not isinstance(numeric_level, int):
            raise ValueError('Invalid log level: %s' % args.log)
        logging.basicConfig(format='[%(asctime)s %(levelname)s] %(message)s', datefmt='%m/%d/%Y %I:%M:%S %p', level=numeric_level)
        ch.setLevel(numeric_level)
    else:
        logging.basicConfig(format='[%(asctime)s %(levelname)s] %(message)s', datefmt='%m/%d/%Y %I:%M:%S %p', level=logging.INFO)
        ch.setLevel(logging.INFO)
        #Supress traceback    
        #sys.tracebacklimit = 0
    
    formatter = logging.Formatter('[%(asctime)s %(levelname)s %(hname)s] %(message)s', datefmt='%m/%d/%Y %I:%M:%S %p')
    ch.setFormatter(formatter)
    logger.addHandler(ch)
    
    # Add syslog handler
    #sh = logging.SysLogHandler(address=(‘localhost’, SYSLOG_UDP_PORT), facility=LOG_USER, socktype=socket.SOCK_DGRAM)
    
    logging.debug({k:v for k, v in vars(args).items() if v})

    if args.nocmd and args.norsi and not args.core:
        if not args.file:
            parser.error("No action requested")
        else:
            pass #find and fetch file
    
    if args.onefile or args.onedir:
        logging.info("Ignoring all other data collection options except commands")
        args.norsi = True
        args.core = None
        args.file = False
    
    # Parse specified devices and remove duplicates
    if args.ipfile != sys.stdin:
        devices = [d.strip() for d in args.ipfile if d.strip()]
        devices = list(set(devices))
    elif args.host:
        devices = list(set(args.host))

    if args.un:
        uname=args.un
        pwd=args.pd
        rpwd=args.rpd
    else:
        uname = input("Username: ") 
        pwd = getpass.getpass()
        rpwd = getpass.getpass(prompt="Root Password:")
    
    if not rpwd:
        logging.info("**** Root password not provided. Commands requiring root access will be unsuccessful ****")

    # Local logging directory
    if args.acr:
        log_dir = "acr_dump@" + datetime.datetime.now().strftime("%m-%d-%Y-%H-%M")
    elif args.smtool:
        log_dir = "smtool_dump@" + datetime.datetime.now().strftime("%m-%d-%Y-%H-%M")
    else:
        log_dir = "data_collection@" + datetime.datetime.now().strftime("%m-%d-%Y-%H-%M") 
     
    #TODO: Handle failure to create dir
    if not os.path.exists(log_dir):
        os.makedirs(log_dir)
    
    #Lock and writer for unreachable devices
    faillock = Lock()
    failfname = log_dir + "/unreachable.csv"
    failfh = open(failfname, 'w+')
    
    future=None
    if args.acr or args.smtool:
        if not args.ipfile:
            sys.exit("Please specify input device IP file via --ipfile")
        else:
            swlock = Lock()
            hwlock = Lock()
            lks=(faillock,swlock,hwlock)
            
            if args.acr:
                region_hash={}
                sw_writer, swfh, hw_writer, hwfh = create_acr_output_files(log_dir)

                fpc_re=re.compile(r'^FPC (\d*)$')
                pic_re=re.compile(r'^PIC (\d*)$')
                xvr_re=re.compile(r'^Xcvr (\d*)$')
                compile_re=(fpc_re,pic_re,xvr_re)
                 
                try:
                    with open('lookup.csv') as f:
                        try:
                            r_hash = {line.split(',')[0].strip(): (line.split(',')[2].strip(),line.split(',')[3].strip()) for line in f}
                        except:
                            logging.error("Incorrect file format of lookup.csv")
                            sys.exit(1)
                except IOError:
                    logging.error("Unable to find lookup.csv")
                    sys.exit(1)
                else:
                    with ProcessPool(max_workers=args.workers, initializer=acr_init, \
                            initargs=(sw_writer,hw_writer,lks,swfh,hwfh,failfh,compile_re,uname,pwd,r_hash)) as p:
                        
                        future = p.map(getAcrDeviceData, devices, timeout=120)
                        #future.add_done_callback(task_done)
            elif args.smtool:
                sw_fname = log_dir + "/smtool_sw.txt"
                hw_fname = log_dir + "/smtool_hw.txt"
                swfh = open(sw_fname, 'w+')
                hwfh = open(hw_fname, 'w+')
                with ProcessPool(max_workers=args.workers, initializer=sm_init, \
                                   initargs=(lks,swfh,hwfh,failfh,uname,pwd)) as p:
                    future = p.map(smtools_output, devices, timeout=120)
    else:
        with ProcessPool(max_workers=args.workers, initializer=collect_init, \
                           initargs=(faillock,failfh,uname,pwd,rpwd,log_dir)) as p:
            future = p.map(run_cmds, devices, timeout=900)
    
    # Main iterator
    iterator = future.result()
    index = 0 
    while True:
        try:
            result = next(iterator)
        except StopIteration:
            break
        except TimeoutError as error:
            logging.error("{} took longer than {} seconds".format(devices[index], error.args[1]))
            update_device_failed(devices[index],faillock,failfh)
        except ProcessExpired as error:
            if error.exitcode != 1:
                logging.error("{}. Exit code: {}".format(error, error.exitcode))
            update_device_failed(devices[index],faillock,failfh)
        except Exception as e:
            logging.error("{}".format(str(e)))
            logging.exception("Exception!")
            update_device_failed(devices[index],faillock,failfh)
        finally:
            index += 1
    
    failfh.close()  
    if args.smtool:
        swfh.close()
        if args.acr:
            hwfh.close()
    
    # To combine output to onedir or further to onefile
    if args.onedir or args.onefile:
        for root, dirs, files in os.walk(log_dir, topdown=True):
            for filename in fnmatch.filter(files, '*data*.log'):
                move(os.path.join(root, filename), log_dir)
                rmtree(root)
         
        outfilename = log_dir + "/combined_data_" + datetime.datetime.now().strftime("%m-%d-%Y-%H-%M") + ".log" 
        if args.onefile:
            with open(outfilename, 'w') as outfile:
                for item in os.listdir(log_dir):
                    if item == outfilename.split('/')[1].strip() or item == 'unreachable.csv':
                        # don't want to copy the output into the output
                        continue
                    with open(os.path.join(log_dir,item), 'r') as readfile:
                        copyfileobj(readfile, outfile)
                    os.remove(os.path.join(log_dir,item))
    
    # To upload all collected files to specified case 
    if args.case:
        paramiko_SSH_exceptions=(paramiko.ssh_exception.SSHException,paramiko.ssh_exception.NoValidConnectionsError,paramiko.ssh_exception.ChannelException)

        retry(upload_collected_files, attempts=3, sleeptime=10, max_sleeptime=50, \
                     sleepscale=1.5, jitter=0, retry_exceptions=(paramiko_SSH_exceptions), args=(args, log_dir))
        
if __name__ == "__main__":
    #cProfile.run('main()')
    main()

    #asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())

    #loop = asyncio.get_event_loop()
    #loop.set_debug(True)
    #loop.run_until_complete(main())
