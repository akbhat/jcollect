#!/usr/bin/python
# Author: akbhat@juniper.net
# Version 1.0  20150803 

from jnpr_cmds import *
from jutil import *

def run_cmds(node, logger, uname, rpwd):
    cmd_set_shell_Q = {"EX4300"     : ex4300_cmds_shell_Q,
                       "QFX5100"    : qfx5100_cmds_shell_Q,
                       "QFX5100_VXLAN":qfx5100_vxlan_cmds_shell_Q}
		       #"QFX10002"   : qfx10002_cmds_shell_Q}
                       #"SRX_BRANCH" : srx_cmds_shell_Q,
                       #"SRX_HIGHEND": srx_cmds_shell_Q,
                       #"MX"         : mx_cmds_shell_Q}

    cmd_set_shell_D = {"EX4300"     : ex4300_cmds_shell_D,
                       "QFX5100"    : qfx5100_cmds_shell_D,
                       "QFX5100_VXLAN":qfx5100_vxlan_cmds_shell_D}
		       #"QFX10002"   : qfx10002_cmds_shell_D}
                       #"SRX_BRANCH" : srx_cmds_shell_D,
                       #"SRX_HIGHEND": srx_cmds_shell_D,
                       #"MX"         : mx_cmds_shell_D}
    
    # TODO: Check if user belongs to either ENG_CLASS or ADMIN_CLASS. User CLASS stored locally?

    #Check free space on filesystem for logging 
    if not check_free_space(node, args, logger):
        sys.exit(1)
    
    fs = FS(node)
    try:
        res = fs.mkdir('/var/tmp/data')
    except:
        logger.error('Could not create directory on device: %s', sys.exc_info()[0])
        sys.exit(1)
    
    if not args.nocmd:
        logfile = "/var/tmp/data/data_collection@" + datetime.datetime.now().strftime("%y-%m-%d-%H-%M") + ".log" 
        fs.mkfile(logfile)        
        if args.cmdfile:
            if args.detail:
                logger.info("--detail ignored as --cmdfile specified")
            try:
                with open(args.cmdfile, 'r') as cmdfile, StartShell(node) as sh:
                    record_banner(args, node, sh, uname, node.facts['hostname'],logfile)                    
                    become_root(sh, uname, rpwd,logger)
                    cmd_type = ''
                    for index, comd in enumerate(cmdfile):
                        if comd.strip() == 'cli':
                            cmd_type = 'cli'
                            continue 
                        elif comd.strip() == 'shell':
                            cmd_type = 'shell'
                            continue
                        elif comd.strip() == 'vty':
                            cmd_type = 'vty'
                            continue
                        else:
                            if cmd_type == 'cli':
                                element = "cli -c '" + comd.strip() + "'"
                            elif cmd_type == 'shell':
                                element = comd.strip()
                            elif cmd_type == 'vty':
                                element = "cprod -A fpc0 -c '" + comd.strip() + "'"
                            run_cmd(node, sh, index , element, logger, args.force, logfile)
                cmdfile.close()
            except IOError as e:
                logger.error('Operation failed: %s', e.strerror)
                sys.exit(1)
            except:
                logger.error('Unexpected error: %s', sys.exc_info()[0])
                sys.exit(1)
        else:
            # TODO: Verify SRX cluster
            person_platform = {'MX', 'SRX_BRANCH', 'SRX_HIGHEND'}
            if node.facts['personality'] in person_platform:
                cmd_set = node.facts['personality']
            elif node.facts['model'] == 'Virtual Chassis':
                rsp = node.rpc.get_chassis_inventory()
                for element in rsp.iter('name'):
                    if element.text == 'FPC 0':
                        for elem in element.getparent().getchildren():
                            if elem.tag == 'model-number': 
                                cmd_set = elem.text.split('-')[0]
            else:
                cmd_set = node.facts['model'].split('-')[0]
            
            with StartShell(node) as sh:
                record_banner(args, node, sh, uname, node.facts['hostname'], logfile)
                become_root(sh, uname, rpwd, logger)
                
                if cmd_set in ('QFX5100', 'QFX5100_VXLAN', 'QFX10002'):
                    try:
                        collect_host_logs(node, sh, logger) 
                    except:
                        logger.error("Could not retrieve host logs")

                try:
                    for index, element in enumerate(cmd_set_shell_Q[cmd_set]):
                        run_cmd(node, sh, index, element, logger, args.force, logfile)
                    
                    if args.vxlan:
                        if cmd_set == 'QFX5100':
                            cmd_set = 'QFX5100_VXLAN'
                            for index, element in enumerate(cmd_set_shell_Q[cmd_set]):
                                run_cmd(node, sh, index, element, logger, args.force, logfile)
                        else:
                            logger.error("VXLAN data collection supported only for QFX5100")
                except KeyError:
                    logger.error('Unsupported platform')
                    sys.exit(1)

                if args.detail:
                    logger.info('######################################################')
                    logger.info("Sleeping for 30 seconds before initiating detailed command set on {}".format(node.facts['hostname']))
                    logger.info('######################################################')               
                    time.sleep(30)
                    
                    logger.info('######################################################')
                    logger.info('Executing detailed command set on...{}'.format(node.facts['hostname']))
                    logger.info('######################################################')
  
                    for index, element in enumerate(cmd_set_shell_D[cmd_set]):
                        run_cmd(node, sh, index, element, logger, args.force, logfile)
                        #time.sleep(2)

    # Collect requested cores     
    if args.core and verify_load(node, logger, 0.75):
        #TODO: No need of 100M for smaller platforms. %age of /var/tmp?
        if not free_space_avail(node, '/var/tmp', 100):
            logging.error("Less than 100M available in /var/tmp")                
        else:
            logger.info('Collecting {} core on {}....'.format(args.core, node.facts['hostname']))
            if args.core=='live':
                with StartShell(node) as sh:
                    become_root(sh, uname, rpwd, logger)

                    #Remove all exisiting live cores
                    #TODO: Can accidentally delete useful kernel core
                    rt = fs.stat('/var/tmp/vmcore.*')
                    while rt is not None:
                        logger.info("Removing %s", rt['path'])
                        sh.run("rm " + rt['path'])
                        rt = fs.stat('/var/tmp/vmcore.*')

                    logging.debug('Dumping live core')
                    # Dump the live core 
                    sh.run("cli -c 'request system live-core'")
                    tm = 0
                    # Loop until stat is successful for new vmcore file
                    while fs.stat('/var/tmp/vmcore.*') is None:
                        # Break from loop if core not available after 5 mins
                        if tm >= 300:
                            logger.info("Skipping live core after waiting 5 mins")
                            break
                        logger.info('Waiting 15 seconds while live core is generated')
                        tm += 15
                        time.sleep(15)
                    logger.debug('Moving live core to /var/tmp/data')
                    sh.run("mv /var/tmp/vmcore.* /var/tmp/data/")
            else:
                with StartShell(node) as sh:               
                    result = sh.run("ps -auxw | grep -w " + args.core.strip() + " | grep /usr/sbin | awk '{print $2}' >> /var/tmp/data/pids.log")
                    pids = fs.cat('/var/tmp/data/pids.log').splitlines()
                    if pids:
                        become_root(sh, uname, rpwd, logger)                        
                        # In case multiple pids returned
                        for index, pd in enumerate(pids):
                            if pd:        
                                filename = "/var/tmp/data/" + args.core.strip() + ".gcore." + str(index)
                                element = "gcore -c " + filename + ' ' + pd.strip()
                                sh.run(element)
                                
                                # Gzip generated core file to save disk space
                                sh.run("gzip " + filename)
                                logging.info("Core collection completed on {}".format(node.facts['hostname']))
                        fs.rm('/var/tmp/data/pids.log')
                    else:
                        logging.error("Invalid process")
    else:
        logging.error("Skipping gcore")

    # Archive RSI & /var/log
    if not args.norsi and verify_load(node, logger, 1.5):       
        logger.info("Collecting {} RSI.....".format(node.facts['hostname']))
        with StartShell(node) as sh:        
            become_root(sh, uname, rpwd, logger)
            sh.run("cli -c 'request support information | no-more | save /var/tmp/data/" + node.facts['hostname'] + '_' + \
                    datetime.datetime.now().strftime("%y-%m-%d-%H-%M") + "_rsi.log'")
        logging.info("RSI Completed")
  
        logger.info("Archiving {} /var/log.....".format(node.facts['hostname']))
        msglog = fs.tgz('/var/log', '/var/tmp/data/varlog_' + node.facts['hostname'] + '_' + datetime.datetime.now().strftime("%y-%m-%d-%H-%M"))
        logging.info("/var/log Completed")
    else:
        logging.info("Skipping RSI and /var/log")

    # Zipping collected data 
    ufname = '/var/tmp/' + node.facts['hostname'] + '_' + datetime.datetime.now().strftime("%y-%m-%d-%H-%M")
    msglog = fs.tgz('/var/tmp/data', ufname)

    logger.info("Transferring {} back to server....".format(ufname.split('/')[3] + '.tgz'))
    with SCP(node) as scp:
        scp.get(remote_path= ufname + '.tgz', local_path='./', preserve_times=True)
    logging.info("Done")
    
    # Removing on device log files
    fs.rmdir('/var/tmp/data')
    fs.rm(ufname + '.tgz')
    node.close()
   
    # Transfer collected data to Juniper FTP
    if args.case:
        t = paramiko.Transport(('sftp.juniper.net', 22))
        t.connect(username = 'anonymous', password = 'anonymous')
        sftp = paramiko.SFTPClient.from_transport(t)
        try:
            sftp.chdir('/pub/incoming/' + args.case)  # Test if remote_path exists
        except IOError:
            sftp.mkdir('/pub/incoming/' + args.case)  # Create remote_path
            sftp.chdir('/pub/incoming/' + args.case)
        
        filename = ufname.split('/')[3] + '.tgz'
        logging.info("Uploading {} to Juniper SFTP.....".format(filename))
        
        #Upload files individually for JCATS detection
        tout = tarfile.open(filename, 'r')
        tout.extractall()
        for item in os.listdir('var/tmp/data'):
            sftp.put('var/tmp/data/' + item, './' + item)  
        rmtree('var')       
        logging.info("File upload completed")
        sftp.close()
    else:
        logging.info("Unable to upload log files to Juniper FTP as case# not provided")

def main():
    logging.getLogger("paramiko").setLevel(logging.WARNING)
    logging.getLogger("ncclient").setLevel(logging.WARNING)

    logger = logging.getLogger('JCOLLECT')
    logger.propagate = False
    formatter = '%(message)s'

    if args.log:
        numeric_level = getattr(logging, args.log.upper(), None)
        if not isinstance(numeric_level, int):
            raise ValueError('Invalid log level: %s' % args.log)
        logging.basicConfig(format=formatter, level=numeric_level)
    else:
        logging.basicConfig(format=formatter, level=logging.INFO)
        #Supress traceback    
        #sys.tracebacklimit = 0
    
    console = logging.StreamHandler()
    console.setLevel (logging.INFO)
    logger.addHandler(console)

    #os.system ('eval "$(register-python-argcomplete jcollect.py)"')
    
    jobs = []
    if args.ipfile != sys.stdin:
        devices = args.ipfile
    elif args.host:
        devices = list(set(args.host))
    else:
        logger.error("argument --host or --ipfile required")
        sys.exit(1)

    uname = raw_input("Username: ") 
    pwd = getpass.getpass()
    rpwd = getpass.getpass(prompt="Root Password:")

    for dev in devices:
        try:
            node = Device (host = dev.strip(), user = uname.strip(), passwd = pwd.strip())
            node.open(auto_probe = True)
            node.timeout = 60
        except Exception as err:                               
            sys.stderr.write('Cannot connect to device: {0}\n'.format(err))
        
        if node.connected:    
            #TODO: If cluster or VC, append to devices 
            t = Thread(target=run_cmds, args=(node,logger,uname,rpwd.strip()))
            jobs.append(t)
        
    for j in jobs:
        j.start()
            
    for j in jobs:
        j.join()

if __name__ == "__main__":
    main()
