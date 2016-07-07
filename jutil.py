import argparse, argcomplete, sys, datetime, time, ftplib, tarfile, os, logging, getpass, paramiko, pdb  
from shutil import rmtree
from threading import Thread
from jnpr.junos.device import Device
from jnpr.junos.utils.start_shell import StartShell
from jnpr.junos.utils.fs import FS
from jnpr.junos.utils.scp import SCP

#logging.getLogger("paramiko").setLevel(logging.CRITICAL)

def free_space_avail(node, mount, capacity):
    rsp = node.rpc.get_system_storage()
    for element in rsp.iter('mounted-on'):
        if element.text.strip() == mount:
            avail = element.getprevious().getprevious().text
            total = element.getprevious().getprevious().getprevious().getprevious().text
            break
    else:
        print "Unable to verify if disk space available in /var/tmp"
        return True
    
    if int(avail) < 0:
        return False
    
    if int(avail) < int(total) * capacity/100:
        return False 
    return True

def check_free_space(node, args, logger):
    if node.facts['personality'] == 'SRX_BRANCH':
        path = '/cf/var'
    elif node.facts['personality'] == 'SRX_HIGHEND':
        path = '/var'
    else:
        path = '/var/tmp'
        
    if args.detail:
        cap = 40
    else:
        cap = 25

    if not free_space_avail(node, path, cap):
        logger.error("{}: Less than {}% available in {}....Aborting".format(node.facts['hostname'], cap, path))
        return False
    return True

def verify_load(node, logger, load = 2.0):
    for i in range (12):
        rsp = node.rpc.get_route_engine_information()
        for elem in rsp.iter("load-average-one"):
            if float(elem.text) > load:
                print "{} load-average-one above {}, sleeping for 15 seconds".format(node.facts['hostname'], load)
                time.sleep(15)
                break
        else:
            return True
    else:
        logger.error("load-average-one above since the last 3 mins")
        return False

def run_cmd(node, sh, index, element, logger, force, fn):
    if not force:
        # Check system load before each command        
        if not verify_load(node, logger, 1.5):
            logger.error("Aborting due to high system load")
            sys.exit()
    
    print node.facts['hostname'], index + 1, element
    got = sh.run_to_file(element, fname = fn) 
    #Pacing execution since overriding load check
    if force:
        time.sleep(1)
    ok = sh.last_ok

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
        logger.error("Root password mandatory, Try again.")
        sys.exit(1)

def collect_host_logs(node, sh ,logger):
    sh.run("cli -c 'request app-engine host-shell'", this='#')
    if not sh.last_ok:
        logger.error("Could not retrieve host logs")
        sys.exit(1)
    print "Collecting Host Logs from {}".format(node.facts['hostname'])
    sh.run("last -x >> /var/log/last.log", this='#')
    sh.run("tar -cvzf /var/log/host-logs.tgz /var/log/*", this='#')
    sh.run("exit")
    sh.run("cli -c 'request app-engine file-copy log from-jhost host-logs.tgz to-vjunos /var/tmp/data'")
    sh.run("cli -c 'request app-engine host-shell'", this='#')
    sh.run("rm /var/log/host-logs.tgz", this='#')
    sh.run("exit")

def record_banner(args, node, sh, uname, host, fname):
    sh.run('echo ############################ >> ' + fname)
    sh.run('echo # user: ' + uname + '    # >> ' + fname)
    sh.run('echo # hostname: ' + node.facts['hostname'] + '  # >> ' + fname)
    if args.detail:
        sh.run('echo # Detailed Command Set # >> ' + fname)
    sh.run('echo ############################ >> ' + fname)


parser = argparse.ArgumentParser(prog='JCOLLECT', description='Juniper Data Collection Script')
argcomplete.autocomplete(parser)
group = parser.add_mutually_exclusive_group()
group.add_argument('--host', metavar='<IP add>', nargs='*', help='Target node IP address (required)')
group.add_argument('--ipfile', nargs='?', type=argparse.FileType('r'), default=sys.stdin, const=sys.stdin, help='Each line contains single IP address')

parser.add_argument('--version', action='version', version='%(prog)s 0.997')
parser.add_argument('--cmdfile', help='Each line contains single CLI command')
parser.add_argument('--core', metavar='<proc name>', dest='core', help='Collect gcore for <proc>')
parser.add_argument('--detail', action='store_true', default=False, help='Runs comprehensive data collection')
parser.add_argument('--norsi', action='store_true', default=False, help='Skip RSI and /var/log')
parser.add_argument('--vxlan', action='store_true', default=False, help='Execute QFX5100 VXLAN command set')
parser.add_argument('--nocmd', action='store_true', default=False, help='Skip running all commands')
parser.add_argument('--case', metavar='<case#>', dest='case', help='Juniper case number')
parser.add_argument('--force', action='store_true', default=False, help=argparse.SUPPRESS)
parser.add_argument('--log', metavar='<loglevel>', dest='log', help=argparse.SUPPRESS)
args = parser.parse_args()
