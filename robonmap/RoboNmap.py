from libnmap.process import NmapProcess
from libnmap.parser import NmapParser, NmapParserException
from robot.api import logger
from robot.api.deco import keyword


from time import sleep
import datetime

class RoboNmap(object):
    ROBOT_LIBRARY_SCOPE = 'TEST'

    def __init__(self):
        '''
        Nmap Initialize the API
        '''
        self.results = None


    def _call_nmap(self, target, options='', file_export=None):
        '''
        Calls the nmap process with the given options
        Returns the number of hosts that are up
        '''
        target = str(target)
        # IPv6 support
        if ':' in target:
            options += ' -6'
        if file_export:
            options += f' -oN {file_export}'
        # Run the nmap process with the given options
        nmproc = NmapProcess(target, options, safe_mode=not file_export)
        rc = nmproc.run()
        logger.debug(f'Nmap command: {nmproc.command}')
        while nmproc.is_running():
            task = nmproc.current_task
            if task:
                #convert unix timestamp to human readable time
                time = int(task.etc)
                eta = datetime.datetime.fromtimestamp(time).strftime('%H:%M:%S')
                logger.debug(f"Task: {task.name} - Remaining: {task.remaining} - ETA: {eta}")
            sleep(2)
        # Check for errors
        if rc != 0:
            raise Exception(f'EXCEPTION: nmap scan failed: {nmproc.stderr}')
        # Parse the results
        try:
            parsed = NmapParser.parse(nmproc.stdout)
            self.results = parsed
            return len([host for host in self.results.hosts if host.is_up()])
        except NmapParserException as ne:
            print('EXCEPTION: Exception in Parsing results: {0}'.format(ne.msg))
            return -1

    @keyword
    def nmap_default_scan(self, target, file_export = None):
        '''
        Runs a basic nmap scan on nmap's default 1024 ports. Performs the default scan
        - file_export is an optional param that exports the file to a txt file with the -oN flag
        Only stores the results, use `nmap print results` to print the results

        Examples:
        | nmap default scan  | target | file_export |

        '''
        return self._call_nmap(target, '', file_export)


    @keyword
    def nmap_custom_scan(self, target, options, file_export = None):
        '''
        Runs a custom nmap scan with the given options. Options are passed as a string.
        Omit the `-6` flag, this is automatically added if the target is an IPv6 address.
        - file_export is an optional param that exports the file to a txt file with the -oN flag
        Only stores the results, use `nmap print results` to print the results

        Examples:
        | nmap custom scan  | target | options | file_export |
        '''
        return self._call_nmap(target, options, file_export)


    @keyword
    def nmap_specific_tcp_scan(self, target, portlist, file_export = None):
        '''
        Runs nmap scan against all TCP Ports without version scanning. Options used -Pn -p <portlist>
        - file_export is an optional param that exports the file to a txt file with the -oN flag
        Only stores the results, use `nmap print results` to print the results

        Examples:
        | nmap tcp scan | target | portlist <default: 1-65535>  |  [file_export] |
        '''
        if portlist:
            options = f'-p {portlist}'
        else:
            options = '-p1-65535 '
        return self._call_nmap(target, options, file_export)


    @keyword
    def nmap_all_tcp_scan(self, target, file_export = None):
        '''
        Runs nmap scan against all TCP Ports without version scanning. Options used -Pn -p1-65535
        - file_export is an optional param that exports the file to a txt file with the -oN flag
        Only stores the results, use `nmap print results` to print the results

        Examples:
        | nmap all tcp scan | target | [file_export] |
        '''
        return self._call_nmap(target, '-p1-65535', file_export)


    @keyword
    def nmap_specific_udp_scan(self, target, portlist, file_export = None):
        '''
        Runs nmap against specified UDP ports given in the portlist argument. Options used -sU -p <portlist>
        ! REQUIRES ROOT PRIVILEGES !
        Arguments:
            - ``target``: IP or the range of IPs that need to be tested
            - ``portlist``: list of ports, range of ports that need to be tested. They can either be comma separated or separated by hyphen
            example: 121,161,240 or 1-100. Default: 1-1024
            - ``file_export``: is an optional param that exports the file to a txt file with the -oN flag
        Only stores the results, use `nmap print results` to print the results

        Examples:
        | nmap specific udp scan  | target | portlist | file_export |
        '''
        options = f'-sU'
        if portlist:
            options += f' -p {portlist}'
        return self._call_nmap(target, options, file_export)


    @keyword
    def nmap_os_services_scan(self, target, portlist=None, version_intense = 7, file_export = None, udp = None):
        '''
        Runs an nmap scan with OS detection and service detection. Options used are: -Pn -sV --version-intensity <default:7> -p <portlist>
        Arguments:
            - ``target``: IP or the range of IPs that need to be tested
            - ``portlist``: list of ports, range of ports that need to be tested. They can either be comma separated or separated by hyphen
            example: 121,161,240 or 1-100
            - ``version_intense``: Version intensity of OS detection, `nmap` default is 7
            - ``file_export``: is an optional param that exports the file to a txt file with the -oN flag
            - ``udp``: optional param that also scans UDP. REQUIRES ROOT PRIVILEGES!
        Only stores the results, use `nmap print results` to print the results
        Examples:
        | nmap os services scan  | target | portlist | version_intense | file_export |
        '''
        options = f'-Pn -sV'
        if version_intense:
            options += f' --version-intensity {version_intense}'
        if portlist:
            options += f' -p {portlist}'
        if udp:
            options += f' -sT -sU'
        return self._call_nmap(target, options, file_export)

    @keyword
    def nmap_script_scan(self, target, portlist=None, version_intense=7, script_name=None, file_export = None):
        '''
        Runs nmap with the -sC arg or the --script arg if script_name is provided. Options used are: -sV --version-intensity <default:0> -sC|--script=<script_name>
        Arguments:
            - ``target``: IP or the range of IPs that need to be tested
            - ``portlist``: list of ports, range of ports that need to be tested. They can either be comma separated or separated by hyphen
            example: 121,161,240 or 1-100
            - ``version_intense``: Version intensity of OS detection
            - ``script_name``: Script Name that needs to be referenced
            - ``file_export``: is an optional param that exports the file to a txt file with the -oN flag
        Only stores the results, use `nmap print results` to print the results
        Examples:
        | nmap script scan  | target | portlist | version_intense | script_name |
        '''
        options = f'-Pn -sV '
        if version_intense:
            options += f' --version-intensity {version_intense}'

        # TODO: further rework
        if portlist and script_name:
            options += f' --script={script_name} -p {portlist}'
        elif portlist and not script_name:
            options += f' -sC -p {portlist}'
        elif script_name and not portlist:
            raise Exception('EXCEPTION: If you use specific script, you have to specify a port')
        else:
            options += f' -sC'
        return self._call_nmap(target, options, file_export)


    @keyword
    def nmap_print_results(self):
        '''
        Retrieves the results of the most recent results and prints them to the log
        Examples:
        | nmap print results |
        '''
        for scanned_hosts in self.results.hosts:
            logger.info(scanned_hosts)
            logger.info("  PORT     STATE         SERVICE")
            for serv in scanned_hosts.services:
                pserv = "{0:>5s}/{1:3s}  {2:12s}  {3}".format(
                    str(serv.port),
                    serv.protocol,
                    serv.state,
                    serv.service)
                if len(serv.banner):
                    pserv += " ({0})".format(serv.banner)
                logger.info(pserv)
                if serv.scripts_results:
                    for output in serv.scripts_results:
                        logger.info("\t Output: {0}, Elements: {1}, ID: {2}".format(output['output'], output['elements'], output['id']))


    @keyword
    def nmap_get_structured_results(self):
        '''
        Retrieves the results of the most recent results and prints them to the log in a structured format
        Returns:
        A dictionary containing the results of the scan
            - endtime: The time when the scan ended
            - hosts_up: The number of hosts that are up
            - hosts: A list of dictionaries containing the results of each host
                - address: The IP address of the host
                - status: The status of the host (up or down)
                - closed_ports: A list of ports that are closed
                - [services]: An [optional] list of dictionaries containing the results of each service
                    - port: The port number
                    - protocol: The protocol used by the service
                    - state: The state of the port (open or closed)
                    - service: The name of the service
                    - [banner]: The [optional] banner returned by the service
                    - [scripts_results]: An [optional] list of dictionaries containing the results of each script
                        - output: The output of the script
                        - elements: The elements returned by the script
                        - id: The ID of the script
        Examples:
        | nmap get structured results |
        '''
        results = {"endtime": datetime.datetime.fromtimestamp(int(self.results.endtime)).isoformat() if self.results.endtime else None,
                   "hosts_up": self.results.hosts_up,
                   "hosts": []
                   }
        for scanned_hosts in self.results.hosts:
            logger.debug(scanned_hosts)
            host_result = { "address": scanned_hosts.address,
                            "status": scanned_hosts.status,
                            "closed_ports": scanned_hosts.extraports_reasons,
                            "services": [] if scanned_hosts.services else None
                            }
            for serv in scanned_hosts.services:
                logger.debug(serv)
                service_result = {"port": serv.port,
                                  "protocol": serv.protocol,
                                  "state": serv.state,
                                  "service": serv.service
                                  }
                if serv.banner:
                    service_result["banner"] = serv.banner
                if serv.scripts_results:
                    service_result["scripts_results"] = serv.scripts_results

                host_result["services"].append(service_result)

            results["hosts"].append(host_result)
        logger.debug(results)
        return results

    @keyword
    def nmap_search_for_service(self, service_name):
        '''
        Searches for a service in the results
        Arguments:
            - ``service_name``: Name of the service that needs to be searched
        Returns:
            - List of tuples containing the IP and the port where the service is, or None if not found
        Examples:
        | nmap search for service | service_name |
        '''
        service_name = str(service_name).lower().strip()
        services = []
        for scanned_host in self.results.hosts:
            logger.info(scanned_host)
            for serv in scanned_host.services:
                if serv.open() and serv.service == service_name:
                    logger.info(f"Service {service_name} found on {scanned_host.address}, port {serv.port}")
                    services.append((scanned_host.address,serv.port))
        return services if services else None
    
if __name__ == '__main__':
    nmap = RoboNmap()
    nmap.nmap_os_services_scan("localhost", portlist="22-23", version_intense=7)
    nmap.nmap_print_results()
    nmap.nmap_get_structured_results()