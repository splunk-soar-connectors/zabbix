[comment]: # "Auto-generated SOAR connector documentation"
# Zabbix

Publisher: Splunk Community  
Connector Version: 1\.0\.1  
Product Vendor: Zabbix LLC  
Product Name: Zabbix  
Product Version Supported (regex): "\.\*"  
Minimum Product Version: 5\.4\.0  

Splunk SOAR connector for Zabbix

### Configuration Variables
The below configuration variables are required for this Connector to operate.  These variables are specified when configuring a Zabbix asset in SOAR.

VARIABLE | REQUIRED | TYPE | DESCRIPTION
-------- | -------- | ---- | -----------
**base\_url** |  required  | string | Base URL including the port, e\.g\. http\://zabbix\.mydomain\:8080
**verify\_server\_cert** |  optional  | boolean | Verify server certificate when using https
**username** |  required  | string | Username
**password** |  required  | password | Password
**endpoint** |  required  | string | Endpoint for RPC API calls

### Supported Actions  
[test connectivity](#action-test-connectivity) - Validate the asset configuration for connectivity using supplied configuration  
[get host info](#action-get-host-info) - Get information about an endpoint  
[execute script](#action-execute-script) - Execute a script against an agent  

## action: 'test connectivity'
Validate the asset configuration for connectivity using supplied configuration

Type: **test**  
Read only: **True**

#### Action Parameters
No parameters are required for this action

#### Action Output
No Output  

## action: 'get host info'
Get information about an endpoint

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**host** |  required  | Hostname/IP address or Host ID | string |  `host name`  `ip` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.parameter\.host | string |  `host name`  `ip` 
action\_result\.status | string | 
action\_result\.data\.\*\.host\_info | string | 
action\_result\.message | string | 
action\_result\.summary | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'execute script'
Execute a script against an agent

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**host** |  required  | Host name \(exact\) or host ID | string | 
**script** |  required  | Script name \(exact\) or script ID | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.parameter\.host | string | 
action\_result\.parameter\.script | string | 
action\_result\.status | string | 
action\_result\.data\.\*\.output | string | 
action\_result\.message | string | 
action\_result\.summary | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric | 