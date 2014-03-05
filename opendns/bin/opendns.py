'''
OpenDNS Modular Input Script

Nicholas Nam

'''

import sys, logging, os, time, re, datetime
import xml.dom.minidom, xml.sax.saxutils

SPLUNK_HOME = os.environ.get('SPLUNK_HOME')

RESPONSE_HANDLER_INSTANCE = None
SPLUNK_PORT = 8089
STANZA = None
SESSION_TOKEN = None
REGEX_PATTERN = None

EGG_DIR = SPLUNK_HOME + '/etc/apps/opendns_ta/bin/'

for filename in os.listdir(EGG_DIR):
    if filename.endswith('.egg'):
        sys.path.append(EGG_DIR + filename)

import requests, json
from splunklib.client import connect
from splunklib.client import Service

#set up logging
logging.root
logging.root.setLevel(logging.ERROR)
formatter = logging.Formatter("%(levelname)s %(message)s")
#with zero args , should go to STD ERR
handler = logging.StreamHandler()
handler.setFormatter(formatter)
logging.root.addHandler(handler)

SCHEME = '''<scheme>
    <title>OpenDNS</title>
    <description>Poll data from the OpenDNS REST API</description>
    <use_external_validation>true</use_external_validation>
    <streaming_mode>xml</streaming_mode>
    <use_single_instance>false</use_single_instance>

    <endpoint>
        <args>
            <arg name='name'>
                <title>OpenDNS REST API endpoint name</title>
                <description>Name of this OpenDNS REST API endpoint</description>
            </arg>

            <arg name='opendns_api_endpoint_base_url'>
                <title>OpenDNS REST API Base URL</title>
                <description>OpenDNS REST API Base URL</description>
                <required_on_edit>true</required_on_edit>
                <required_on_create>true</required_on_create>
            </arg>

            <arg name='opendns_organization_id'>
                <title>OpenDNS Organization ID</title>
                <description>OpenDNS Organization ID</description>
                <required_on_edit>true</required_on_edit>
                <required_on_create>true</required_on_create>
            </arg>

            <arg name='opendns_api_endpoint_path'>
                <title>OpenDNS REST API Endpoint Path</title>
                <description>OpenDNS REST API Endpoint Path</description>
                <required_on_edit>true</required_on_edit>
                <required_on_create>true</required_on_create>
            </arg>

            <arg name='opendns_api_key'>
                <title>OpenDNS API Key</title>
                <description>OpenDNS API Key</description>
                <required_on_edit>true</required_on_edit>
                <required_on_create>true</required_on_create>
            </arg>

            <arg name='opendns_auth_token'>
                <title>OpenDNS Authentication Token</title>
                <description>OpenDNS Authentication Token</description>
                <required_on_edit>true</required_on_edit>
                <required_on_create>true</required_on_create>
            </arg>

            <arg name='http_header_properties'>
                <title>HTTP Header Properties</title>
                <description>Custom HTTP header properties: key=value, key2=value2</description>
                <required_on_edit>false</required_on_edit>
                <required_on_create>false</required_on_create>
            </arg>

            <arg name='url_args'>
                <title>URL Arguments</title>
                <description>Custom URL arguments: key=value, key2=value2</description>
                <required_on_edit>false</required_on_edit>
                <required_on_create>false</required_on_create>
            </arg>

            <arg name='streaming_request'>
                <title>Streaming Request</title>
                <description>Whether or not this is an HTTP streaming request: true | false</description>
                <required_on_edit>false</required_on_edit>
                <required_on_create>false</required_on_create>
            </arg>

            <arg name='http_proxy'>
                <title>HTTP Proxy Address</title>
                <description>HTTP Proxy Address</description>
                <required_on_edit>false</required_on_edit>
                <required_on_create>false</required_on_create>
            </arg>

            <arg name='https_proxy'>
                <title>HTTPS Proxy Address</title>
                <description>HTTPS Proxy Address</description>
                <required_on_edit>false</required_on_edit>
                <required_on_create>false</required_on_create>
            </arg>

            <arg name='request_timeout'>
                <title>Request Timeout</title>
                <description>Request timeout in seconds</description>
                <required_on_edit>false</required_on_edit>
                <required_on_create>false</required_on_create>
            </arg>

            <arg name='backoff_time'>
                <title>Backoff Time</title>
                <description>Time in seconds to wait for retry after error or timeout</description>
                <required_on_edit>false</required_on_edit>
                <required_on_create>false</required_on_create>
            </arg>

            <arg name='polling_interval'>
                <title>Polling Interval</title>
                <description>Interval time in seconds to poll the endpoint</description>
                <required_on_edit>false</required_on_edit>
                <required_on_create>false</required_on_create>
            </arg>

            <arg name='delimiter'>
                <title>Delimiter</title>
                <description>Delimiter to use for any multi 'key=value' field inputs</description>
                <required_on_edit>false</required_on_edit>
                <required_on_create>false</required_on_create>
            </arg>

            <arg name='index_error_response_codes'>
                <title>Index Error Responses</title>
                <description>Whether or not to index error response codes: true | false</description>
                <required_on_edit>false</required_on_edit>
                <required_on_create>false</required_on_create>
            </arg>

            <arg name='response_handler'>
                <title>Response Handler</title>
                <description>Python classname of custom response handler</description>
                <required_on_edit>false</required_on_edit>
                <required_on_create>false</required_on_create>
            </arg>

            <arg name='response_handler_args'>
                <title>Response Handler Arguments</title>
                <description>Response handler arguments string: key=value, key2=value2</description>
                <required_on_edit>false</required_on_edit>
                <required_on_create>false</required_on_create>
            </arg>

            <arg name='response_filter_pattern'>
                <title>Response Filter Pattern</title>
                <description>Python regex pattern to filter resonses before indexing</description>
                <required_on_edit>false</required_on_edit>
                <required_on_create>false</required_on_create>
            </arg>
        </args>
    </endpoint>
</scheme>
'''

def do_validate():
    config = get_validation_config()

def do_run():
    config = get_input_config()

    #setup some globals
    server_uri = config.get('server_uri')
    global SPLUNK_PORT
    global STANZA
    global SESSION_TOKEN
    SPLUNK_PORT = server_uri[18:]
    STANZA = config.get('name')
    SESSION_TOKEN = config.get('session_key')

    #params

    endpoint=config.get('opendns_api_endpoint_base_url')+'/'+config.get('opendns_organization_id')+'/'+config.get('opendns_api_endpoint_path')

    http_method='GET'

    #none | basic | digest | oauth1 | oauth2
    auth_type='none'

    #Delimiter to use for any multi 'key=value' field inputs
    delimiter=config.get('delimiter',',')


    http_header_properties={}
    http_header_properties_str=config.get('http_header_properties')

    if not http_header_properties_str is None:
        http_header_properties = dict((k.strip(), v.strip()) for k, v in
              (item.split('=') for item in http_header_properties_str.split(delimiter)))


    url_args = {}
    url_args['offset'] = 0
    url_args['limit'] = 500
    url_args['api-key'] = config.get('opendns_api_key')
    url_args['token'] = config.get('opendns_auth_token')
    url_args_str = config.get('url_args')

    if not url_args_str is None:
        add_url_args = dict((k.strip(), v.strip()) for k, v in
              (item.split('=') for item in url_args_str.split(delimiter)))
        url_args.update(add_url_args)

    response_type = 'json'

    streaming_request = int(config.get('streaming_request', 0))

    http_proxy = config.get('http_proxy')
    https_proxy = config.get('https_proxy')

    proxies = {}

    if not http_proxy is None:
        proxies['http'] = http_proxy
    if not https_proxy is None:
        proxies['https'] = https_proxy


    request_timeout = int(config.get('request_timeout', 30))
    backoff_time = int(config.get('backoff_time', 10))
    polling_interval = int(config.get('polling_interval', 60))
    index_error_response_codes = int(config.get('index_error_response_codes', 0))
    response_filter_pattern = config.get('response_filter_pattern')

    if response_filter_pattern:
        global REGEX_PATTERN
        REGEX_PATTERN = re.compile(response_filter_pattern)

    response_handler_args = {}
    response_handler_args_str = config.get('response_handler_args')
    if not response_handler_args_str is None:
        response_handler_args = dict((k.strip(), v.strip()) for k, v in
              (item.split('=') for item in response_handler_args_str.split(delimiter)))

    response_handler = config.get('response_handler', 'DefaultResponseHandler')
    module = __import__('responsehandlers')
    class_ = getattr(module, response_handler)

    global RESPONSE_HANDLER_INSTANCE
    RESPONSE_HANDLER_INSTANCE = class_(**response_handler_args)

    req_args = {'verify' : False ,'stream' : bool(streaming_request) , 'timeout' : float(request_timeout)}


    try:

        if url_args:
            req_args['params'] = url_args
        if http_header_properties:
            req_args['headers'] = http_header_properties
        if proxies:
            req_args['proxies'] = proxies

        while True:

            if 'params' in req_args:
                end_time = datetime.datetime.utcnow()
                start_time = end_time - datetime.timedelta(0, polling_interval)
                req_args['params']['filters'] = '{"start": %d,  "end": %d}' % (unix_time(start_time), unix_time(end_time))
                req_args_params_current = dictParameterToStringFormat(req_args['params'])
            else:
                req_args_params_current = ''
            if 'headers' in req_args:
                req_args_headers_current = dictParameterToStringFormat(req_args['headers'])
            else:
                req_args_headers_current = ''


            try:
                r = requests.get(endpoint, **req_args)

            except requests.exceptions.Timeout,e:
                logging.error("HTTP Request Timeout error: %s" % str(e))
                time.sleep(float(backoff_time))
                continue
            except Exception as e:
                logging.error("Exception performing request: %s" % str(e))
                time.sleep(float(backoff_time))
                continue
            try:
                r.raise_for_status()
                if streaming_request:
                    for line in r.iter_lines():
                        if line:
                            handle_output(r, line, response_type, req_args, endpoint)
                else:
                    handle_output(r, r.text, response_type, req_args, endpoint)
            except requests.exceptions.HTTPError,e:
                error_output = r.text
                error_http_code = r.status_code
                if index_error_response_codes:
                    error_event = ''
                    error_event += "http_error_code = %s error_message = %s" % (error_http_code, error_output)
                    print_xml_single_instance_mode(error_event)
                    sys.stdout.flush()
                logging.error("HTTP Request error: %s" % str(e))
                time.sleep(float(backoff_time))
                continue

            if 'params' in req_args:
                checkParamUpdated(req_args_params_current,dictParameterToStringFormat(req_args['params']), 'url_args')
            if 'headers' in req_args:
                checkParamUpdated(req_args_headers_current,dictParameterToStringFormat(req_args['headers']), 'http_header_properties')

            time.sleep(float(polling_interval))

    except RuntimeError, e:
        logging.error("Looks like an error: %s" % str(e))
        sys.exit(2)

def checkParamUpdated(cached, current, rest_name):

    if not cached == current:
        try:
            args = {'host': 'localhost', 'port': SPLUNK_PORT, 'token': SESSION_TOKEN}
            service = Service(**args)
            item = service.inputs.__getitem__(STANZA[11:])
            item.update(**{rest_name: current})
        except RuntimeError, e:
            logging.error("Looks like an error updating the modular input parameter %s: %s" % (rest_name, str(e)))


def dictParameterToStringFormat(parameter):

    if parameter:
        return ''.join('{}={},'.format(k, v) for k, v in parameter.items())[:-1]
    else:
        return None


def handle_output(response, output, type, req_args, endpoint):

    try:
        if REGEX_PATTERN:
            search_result = REGEX_PATTERN.search(output)
            if search_result == None:
                return
        RESPONSE_HANDLER_INSTANCE(response, output, type, req_args, endpoint)
        sys.stdout.flush()
    except RuntimeError, e:
        logging.error("Looks like an error handle the response output: %s" % str(e))

# prints validation error data to be consumed by Splunk
def print_validation_error(s):
    print "<error><message>%s</message></error>" % encodeXMLText(s)

# prints XML stream
def print_xml_single_instance_mode(s):
    print "<stream><event><data>%s</data></event></stream>" % encodeXMLText(s)

# prints simple stream
def print_simple(s):
    print "%s\n" % s

def encodeXMLText(text):
    text = text.replace('&', '&amp;')
    text = text.replace('"', '&quot;')
    text = text.replace("'", '&apos;')
    text = text.replace('<', '&lt;')
    text = text.replace('>', '&gt;')
    return text

def usage():
    print "usage: %s [--scheme|--validate-arguments]"
    logging.error('Incorrect Program Usage')
    sys.exit(2)

def do_scheme():
    print SCHEME

#read XML configuration passed from splunkd, need to refactor to support single instance mode
def get_input_config():
    config = {}

    try:
        # read everything from stdin
        config_str = sys.stdin.read()

        # parse the config XML
        doc = xml.dom.minidom.parseString(config_str)
        root = doc.documentElement

        session_key_node = root.getElementsByTagName('session_key')[0]
        if session_key_node and session_key_node.firstChild and session_key_node.firstChild.nodeType == session_key_node.firstChild.TEXT_NODE:
            data = session_key_node.firstChild.data
            config['session_key'] = data

        server_uri_node = root.getElementsByTagName('server_uri')[0]
        if server_uri_node and server_uri_node.firstChild and server_uri_node.firstChild.nodeType == server_uri_node.firstChild.TEXT_NODE:
            data = server_uri_node.firstChild.data
            config['server_uri'] = data

        conf_node = root.getElementsByTagName('configuration')[0]
        if conf_node:
            logging.debug('XML: found configuration')
            stanza = conf_node.getElementsByTagName('stanza')[0]
            if stanza:
                stanza_name = stanza.getAttribute('name')
                if stanza_name:
                    logging.debug('XML: found stanza ' + stanza_name)
                    config['name'] = stanza_name

                    params = stanza.getElementsByTagName('param')
                    for param in params:
                        param_name = param.getAttribute('name')
                        logging.debug("XML: found param '%s'" % param_name)
                        if param_name and param.firstChild and \
                           param.firstChild.nodeType == param.firstChild.TEXT_NODE:
                            data = param.firstChild.data
                            config[param_name] = data
                            logging.debug("XML: '%s' -> '%s'" % (param_name, data))

        checkpnt_node = root.getElementsByTagName('checkpoint_dir')[0]
        if checkpnt_node and checkpnt_node.firstChild and \
           checkpnt_node.firstChild.nodeType == checkpnt_node.firstChild.TEXT_NODE:
            config['checkpoint_dir'] = checkpnt_node.firstChild.data

        if not config:
            raise Exception, 'Invalid configuration received from Splunk.'


    except Exception, e:
        raise Exception, "Error getting Splunk configuration via STDIN: %s" % str(e)

    return config

#read XML configuration passed from splunkd, need to refactor to support single instance mode
def get_validation_config():
    val_data = {}

    # read everything from stdin
    val_str = sys.stdin.read()

    # parse the validation XML
    doc = xml.dom.minidom.parseString(val_str)
    root = doc.documentElement

    logging.debug('XML: found items')
    item_node = root.getElementsByTagName('item')[0]
    if item_node:
        logging.debug('XML: found item')

        name = item_node.getAttribute('name')
        val_data['stanza'] = name

        params_node = item_node.getElementsByTagName('param')
        for param in params_node:
            name = param.getAttribute('name')
            logging.debug("Found param %s" % name)
            if name and param.firstChild and \
               param.firstChild.nodeType == param.firstChild.TEXT_NODE:
                val_data[name] = param.firstChild.data

    return val_data

def unix_time(dt):
    epoch = datetime.datetime.utcfromtimestamp(0)
    delta = dt - epoch
    return int(delta.total_seconds())

if __name__ == '__main__':

    if len(sys.argv) > 1:
        if sys.argv[1] == '--scheme':
            do_scheme()
        elif sys.argv[1] == '--validate-arguments':
            do_validate()
        else:
            usage()
    else:
        do_run()

    sys.exit(0)
