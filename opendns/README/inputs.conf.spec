[opendns://<name>]

* OpenDNS REST API Endpoint Base URL
opendns_api_endpoint_base_url = <value>

* OpenDNS API Key
opendns_api_key= <value>

* OpenDNS Authentication Token
opendns_auth_token = <value>

* OpenDNS REST API Endpoint Path
opendns_api_endpoint_path = <value>

* OpenDNS Organization ID
opendns_organization_id = <value>

* prop =value, prop2 =value2
http_header_properties = <value>

* arg =value, arg2 =value2
url_args = <value>

* true | false
streaming_request = <value>

* ie: (http://10.10.1.10:3128 or http://user:pass@10.10.1.10:3128 or https://10.10.1.10:1080 etc...)
http_proxy = <value>
https_proxy = <value>

*in seconds
request_timeout = <value>

* time to wait for reconnect after timeout or error
backoff_time  = <value>

*in seconds
polling_interval = <value>

* whether or not to index http error response codes
index_error_response_codes = <value>

* Python classname of custom response handler
response_handler = <value>

* Response Handler arguments string:  key=value, key2=value2
response_handler_args = <value>

* Python regex pattern to filter resonses before indexing
response_filter_pattern  = <value>

* Delimiter to use for any multi "key=value" field inputs
delimiter = <value>





