'''
Copywright 2014 Nicholas Nam. All rights reserved.
Use of this source code is governed by the GPLv3
license that can be found in the LICENSE file.
'''

# add your custom response handler class to this module
import json
import datetime
# the default handler , does nothing , just passes the raw output directly to STDOUT
class DefaultResponseHandler:

    def __init__(self,**args):
        pass

    def __call__(self, response_object,raw_response_output,response_type,req_args,endpoint):
        print_xml_stream(raw_response_output)


class OpenDNSErrorsEventHandler:

    def __init__(self,**args):
        pass

    def __call__(self, response_object,raw_response_output,response_type,req_args,endpoint):
        if response_type == "json":
            output = json.loads(raw_response_output)

            # perform any custom processing of the JSON response
            for line in output:
                print_xml_stream(json.dumps(line))

        else:
            print_xml_stream(raw_response_output)

class OpenDNSHandler:

    def __init__(self,**args):
        pass

    def __call__(self, response_object,raw_response_output,response_type,req_args,endpoint):
        if response_type == "json":
            output = json.loads(raw_response_output)

            # perform any custom processing of the JSON response
            for line in output:
                print_xml_stream(json.dumps(line))
        else:
            print_xml_stream(raw_response_output)

# prints XML stream
def print_xml_stream(s):
    print '<stream><event unbroken="1"><data>%s</data><done/></event></stream>' % encodeXMLText(s)

def encodeXMLText(text):
    text = text.replace('&', '&amp;')
    text = text.replace('"', '&quot;')
    text = text.replace("'", '&apos;')
    text = text.replace('<', '&lt;')
    text = text.replace('>', '&gt;')
    text = text.replace("\n", '')
    return text
