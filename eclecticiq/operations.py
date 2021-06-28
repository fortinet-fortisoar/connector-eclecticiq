from .EclecticIQ import eiq_api

from connectors.core.connector import get_logger, ConnectorError

logger = get_logger('eclecticiq')


def get_config_data(config):
    eiq_url = config.get('eiq_url').strip('/')
    if eiq_url[:7] == 'http://' and eiq_url[:8] != 'https://':
        eiq_url = 'https://{0}'.format(str(eiq_url.replace('http://', '')))
    eiq_user = config.get('eiq_user', None)
    eiq_password = config.get('eiq_password', None)
    verify_ssl = config.get('verify_ssl', None)
    return eiq_url, eiq_user, eiq_password, verify_ssl


def eiq_init(config):
    eiq_url, eiq_user, eiq_password, verify_ssl = get_config_data(config)
    try:
        eiq = eiq_api.EclecticIQ_api(baseurl=eiq_url, eiq_version="2.7", username=eiq_user, password=eiq_password,
                                     verify_ssl=verify_ssl)
        return eiq
    except Exception as e:
        logger.exception("Exception to connect: {}".format(e))
        raise ConnectorError(e)


def get_observable_reputation(config, operation_name, params):
    observable_type_dict = {'get_ip_reputation': 'ipv4',
                            'get_domain_reputation': 'domain',
                            'get_email_reputation': 'email',
                            'get_file_reputation': 'file,hash-md5,hash-sha1,hash-sha256,hash-sha512',
                            'get_uri_reputation': 'uri'}

    observable_value = params.get('observable')
    observable_type = observable_type_dict.get(str(operation_name))

    try:
        eiq = eiq_init(config)
        lookup_result = eiq.lookup_observable(observable_value, observable_type)

        if isinstance(lookup_result, dict):
            parsed_response = {
                'last_updated': lookup_result.get('last_updated'),
                'maliciousness': lookup_result.get('maliciousness'),
                'value': lookup_result.get('value'),
                'platform_link': lookup_result.get('platform_link'),
                'source_name': lookup_result.get('source_name'),
                'created': lookup_result.get('created')
            }
            return {"result": parsed_response, "count": 1, "status": "success"}

        else:
            parsed_response = {}
            return {"result": parsed_response, "count": 0, "status": "success"}

    except Exception as e:
        logger.exception("Error: {0}".format(e))
        raise ConnectorError("Error: {0}".format(e))


def prepare_observables(param):
    valid_ops = {
        "Domain": "domain",
        "Email": "email",
        "Email Subject": "email-subject",
        "File": "file",
        "Hash": "hash",
        "Hash MD5": "hash-md5",
        "Hash SHA1": "hash-sha1",
        "Hash SHA256": "hash-sha256",
        "Hash SHA512": "hash-sha512",
        "Host": "host",
        "IPv4": "ipv4",
        "IPv6": "ipv6",
        "Mutex": "mutex",
        "Port": "port",
        "Process": "process",
        "URI": "uri",
        "URI Hash SHA256": "uri-hash-sha256",
        "Win Registry": "winregistry"
    }

    observable_params = [
        (
            param['observable_maliciousness'],
            valid_ops.get(param['observable_type']),
            param['observable_value'],
        )
    ]
    observables_list = []

    maliciousness_to_meta = {
        "Malicious (High confidence)": {
            "classification": "bad",
            "confidence": "high",
        },
        "Malicious (Medium confidence)": {
            "classification": "bad",
            "confidence": "medium",
        },
        "Malicious (Low confidence)": {
            "classification": "bad",
            "confidence": "low",
        },
        "Safe": {
            "classification": "good",
        },
        "Unknown": {
        },
    }

    for observable in observable_params:
        record = dict(
            observable_type=observable[1],
            observable_value=observable[2])

        record["observable_maliciousness"] = maliciousness_to_meta[observable[0]].get("confidence", "")
        record["observable_classification"] = maliciousness_to_meta[observable[0]].get("classification", "")

        observables_list.append(record)

    return observables_list


def create_sighting(config, operation_name, params):
    eiq_group = config.get('eiq_group', None)

    observables_dict = prepare_observables(params)
    sighting_conf_value = "None" if params.get('confidence_value') == "No Confidence(None)" else params.get(
        'confidence_value')
    sighting_title = params.get('sighting_title')
    sighting_tags = params.get('tags').split(",")
    sighting_impact_value = "None" if params.get('impact_value') == "No Impact(None)" else params.get('impact_value')
    sighting_description = params.get('sighting_description', "")

    try:
        eiq = eiq_init(config)
        sighting = eiq.create_entity(observable_dict=observables_dict, source_group_name=eiq_group,
                                     entity_title=sighting_title, entity_description=sighting_description,
                                     entity_tags=sighting_tags, entity_confidence=sighting_conf_value,
                                     entity_impact_value=sighting_impact_value)

        if sighting is not False:
            return {"result": sighting, "status": "success"}
        else:
            return {"result": sighting, "status": "fail"}

    except Exception as e:
        logger.exception("Error: {0}".format(e))
        raise ConnectorError("Error: {0}".format(e))


def query_entities(config, operation_name, params):
    entity_type_dict = {"All": "all", "Campaign": "campaign",
                        "Course of Action": "course-of-action",
                        "Exploit Target": "exploit-target",
                        "Incident": "incident", "Indicator": "indicator",
                        "Threat Actor": "threat-actor", "TTP": "ttp"}
    if params['entity_type'] == "All":
        entity_type = '("ttp" OR "campaign" OR "course-of-action" OR "exploit-target" OR "incident" OR' \
                      ' "indicator" OR "threat-actor")'
    else:
        entity_type = entity_type_dict.get(params['entity_type'])
    if params["query"] == "":
        query = None
    else:
        query = params["query"]
    if params["entity_value"] == "":
        entity_value = None
    else:
        entity_value = params["entity_value"]

    query_params = {
        "from": params.get("from", 0),
        "size": params.get("size", 10)
    }
    try:
        eiq = eiq_init(config)
        query_result, result_size = eiq.search_entity(entity_value=entity_value, entity_type=entity_type,
                                                      observable_value=query, params=query_params)
        result = []
        if query_result is not False:
            for k in query_result:
                if len(k['_source']['extracts']) > 0:
                    for kk in k['_source']['extracts']:
                        response_classification = kk['meta'].get('classification', 'N/A')
                        response_confidence = kk['meta'].get('confidence', 'N/A')
                        response_kind = kk.get('kind', 'N/A')
                        response_value = kk.get('value', 'N/A')
                        response_title = k['_source']['data'].get('title', 'N/A')
                        response_type = k['_source']['data'].get('type', 'N/A')
                        response_description = k['_source']['data'].get('description', 'N/A')
                        response_threat_start = k['_source']['meta'].get('estimated_threat_start_time', 'N/A')
                        response_tags = ''
                        response_source_name = k['_source']['sources'][0].get('name', 'N/A')
                        response_tags = ', '.join(k['_source']['tags'])
                        parsed_response = {
                            'extract_kind': response_kind,
                            'extract_value': response_value,
                            'extract_classification': response_classification,
                            'extract_confidence': response_confidence,
                            'title': response_title,
                            'type': response_type,
                            'description': response_description,
                            'threat_start': response_threat_start,
                            'tags': response_tags,
                            'source_name': response_source_name
                        }
                        result.append(parsed_response)
                else:
                    response_classification = 'N/A'
                    response_confidence = 'N/A'
                    response_kind = 'N/A'
                    response_value = 'N/A'
                    response_title = k['_source']['data'].get('title', 'N/A')
                    response_description = k['_source']['data'].get('description', 'N/A')
                    response_threat_start = k['_source']['meta'].get('estimated_threat_start_time', 'N/A')
                    response_source_name = k['_source']['sources'][0].get('name', 'N/A')
                    response_tags = ', '.join(k['_source']['tags'])
                    parsed_response = {
                        'extract_kind': response_kind,
                        'extract_value': response_value,
                        'extract_classification': response_classification,
                        'extract_confidence': response_confidence,
                        'title': response_title,
                        'description': response_description,
                        'threat_start': response_threat_start,
                        'tags': response_tags,
                        'source_name': response_source_name
                    }
                    result.append(parsed_response)
            return {"status": "success",
                    "actual_result_size": result_size["value"],
                    "reported_results": len(result),
                    "result": result
                    }
        else:
            return {"result": [], "status": "success",
                    "actual_result_size": result_size["value"],
                    "reported_results": len(result)
                    }
    except Exception as e:
        logger.exception("Error: {0}".format(e))
        raise ConnectorError("Error: {0}".format(e))


def _check_health(config):
    try:
        eiq = eiq_init(config)
        return True
    except Exception as err:
        logger.exception("Provide valid configuration")
        logger.exception("Error connecting to EclecticIQ. Error as follows: {}".format(str(err)))
        raise ConnectorError("Invalid configuration")


operations = {
    'get_ip_reputation': get_observable_reputation,
    'get_domain_reputation': get_observable_reputation,
    'get_email_reputation': get_observable_reputation,
    'get_file_reputation': get_observable_reputation,
    'get_uri_reputation': get_observable_reputation,
    'create_sighting': create_sighting,
    'query_entities': query_entities
}
