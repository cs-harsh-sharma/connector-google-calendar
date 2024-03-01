"""
Copyright start
MIT License
Copyright (c) 2024 Fortinet Inc
Copyright end
"""

from requests import request
from connectors.core.connector import get_logger, ConnectorError
from .google_api_auth import *
from .constants import *

CALENDARS_API_VERSION = 'v3'

logger = get_logger('google-calendar')


def api_request(method, endpoint, connector_info, config, params=None, data=None, headers={}):
    try:
        go = GoogleAuth(config)
        endpoint = go.host + "/" + endpoint
        token = go.validate_token(config, connector_info)
        headers['Authorization'] = token
        headers['Content-Type'] = 'application/json'
        response = request(method, endpoint, headers=headers, params=params, data=data, verify=go.verify_ssl)
        if response.ok or response.status_code == 204:
            if 'json' in str(response.headers):
                return response.json()
            else:
                return response
        else:
            logger.error("{0}".format(response.status_code))
            raise ConnectorError("{0}:{1}".format(response.status_code, response.text))
    except requests.exceptions.SSLError:
        raise ConnectorError('SSL certificate validation failed')
    except requests.exceptions.ConnectTimeout:
        raise ConnectorError('The request timed out while trying to connect to the server')
    except requests.exceptions.ReadTimeout:
        raise ConnectorError(
            'The server did not send any data in the allotted amount of time')
    except requests.exceptions.ConnectionError:
        raise ConnectorError('Invalid Credentials')
    except Exception as err:
        raise ConnectorError(str(err))


def check_payload(payload):
    l = {}
    for k, v in payload.items():
        if isinstance(v, dict):
            x = check_payload(v)
            if len(x.keys()) > 0:
                l[k] = x
        elif isinstance(v, list):
            p = []
            for c in v:
                if isinstance(c, dict):
                    x = check_payload(c)
                    if len(x.keys()) > 0:
                        p.append(x)
                elif c is not None and c != '':
                    p.append(c)
            if p != []:
                l[k] = p
        elif v is not None and v != '':
            l[k] = v
    return l


def build_payload(payload):
    payload = {k: v for k, v in payload.items() if v is not None and v != ''}
    return payload


def get_calendar_list(config, params, connector_info):
    try:
        url = 'calendar/{0}/users/me/calendarList'.format(CALENDARS_API_VERSION)
        min_access_role = params.get('minAccessRole')
        if min_access_role:
            min_access_role = ACCESS_ROLE.get(min_access_role)
            params.update({'minAccessRole': min_access_role})
        query_parameter = build_payload(params)
        response = api_request('GET', url, connector_info, config, params=query_parameter)
        return response
    except Exception as err:
        logger.exception("{0}".format(str(err)))
        raise ConnectorError("{0}".format(str(err)))


def get_calendar_list_details(config, params, connector_info):
    try:
        url = 'calendar/{0}/users/me/calendarList/{1}'.format(CALENDARS_API_VERSION, params.get('calendar_id'))
        response = api_request('GET', url, connector_info, config)
        return response
    except Exception as err:
        logger.exception("{0}".format(str(err)))
        raise ConnectorError("{0}".format(str(err)))


def get_calendar_access_control_list(config, params, connector_info):
    try:
        url = 'calendar/{0}/calendars/{1}/acl'.format(CALENDARS_API_VERSION, params.pop('calendar_id'))
        query_parameter = build_payload(params)
        response = api_request('GET', url, connector_info, config, params=query_parameter)
        return response
    except Exception as err:
        logger.exception("{0}".format(str(err)))
        raise ConnectorError("{0}".format(str(err)))


def get_access_control_rule_details(config, params, connector_info):
    try:
        url = 'calendar/{0}/calendars/{1}/acl/{2}'.format(CALENDARS_API_VERSION, params.get('calendar_id'),
                                                          params.get('rule_id'))
        response = api_request('GET', url, connector_info, config)
        return response
    except Exception as err:
        logger.exception("{0}".format(str(err)))
        raise ConnectorError("{0}".format(str(err)))


def get_events_list(config, params, connector_info):
    try:
        url = 'calendar/{0}/calendars/{1}/events'.format(CALENDARS_API_VERSION, params.get('calendar_id'))
        event_types_list = []
        event_types = params.get('eventTypes')
        if event_types:
            for event in event_types:
                event_types_list.append(EVENT_TYPES.get(event))
        query_parameter = {
            'eventTypes': event_types_list if event_types_list else '',
            'maxAttendees': params.get('maxAttendees'),
            'maxResults': params.get('maxResults'),
            'orderBy': params.get('orderBy'),
            'pageToken': params.get('pageToken'),
            'timeMax': params.get('timeMax'),
            'timeMin': params.get('timeMin'),
            'updatedMin': params.get('updatedMin')
        }
        additional_parameters = params.get('additional_parameters')
        if additional_parameters:
            query_parameter.update(additional_parameters)
        query_parameter = build_payload(query_parameter)
        response = api_request('GET', url, connector_info, config, params=query_parameter)
        return response
    except Exception as err:
        logger.exception("{0}".format(str(err)))
        raise ConnectorError("{0}".format(str(err)))


def get_event_details(config, params, connector_info):
    try:
        url = 'calendar/{0}/calendars/{1}/events/{2}'.format(CALENDARS_API_VERSION, params.pop('calendar_id'),
                                                             params.pop('event_id'))
        query_parameter = build_payload(params)
        response = api_request('GET', url, connector_info, config, params=query_parameter)
        return response
    except Exception as err:
        logger.exception("{0}".format(str(err)))
        raise ConnectorError("{0}".format(str(err)))


def _check_health(config, connector_info):
    try:
        return check(config, connector_info)
    except Exception as err:
        logger.exception("{0}".format(str(err)))
        raise ConnectorError("{0}".format(str(err)))


operations = {
    'get_calendar_list': get_calendar_list,
    'get_calendar_list_details': get_calendar_list_details,
    'get_calendar_access_control_list': get_calendar_access_control_list,
    'get_access_control_rule_details': get_access_control_rule_details,
    'get_events_list': get_events_list,
    'get_event_details': get_event_details
}
