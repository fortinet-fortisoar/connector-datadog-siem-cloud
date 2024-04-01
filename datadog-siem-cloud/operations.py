"""
Copyright start
MIT License
Copyright (c) 2024 Fortinet Inc
Copyright end
"""

from connectors.core.connector import get_logger, ConnectorError
from datetime import datetime
from datadog_api_client import ApiClient, Configuration
from datadog_api_client.v1.api.events_api import EventsApi as EventsApiV1
from datadog_api_client.v1.api.hosts_api import HostsApi
from datadog_api_client.v2.api.events_api import EventsApi
from datadog_api_client.v2.api.incidents_api import IncidentsApi
from datadog_api_client.v2.model.events_list_request import EventsListRequest
from datadog_api_client.v2.model.events_query_filter import EventsQueryFilter
from datadog_api_client.v2.model.events_query_options import EventsQueryOptions
from datadog_api_client.v2.model.events_request_page import EventsRequestPage
from datadog_api_client.v2.model.events_sort import EventsSort
from datadog_api_client.v2.model.incident_field_attributes_single_value import IncidentFieldAttributesSingleValue
from datadog_api_client.v2.model.incident_field_attributes_single_value_type import IncidentFieldAttributesSingleValueType
from datadog_api_client.v2.model.incident_search_sort_order import IncidentSearchSortOrder
from datadog_api_client.v2.model.incident_type import IncidentType
from datadog_api_client.v2.model.incident_update_attributes import IncidentUpdateAttributes
from datadog_api_client.v2.model.incident_update_data import IncidentUpdateData
from datadog_api_client.v2.model.incident_update_request import IncidentUpdateRequest
from .constants import *


logger = get_logger("datadog-siem-cloud")


class DataDog:
    def __init__(self, config, *args, **kwargs):
        server_url = config.get("server_url").strip('/')
        if not server_url.startswith('https://') and not server_url.startswith('http://'):
            server_url = "https://" + server_url
        self.datadog_config = Configuration()
        self.datadog_config.host = server_url
        self.datadog_config.api_key["apiKeyAuth"] = config.get("api_key")
        self.datadog_config.api_key["appKeyAuth"] = config.get("application_key")
        self.datadog_config.verify_ssl = config.get("verify_ssl")


def build_params(params):
    new_params = {}
    for key, value in params.items():
        if value is False or value == 0 or value:
            if key in {"state", "detection_method", "include"}:
                if isinstance(value, list):
                    value = [v.lower() for v in value]
                else:
                    value = value.lower()
            elif key == "severity":
                value = SEVERITY_MAPPING.get(value)
            elif key == "sort" and value in SORT_MAPPING:
                value = SORT_MAPPING.get(value)
            new_params[key] = value
    logger.info(f"updated params: {new_params}")
    return new_params


def incident_search_query(params):
    query = ""
    if params.get("state"):
        query += f"state:{params['state']}"
    if params.get("severity"):
        query += (
            f" AND severity:{params['severity']}"
            if len(query)
            else f"severity:{params['severity']}"
        )
    if isinstance(params.get("customer_impacted"), bool):
        query += (
            f" AND customer_impacted:{str(params['customer_impacted']).lower()}"
            if len(query)
            else f"customer_impacted:{str(params['customer_impacted']).lower()}"
        )
    if params.get("detection_method"):
        query += (
            f" AND detection_method:{params['detection_method']}"
            if len(query)
            else f"detection_method:{params['detection_method']}"
        )
    if not query:
        query = "state:(active OR stable OR resolved)"
    logger.info(f"query: {query}")
    return query


def get_incidents(config, params):
    ob = DataDog(config)
    params = build_params(params)
    ob.datadog_config.unstable_operations["list_incidents"] = True
    with ApiClient(ob.datadog_config) as api_client:
        api_instance = IncidentsApi(api_client)
        response = api_instance.list_incidents(**params)  # params can be: include, page_size, page_offset
        return response.to_dict()


def get_incident_details(config, params):
    ob = DataDog(config)
    params = build_params(params)
    ob.datadog_config.unstable_operations["get_incident"] = True
    with ApiClient(ob.datadog_config) as api_client:
        api_instance = IncidentsApi(api_client)
        response = api_instance.get_incident(
            incident_id=params["incident_id"],
        )
        return response.to_dict()


def search_incidents(config, params):
    ob = DataDog(config)
    params = build_params(params)
    sort = params.get("sort") or "desc"
    sort_data = {"asc": "created", "desc": "-created"}
    offset = params.get("offset")
    limit = params.get("limit")
    include = params.get("include")
    incident_params = {
        "query": incident_search_query(params),
        "sort": IncidentSearchSortOrder(sort_data[sort]),
    }
    offset and incident_params.update(page_offset=offset)
    limit and incident_params.update(page_size=limit)
    include and incident_params.update(include=include)
    logger.info(f"incident_params: {incident_params}")
    ob.datadog_config.unstable_operations["search_incidents"] = True
    with ApiClient(ob.datadog_config) as api_client:
        api_instance = IncidentsApi(api_client)
        incident_list_response = api_instance.search_incidents(**incident_params)
        return incident_list_response.to_dict()


def update_incident(config, params):
    params = build_params(params)
    update_fields = {}
    customer_impact_end = params.get("customer_impact_end")
    customer_impact_scope = params.get("customer_impact_scope")
    customer_impact_start = params.get("customer_impact_start")
    customer_impacted = params.get("customer_impacted")
    detected = params.get("detected")
    title = params.get("title")

    customer_impact_end and update_fields.update(customer_impact_end=datetime.strptime(customer_impact_end, INPUT_DATE_FORMAT))
    customer_impact_scope and update_fields.update(customer_impact_scope=customer_impact_scope)
    customer_impact_start and update_fields.update(customer_impact_start=datetime.strptime(customer_impact_start, INPUT_DATE_FORMAT))
    isinstance(customer_impacted, bool) and update_fields.update(customer_impacted=customer_impacted)
    detected and update_fields.update(detected=datetime.strptime(detected, INPUT_DATE_FORMAT))
    title and update_fields.update(title=title)

    incident_fields = {}
    state = params.get("state")
    severity = params.get("severity")
    detection_method = params.get("detection_method")
    root_cause = params.get("root_cause")
    summary = params.get("summary")
    state and incident_fields.update({
        "state": IncidentFieldAttributesSingleValue(
            type=IncidentFieldAttributesSingleValueType.DROPDOWN,
            value=state,
        )
    })
    severity and incident_fields.update({
        "severity": IncidentFieldAttributesSingleValue(
            type=IncidentFieldAttributesSingleValueType.DROPDOWN,
            value=severity,
        )
    })
    detection_method and incident_fields.update({
        "detection_method": IncidentFieldAttributesSingleValue(
            type=IncidentFieldAttributesSingleValueType.DROPDOWN,
            value=detection_method,
        )
    })
    root_cause and incident_fields.update({
        "root_cause": IncidentFieldAttributesSingleValue(
            type=IncidentFieldAttributesSingleValueType.TEXTBOX,
            value=root_cause,
        )
    })
    summary and incident_fields.update({
        "summary": IncidentFieldAttributesSingleValue(
            type=IncidentFieldAttributesSingleValueType.TEXTBOX,
            value=summary,
        )
    })

    incident_fields and update_fields.update(fields=incident_fields)
    logger.info(f"update_fields: {update_fields}")
    body = IncidentUpdateRequest(
        data=IncidentUpdateData(
            id=str(params["incident_id"]),
            type=IncidentType.INCIDENTS,
            attributes=IncidentUpdateAttributes(**update_fields)
        )
    )

    ob = DataDog(config)
    ob.datadog_config.unstable_operations["update_incident"] = True
    with ApiClient(ob.datadog_config) as api_client:
        api_instance = IncidentsApi(api_client)
        response = api_instance.update_incident(incident_id=str(params["incident_id"]), body=body)
        return response.to_dict()


def search_events(config, params):
    ob = DataDog(config)
    params = build_params(params)

    filter_params = {}
    query = params.get("query")
    _from = params.get("from")
    to = params.get("to")
    query and filter_params.update(query=query)
    _from and filter_params.update(_from=datetime.strptime(_from, INPUT_DATE_FORMAT).strftime('%Y-%m-%dT%H:%M:%S+00:00'))
    to and filter_params.update(to=datetime.strptime(to, INPUT_DATE_FORMAT).strftime('%Y-%m-%dT%H:%M:%S+00:00'))

    time_params = {}
    time_offset = params.get("time_offset")
    timezone = params.get("timezone")
    time_offset and time_params.update(timeOffset=time_offset)
    timezone and time_params.update(timezone=timezone)

    page_params = {}
    limit = params.get("limit")
    cursor = params.get("cursor")
    limit and page_params.update(limit=limit)
    cursor and page_params.update(cursor=cursor)
    logger.info(f"\nfilter_params: {filter_params}\ntime_params: {time_params}\npage_params: {page_params}")

    body = EventsListRequest(
        filter=EventsQueryFilter(**filter_params),
        options=EventsQueryOptions(**time_params),
        sort=params.get("sort") or EventsSort.TIMESTAMP_DESCENDING,
        page=EventsRequestPage(**page_params),
    )

    with ApiClient(ob.datadog_config) as api_client:
        api_instance = EventsApi(api_client)
        response = api_instance.search_events(body=body)
        return response.to_dict()


def get_event_details(config, params):
    ob = DataDog(config)
    with ApiClient(ob.datadog_config) as api_client:
        api_instance = EventsApiV1(api_client)
        response = api_instance.get_event(event_id=params["event_id"])
        return response.to_dict()


def get_hosts(config, params):
    ob = DataDog(config)
    params = build_params(params)
    _from = params.get("_from")
    _from and params.update(_from=datetime.strptime(_from, '%Y-%m-%dT%H:%M:%S.%fZ').timestamp())
    logger.info(f"hosts params: {params}")
    with ApiClient(ob.datadog_config) as api_client:
        api_instance = HostsApi(api_client)
        response = api_instance.list_hosts(**params)
        return response.to_dict()


def get_attachments(config, params):
    ob = DataDog(config)
    params = build_params(params)
    ob.datadog_config.unstable_operations["list_incident_attachments"] = True
    body = {
        "incident_id": params["incident_id"]
    }
    logger.info(f"attachment params: {body}")
    with ApiClient(ob.datadog_config) as api_client:
        api_instance = IncidentsApi(api_client)
        response = api_instance.list_incident_attachments(**body)
        return response.to_dict()


def check_health_ex(config):
    get_incidents(config, {"page_size": 1})
    return True


operations = {
    "get_incidents": get_incidents,
    "get_incident_details": get_incident_details,
    "search_incidents": search_incidents,
    "update_incident": update_incident,
    "search_events": search_events,
    "get_event_details": get_event_details,
    "get_hosts": get_hosts,
    "get_attachments": get_attachments
}
