"""
Copyright start
MIT License
Copyright (c) 2024 Fortinet Inc
Copyright end
"""

from connectors.core.connector import get_logger, ConnectorError, Connector
from .operations import operations, check_health_ex

logger = get_logger("datadog-siem-cloud")


class KnowB4PhishER(Connector):
    def execute(self, config, operation, params, **kwargs):
        try:
            operation = operations.get(operation)
            return operation(config, params)
        except Exception as err:
            logger.exception(err)
            raise ConnectorError(err)

    def check_health(self, config):
        logger.info("starting health check")
        check_health_ex(config)
        logger.info("completed health check no errors")
