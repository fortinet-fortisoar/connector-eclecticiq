from connectors.core.connector import Connector, ConnectorError, get_logger
from .operations import operations, _check_health

logger = get_logger('eclecticiq')


class EclecticIQ(Connector):
    def execute(self, config, operation_name, params, **kwargs):
        try:
            logger.info("operation_name: {0}".format(operation_name))
            op = operations.get(operation_name)
            result = op(config, operation_name, params)
            return result
        except Exception as e:
            logger.exception("An exception occurred {0}".format(e))
            raise ConnectorError("{0}".format(e))

    def check_health(self, config):
        try:
            return _check_health(config)
        except Exception as e:
            raise ConnectorError(e)
