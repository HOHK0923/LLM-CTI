#!/usr/bin/env python3
"""
SIEM Integration Module
Connects to SIEM systems (Splunk, ELK, etc.) and sends analyzed logs
"""

import json
import requests
from typing import Dict, Any, List, Optional
from datetime import datetime
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class SIEMConnector:
    """Base SIEM connector class"""

    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.siem_type = config.get('type', 'generic')

    def send_event(self, event: Dict[str, Any]) -> bool:
        """Send event to SIEM"""
        raise NotImplementedError("Subclasses must implement send_event")

    def send_batch(self, events: List[Dict[str, Any]]) -> bool:
        """Send multiple events to SIEM"""
        raise NotImplementedError("Subclasses must implement send_batch")


class SplunkConnector(SIEMConnector):
    """Splunk HEC (HTTP Event Collector) connector"""

    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.hec_url = config.get('hec_url')
        self.hec_token = config.get('hec_token')
        self.index = config.get('index', 'main')
        self.sourcetype = config.get('sourcetype', 'security:attack')

    def send_event(self, event: Dict[str, Any]) -> bool:
        """Send single event to Splunk"""
        try:
            payload = {
                'time': datetime.now().timestamp(),
                'host': 'security-analyzer',
                'source': 'llm-siem',
                'sourcetype': self.sourcetype,
                'index': self.index,
                'event': event
            }

            headers = {
                'Authorization': f'Splunk {self.hec_token}',
                'Content-Type': 'application/json'
            }

            response = requests.post(
                self.hec_url,
                headers=headers,
                json=payload,
                verify=False
            )

            if response.status_code == 200:
                logger.info(f"Event sent to Splunk successfully")
                return True
            else:
                logger.error(f"Failed to send event to Splunk: {response.text}")
                return False

        except Exception as e:
            logger.error(f"Error sending event to Splunk: {e}")
            return False

    def send_batch(self, events: List[Dict[str, Any]]) -> bool:
        """Send multiple events to Splunk"""
        success_count = 0
        for event in events:
            if self.send_event(event):
                success_count += 1

        logger.info(f"Sent {success_count}/{len(events)} events to Splunk")
        return success_count == len(events)


class ElasticsearchConnector(SIEMConnector):
    """Elasticsearch connector for ELK stack"""

    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.es_url = config.get('es_url')
        self.index = config.get('index', 'security-events')
        self.username = config.get('username')
        self.password = config.get('password')

    def send_event(self, event: Dict[str, Any]) -> bool:
        """Send single event to Elasticsearch"""
        try:
            event['@timestamp'] = datetime.now().isoformat()

            url = f"{self.es_url}/{self.index}/_doc"

            auth = None
            if self.username and self.password:
                auth = (self.username, self.password)

            response = requests.post(
                url,
                auth=auth,
                json=event,
                headers={'Content-Type': 'application/json'}
            )

            if response.status_code in [200, 201]:
                logger.info(f"Event sent to Elasticsearch successfully")
                return True
            else:
                logger.error(f"Failed to send event to Elasticsearch: {response.text}")
                return False

        except Exception as e:
            logger.error(f"Error sending event to Elasticsearch: {e}")
            return False

    def send_batch(self, events: List[Dict[str, Any]]) -> bool:
        """Send multiple events to Elasticsearch using bulk API"""
        try:
            bulk_data = []
            for event in events:
                event['@timestamp'] = datetime.now().isoformat()

                # Bulk API format
                bulk_data.append(json.dumps({'index': {'_index': self.index}}))
                bulk_data.append(json.dumps(event))

            bulk_body = '\n'.join(bulk_data) + '\n'

            url = f"{self.es_url}/_bulk"

            auth = None
            if self.username and self.password:
                auth = (self.username, self.password)

            response = requests.post(
                url,
                auth=auth,
                data=bulk_body,
                headers={'Content-Type': 'application/x-ndjson'}
            )

            if response.status_code == 200:
                result = response.json()
                errors = result.get('errors', False)
                if not errors:
                    logger.info(f"Sent {len(events)} events to Elasticsearch successfully")
                    return True
                else:
                    logger.error(f"Some events failed to index in Elasticsearch")
                    return False
            else:
                logger.error(f"Failed to send batch to Elasticsearch: {response.text}")
                return False

        except Exception as e:
            logger.error(f"Error sending batch to Elasticsearch: {e}")
            return False


class SyslogConnector(SIEMConnector):
    """Syslog connector for traditional SIEM systems"""

    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.syslog_host = config.get('host')
        self.syslog_port = config.get('port', 514)
        self.protocol = config.get('protocol', 'udp')

    def send_event(self, event: Dict[str, Any]) -> bool:
        """Send event via syslog"""
        import socket

        try:
            message = json.dumps(event)

            if self.protocol == 'udp':
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.sendto(message.encode(), (self.syslog_host, self.syslog_port))
                sock.close()
            elif self.protocol == 'tcp':
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.connect((self.syslog_host, self.syslog_port))
                sock.send(message.encode())
                sock.close()

            logger.info(f"Event sent via syslog successfully")
            return True

        except Exception as e:
            logger.error(f"Error sending event via syslog: {e}")
            return False

    def send_batch(self, events: List[Dict[str, Any]]) -> bool:
        """Send multiple events via syslog"""
        success_count = 0
        for event in events:
            if self.send_event(event):
                success_count += 1

        logger.info(f"Sent {success_count}/{len(events)} events via syslog")
        return success_count == len(events)


class SIEMManager:
    """Manage multiple SIEM connections"""

    def __init__(self, config_file: str):
        self.connectors = []
        self.load_config(config_file)

    def load_config(self, config_file: str):
        """Load SIEM configuration"""
        with open(config_file, 'r') as f:
            config = json.load(f)

        for siem_config in config.get('siems', []):
            connector = self._create_connector(siem_config)
            if connector:
                self.connectors.append(connector)

        logger.info(f"Loaded {len(self.connectors)} SIEM connectors")

    def _create_connector(self, config: Dict[str, Any]) -> Optional[SIEMConnector]:
        """Create appropriate connector based on type"""
        siem_type = config.get('type')

        if siem_type == 'splunk':
            return SplunkConnector(config)
        elif siem_type == 'elasticsearch':
            return ElasticsearchConnector(config)
        elif siem_type == 'syslog':
            return SyslogConnector(config)
        else:
            logger.warning(f"Unknown SIEM type: {siem_type}")
            return None

    def send_analysis_result(self, analysis: Dict[str, Any]):
        """Send analysis result to all configured SIEMs"""
        event = {
            'event_type': 'security_analysis',
            'timestamp': datetime.now().isoformat(),
            'analysis': analysis
        }

        for connector in self.connectors:
            connector.send_event(event)

    def send_attack_alert(self, attack_data: Dict[str, Any]):
        """Send attack alert to all SIEMs"""
        alert = {
            'event_type': 'attack_detected',
            'timestamp': datetime.now().isoformat(),
            'severity': attack_data.get('risk_score', 0),
            'attack_types': attack_data.get('attack_types', []),
            'source_ip': attack_data.get('source_ip'),
            'session_id': attack_data.get('session_id'),
            'details': attack_data
        }

        for connector in self.connectors:
            connector.send_event(alert)


def create_sample_config(output_file: str):
    """Create sample SIEM configuration file"""
    config = {
        'siems': [
            {
                'type': 'splunk',
                'name': 'Splunk Production',
                'hec_url': 'https://splunk.example.com:8088/services/collector',
                'hec_token': 'YOUR_HEC_TOKEN_HERE',
                'index': 'security',
                'sourcetype': 'security:attack'
            },
            {
                'type': 'elasticsearch',
                'name': 'ELK Stack',
                'es_url': 'http://elasticsearch.example.com:9200',
                'index': 'security-events',
                'username': 'elastic',
                'password': 'YOUR_PASSWORD_HERE'
            },
            {
                'type': 'syslog',
                'name': 'Legacy SIEM',
                'host': 'siem.example.com',
                'port': 514,
                'protocol': 'udp'
            }
        ]
    }

    with open(output_file, 'w') as f:
        json.dump(config, f, indent=2)

    print(f"Sample SIEM configuration created: {output_file}")


def main():
    import sys

    if len(sys.argv) < 2:
        print("Usage:")
        print("  python siem_connector.py create-config <output_file>")
        print("  python siem_connector.py test <config_file>")
        sys.exit(1)

    command = sys.argv[1]

    if command == 'create-config':
        output_file = sys.argv[2] if len(sys.argv) > 2 else 'siem_config.json'
        create_sample_config(output_file)

    elif command == 'test':
        config_file = sys.argv[2] if len(sys.argv) > 2 else 'siem_config.json'

        manager = SIEMManager(config_file)

        test_event = {
            'attack_type': 'SQL_INJECTION',
            'source_ip': '192.168.1.100',
            'severity': 8,
            'message': 'Test attack event'
        }

        manager.send_attack_alert(test_event)
        print("Test event sent to all configured SIEMs")


if __name__ == '__main__':
    main()
