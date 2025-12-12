#!/usr/bin/env python3
"""
SOAR (Security Orchestration, Automation and Response) System
Automates security response based on attack analysis
"""

import json
import logging
from typing import Dict, Any, List
from datetime import datetime
import time

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class ResponseAction:
    """Base class for automated response actions"""

    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.action_type = config.get('action')
        self.priority = config.get('priority', 'MEDIUM')

    def execute(self) -> bool:
        """Execute the response action"""
        raise NotImplementedError("Subclasses must implement execute")

    def validate(self) -> bool:
        """Validate action parameters"""
        return True

    def log_action(self, status: str, message: str):
        """Log action execution"""
        logger.info(f"[{self.action_type}] [{status}] {message}")


class BlockIPAction(ResponseAction):
    """Block IP address via firewall"""

    def execute(self) -> bool:
        ip = self.config['parameters'].get('ip')
        duration = self.config['parameters'].get('duration', 'temporary')

        self.log_action('STARTED', f"Blocking IP: {ip} ({duration})")

        # Simulate firewall API call
        try:
            # In production, call actual firewall API
            # Example: requests.post(firewall_api, json={'action': 'block', 'ip': ip})

            self.log_action('SUCCESS', f"IP {ip} blocked successfully")
            return True

        except Exception as e:
            self.log_action('FAILED', f"Failed to block IP {ip}: {e}")
            return False


class RateLimitAction(ResponseAction):
    """Apply rate limiting to IP address"""

    def execute(self) -> bool:
        ip = self.config['parameters'].get('ip')
        max_requests = self.config['parameters'].get('max_requests', 10)
        duration = self.config['parameters'].get('duration', 3600)

        self.log_action('STARTED', f"Applying rate limit to {ip}: {max_requests} req/{duration}s")

        try:
            # In production, configure rate limiting (nginx, API gateway, etc.)
            self.log_action('SUCCESS', f"Rate limit applied to {ip}")
            return True

        except Exception as e:
            self.log_action('FAILED', f"Failed to apply rate limit: {e}")
            return False


class AlertSOCAction(ResponseAction):
    """Send alert to SOC team"""

    def execute(self) -> bool:
        severity = self.config['parameters'].get('severity', 'medium')
        escalate = self.config['parameters'].get('escalate', False)

        self.log_action('STARTED', f"Alerting SOC team (severity: {severity}, escalate: {escalate})")

        try:
            # In production, send via email, Slack, PagerDuty, etc.
            # Example: send_slack_alert(channel='#soc', message=alert_message)

            alert_message = f"Security alert: {severity.upper()} severity"
            if escalate:
                alert_message += " [ESCALATED]"

            self.log_action('SUCCESS', f"SOC team alerted: {alert_message}")
            return True

        except Exception as e:
            self.log_action('FAILED', f"Failed to alert SOC: {e}")
            return False


class EnableWAFRuleAction(ResponseAction):
    """Enable specific WAF rule"""

    def execute(self) -> bool:
        rule_id = self.config['parameters'].get('rule_id')

        self.log_action('STARTED', f"Enabling WAF rule: {rule_id}")

        try:
            # In production, call WAF API (Cloudflare, AWS WAF, etc.)
            self.log_action('SUCCESS', f"WAF rule {rule_id} enabled")
            return True

        except Exception as e:
            self.log_action('FAILED', f"Failed to enable WAF rule: {e}")
            return False


class IsolateServerAction(ResponseAction):
    """Isolate compromised server"""

    def execute(self) -> bool:
        server = self.config['parameters'].get('server')

        self.log_action('STARTED', f"Initiating server isolation: {server}")

        try:
            # In production, this would:
            # 1. Remove from load balancer
            # 2. Apply network isolation rules
            # 3. Snapshot for forensics

            self.log_action('SUCCESS', f"Server {server} isolated")
            return True

        except Exception as e:
            self.log_action('FAILED', f"Failed to isolate server: {e}")
            return False


class LogMonitorAction(ResponseAction):
    """Enhanced monitoring for suspicious activity"""

    def execute(self) -> bool:
        ip = self.config['parameters'].get('ip')
        duration = self.config['parameters'].get('duration', 1800)

        self.log_action('STARTED', f"Enhanced monitoring for {ip} ({duration}s)")

        try:
            # In production, configure SIEM to watch this IP closely
            self.log_action('SUCCESS', f"Monitoring enhanced for {ip}")
            return True

        except Exception as e:
            self.log_action('FAILED', f"Failed to enhance monitoring: {e}")
            return False


class SOAROrchestrator:
    """Orchestrate automated security responses"""

    def __init__(self):
        self.action_handlers = {
            'BLOCK_IP': BlockIPAction,
            'RATE_LIMIT': RateLimitAction,
            'ALERT_SOC': AlertSOCAction,
            'ENABLE_WAF_RULE': EnableWAFRuleAction,
            'ISOLATE_SERVER': IsolateServerAction,
            'LOG_MONITOR': LogMonitorAction
        }

        self.execution_history = []

    def execute_response_plan(self, response_plan: Dict[str, Any]) -> Dict[str, Any]:
        """Execute a complete response plan"""
        risk_score = response_plan.get('risk_score', 0)
        actions = response_plan.get('actions', [])

        logger.info(f"Executing response plan (risk score: {risk_score})")
        logger.info(f"Total actions: {len(actions)}")

        results = []
        start_time = datetime.now()

        # Sort actions by priority
        priority_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}
        sorted_actions = sorted(actions, key=lambda x: priority_order.get(x.get('priority', 'MEDIUM'), 99))

        for action_config in sorted_actions:
            action_type = action_config.get('action')

            if action_type not in self.action_handlers:
                logger.warning(f"Unknown action type: {action_type}")
                continue

            # Create and execute action
            handler_class = self.action_handlers[action_type]
            handler = handler_class(action_config)

            if not handler.validate():
                logger.error(f"Action validation failed: {action_type}")
                results.append({
                    'action': action_type,
                    'status': 'VALIDATION_FAILED',
                    'timestamp': datetime.now().isoformat()
                })
                continue

            # Execute action
            success = handler.execute()

            result = {
                'action': action_type,
                'priority': action_config.get('priority'),
                'status': 'SUCCESS' if success else 'FAILED',
                'timestamp': datetime.now().isoformat(),
                'description': action_config.get('description')
            }

            results.append(result)

            # Add delay between critical actions
            if action_config.get('priority') == 'CRITICAL':
                time.sleep(1)

        end_time = datetime.now()
        execution_time = (end_time - start_time).total_seconds()

        execution_summary = {
            'start_time': start_time.isoformat(),
            'end_time': end_time.isoformat(),
            'execution_time_seconds': execution_time,
            'total_actions': len(actions),
            'successful_actions': sum(1 for r in results if r['status'] == 'SUCCESS'),
            'failed_actions': sum(1 for r in results if r['status'] == 'FAILED'),
            'results': results
        }

        self.execution_history.append(execution_summary)

        logger.info(f"Response plan execution complete: {execution_summary['successful_actions']}/{execution_summary['total_actions']} successful")

        return execution_summary

    def create_playbook(self, attack_type: str, severity: int) -> Dict[str, Any]:
        """Create a response playbook based on attack type and severity"""
        playbook = {
            'attack_type': attack_type,
            'severity': severity,
            'actions': []
        }

        # Critical severity (8-10)
        if severity >= 8:
            playbook['actions'].extend([
                {
                    'action': 'BLOCK_IP',
                    'priority': 'CRITICAL',
                    'description': 'Immediately block malicious IP',
                    'parameters': {'duration': 'permanent'}
                },
                {
                    'action': 'ALERT_SOC',
                    'priority': 'CRITICAL',
                    'description': 'Escalate to SOC team',
                    'parameters': {'severity': 'critical', 'escalate': True}
                },
                {
                    'action': 'ISOLATE_SERVER',
                    'priority': 'HIGH',
                    'description': 'Consider server isolation',
                    'parameters': {}
                }
            ])

        # High severity (5-7)
        elif severity >= 5:
            playbook['actions'].extend([
                {
                    'action': 'RATE_LIMIT',
                    'priority': 'HIGH',
                    'description': 'Apply rate limiting',
                    'parameters': {'max_requests': 10, 'duration': 3600}
                },
                {
                    'action': 'ALERT_SOC',
                    'priority': 'HIGH',
                    'description': 'Alert SOC team',
                    'parameters': {'severity': 'high', 'escalate': False}
                }
            ])

        # Medium severity (3-4)
        else:
            playbook['actions'].extend([
                {
                    'action': 'LOG_MONITOR',
                    'priority': 'MEDIUM',
                    'description': 'Enhanced monitoring',
                    'parameters': {'duration': 1800}
                }
            ])

        # Attack-specific actions
        if attack_type == 'SQL_INJECTION':
            playbook['actions'].append({
                'action': 'ENABLE_WAF_RULE',
                'priority': 'HIGH',
                'description': 'Enable SQL injection protection',
                'parameters': {'rule_id': 'sql_injection_protection'}
            })

        elif attack_type == 'XSS':
            playbook['actions'].append({
                'action': 'ENABLE_WAF_RULE',
                'priority': 'HIGH',
                'description': 'Enable XSS protection',
                'parameters': {'rule_id': 'xss_protection'}
            })

        elif attack_type == 'COMMAND_INJECTION':
            playbook['actions'].append({
                'action': 'ISOLATE_SERVER',
                'priority': 'CRITICAL',
                'description': 'Isolate potentially compromised server',
                'parameters': {}
            })

        return playbook

    def save_execution_history(self, output_file: str):
        """Save execution history to file"""
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(self.execution_history, f, ensure_ascii=False, indent=2)

        logger.info(f"Execution history saved to: {output_file}")


def main():
    import sys

    if len(sys.argv) < 2:
        print("Usage:")
        print("  python soar_orchestrator.py execute <response_plan.json>")
        print("  python soar_orchestrator.py create-playbook <attack_type> <severity>")
        sys.exit(1)

    command = sys.argv[1]
    orchestrator = SOAROrchestrator()

    if command == 'execute':
        if len(sys.argv) < 3:
            print("Error: Please provide response plan JSON file")
            sys.exit(1)

        plan_file = sys.argv[2]

        with open(plan_file, 'r') as f:
            response_plan = json.load(f)

        result = orchestrator.execute_response_plan(response_plan)
        print(json.dumps(result, indent=2, ensure_ascii=False))

    elif command == 'create-playbook':
        if len(sys.argv) < 4:
            print("Error: Please provide attack_type and severity")
            sys.exit(1)

        attack_type = sys.argv[2]
        severity = int(sys.argv[3])

        playbook = orchestrator.create_playbook(attack_type, severity)
        print(json.dumps(playbook, indent=2, ensure_ascii=False))


if __name__ == '__main__':
    main()
