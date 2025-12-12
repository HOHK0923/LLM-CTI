#!/usr/bin/env python3
"""
Dataset Builder for LLM Training
Converts parsed JSON logs into training datasets with timeline analysis
"""

import json
import os
from datetime import datetime
from typing import List, Dict, Any
from collections import defaultdict


class DatasetBuilder:
    def __init__(self):
        self.sessions = defaultdict(list)
        self.attack_patterns = []

    def load_parsed_logs(self, json_file: str) -> Dict[str, Any]:
        """Load parsed JSON logs from C engine output"""
        with open(json_file, 'r') as f:
            return json.load(f)

    def group_by_session(self, events: List[Dict]) -> Dict[str, List[Dict]]:
        """Group events by session ID to build attack timelines"""
        sessions = defaultdict(list)
        for event in events:
            session_id = event.get('session_id', 'UNKNOWN')
            sessions[session_id].append(event)
        return sessions

    def analyze_attack_timeline(self, session_events: List[Dict]) -> Dict[str, Any]:
        """Analyze a session's attack timeline"""
        if not session_events:
            return {}

        # Sort by timestamp
        sorted_events = sorted(session_events, key=lambda x: x['timestamp'])

        attack_types = [e['attack_type'] for e in sorted_events]
        success_count = sum(1 for e in sorted_events if e['success'])
        failure_count = len(sorted_events) - success_count

        # Determine attack stage
        stage = self._determine_attack_stage(sorted_events)

        # Calculate risk score
        risk_score = self._calculate_risk_score(sorted_events)

        # Generate timeline description
        timeline_desc = self._generate_timeline_description(sorted_events)

        # Determine recommended response
        response = self._recommend_response(sorted_events, risk_score)

        return {
            'session_id': sorted_events[0]['session_id'],
            'source_ip': sorted_events[0]['source_ip'],
            'start_time': sorted_events[0]['timestamp'],
            'end_time': sorted_events[-1]['timestamp'],
            'total_attempts': len(sorted_events),
            'successful_attacks': success_count,
            'failed_attacks': failure_count,
            'attack_types': list(set(attack_types)),
            'attack_stage': stage,
            'risk_score': risk_score,
            'timeline': timeline_desc,
            'recommended_response': response,
            'events': sorted_events
        }

    def _determine_attack_stage(self, events: List[Dict]) -> str:
        """Determine the stage of attack"""
        attack_types = [e['attack_type'] for e in events]

        # Check for multi-stage attacks
        if len(set(attack_types)) > 2:
            return "MULTI_STAGE_ATTACK"

        # Check for reconnaissance
        recon_keywords = ['version', 'database()', 'user()', 'uname', 'information_schema']
        if any(any(keyword in e['payload'].lower() for keyword in recon_keywords) for e in events):
            return "RECONNAISSANCE"

        # Check for exploitation
        exploit_keywords = ['union select', 'load_file', 'nc -e', 'backdoor', 'shell']
        if any(any(keyword in e['payload'].lower() for keyword in exploit_keywords) for e in events):
            return "EXPLOITATION"

        # Check for data exfiltration
        exfil_keywords = ['users', 'password', 'passwd', 'document.cookie']
        if any(any(keyword in e['payload'].lower() for keyword in exfil_keywords) for e in events):
            return "DATA_EXFILTRATION"

        return "INITIAL_ACCESS"

    def _calculate_risk_score(self, events: List[Dict]) -> int:
        """Calculate risk score based on attack severity and success rate"""
        total_severity = sum(e.get('severity', 1) for e in events)
        success_rate = sum(1 for e in events if e['success']) / len(events) if events else 0

        base_score = total_severity / len(events) if events else 0
        risk_score = int(base_score * (1 + success_rate))

        return min(risk_score, 10)

    def _generate_timeline_description(self, events: List[Dict]) -> str:
        """Generate human-readable timeline description"""
        descriptions = []

        for i, event in enumerate(events, 1):
            status = "성공" if event['success'] else "실패"
            desc = f"{i}. [{event['timestamp']}] {event['attack_type']} 시도 ({status}): {event['payload'][:50]}"
            descriptions.append(desc)

        return "\n".join(descriptions)

    def _recommend_response(self, events: List[Dict], risk_score: int) -> Dict[str, Any]:
        """Recommend SOAR response based on attack analysis"""
        responses = []

        # Check for successful attacks
        successful_attacks = [e for e in events if e['success']]

        if risk_score >= 8:
            responses.append({
                'action': 'BLOCK_IP',
                'priority': 'CRITICAL',
                'description': 'IP 차단 (즉시)',
                'parameters': {'ip': events[0]['source_ip'], 'duration': 'permanent'}
            })
            responses.append({
                'action': 'ALERT_SOC',
                'priority': 'CRITICAL',
                'description': 'SOC 팀 즉시 알림',
                'parameters': {'severity': 'critical', 'escalate': True}
            })
        elif risk_score >= 5:
            responses.append({
                'action': 'RATE_LIMIT',
                'priority': 'HIGH',
                'description': 'IP 속도 제한',
                'parameters': {'ip': events[0]['source_ip'], 'max_requests': 10, 'duration': 3600}
            })
            responses.append({
                'action': 'ALERT_SOC',
                'priority': 'HIGH',
                'description': 'SOC 팀 알림',
                'parameters': {'severity': 'high', 'escalate': False}
            })
        else:
            responses.append({
                'action': 'LOG_MONITOR',
                'priority': 'MEDIUM',
                'description': '모니터링 강화',
                'parameters': {'ip': events[0]['source_ip'], 'duration': 1800}
            })

        # Add specific responses based on attack type
        attack_types = set(e['attack_type'] for e in successful_attacks)

        if 'SQL_INJECTION' in attack_types:
            responses.append({
                'action': 'ENABLE_WAF_RULE',
                'priority': 'HIGH',
                'description': 'WAF SQL Injection 규칙 활성화',
                'parameters': {'rule_id': 'sql_injection_protection'}
            })

        if 'COMMAND_INJECTION' in attack_types:
            responses.append({
                'action': 'ISOLATE_SERVER',
                'priority': 'CRITICAL',
                'description': '서버 격리 검토',
                'parameters': {'server': 'target_server'}
            })

        return {
            'risk_score': risk_score,
            'actions': responses
        }

    def build_training_dataset(self, json_file: str, output_file: str):
        """Build complete training dataset"""
        print(f"Loading parsed logs from: {json_file}")
        data = self.load_parsed_logs(json_file)

        events = data.get('events', [])
        print(f"Total events: {len(events)}")

        # Group by session
        sessions = self.group_by_session(events)
        print(f"Total sessions: {len(sessions)}")

        # Analyze each session
        training_data = []
        for session_id, session_events in sessions.items():
            analysis = self.analyze_attack_timeline(session_events)
            if analysis:
                # Create training example
                training_example = self._create_training_example(analysis)
                training_data.append(training_example)

        # Save training dataset
        output = {
            'metadata': {
                'total_sessions': len(sessions),
                'total_events': len(events),
                'generated_at': datetime.now().isoformat()
            },
            'training_data': training_data
        }

        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(output, f, ensure_ascii=False, indent=2)

        print(f"\nTraining dataset saved to: {output_file}")
        print(f"Total training examples: {len(training_data)}")

    def _create_training_example(self, analysis: Dict) -> Dict:
        """Create a training example in instruction-response format"""
        # Create instruction (input)
        instruction = f"""다음은 보안 시스템에서 탐지된 공격 로그입니다. 이 공격을 분석하고 적절한 대응 방안을 제시하세요.

세션 ID: {analysis['session_id']}
출발지 IP: {analysis['source_ip']}
공격 시작 시간: {analysis['start_time']}
공격 종료 시간: {analysis['end_time']}
총 시도 횟수: {analysis['total_attempts']}
성공한 공격: {analysis['successful_attacks']}
실패한 공격: {analysis['failed_attacks']}
공격 유형: {', '.join(analysis['attack_types'])}

공격 타임라인:
{analysis['timeline']}
"""

        # Create response (output)
        response = f"""### 공격 분석 결과

**공격 단계**: {analysis['attack_stage']}
**위험도 점수**: {analysis['risk_score']}/10

**권장 대응 조치**:
"""

        for i, action in enumerate(analysis['recommended_response']['actions'], 1):
            response += f"\n{i}. [{action['priority']}] {action['description']}"
            response += f"\n   - 조치: {action['action']}"

        response += f"\n\n**분석 요약**:\n"
        response += f"이 공격은 {analysis['attack_stage']} 단계로 분류되며, "
        response += f"총 {analysis['total_attempts']}회 시도 중 {analysis['successful_attacks']}회 성공하였습니다. "
        response += f"위험도는 {analysis['risk_score']}/10 입니다."

        return {
            'instruction': instruction,
            'response': response,
            'metadata': {
                'session_id': analysis['session_id'],
                'risk_score': analysis['risk_score'],
                'attack_stage': analysis['attack_stage'],
                'attack_types': analysis['attack_types']
            }
        }


def main():
    import sys

    if len(sys.argv) != 3:
        print("Usage: python dataset_builder.py <input_json> <output_json>")
        print("Example: python dataset_builder.py ../data/parsed_logs/attack.json ../data/datasets/training.json")
        sys.exit(1)

    input_file = sys.argv[1]
    output_file = sys.argv[2]

    builder = DatasetBuilder()
    builder.build_training_dataset(input_file, output_file)


if __name__ == '__main__':
    main()
