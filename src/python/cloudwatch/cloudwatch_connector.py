#!/usr/bin/env python3
"""
AWS CloudWatch Logs Connector
CloudWatch에서 로그를 가져와 LLM CTI 파이프라인에 연동
"""

import boto3
import json
import os
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional
import re


class CloudWatchConnector:
    """AWS CloudWatch Logs 연동 클래스"""

    def __init__(self, region_name: str = 'ap-northeast-2'):
        """
        CloudWatch 클라이언트 초기화

        Args:
            region_name: AWS 리전 (기본값: 서울 ap-northeast-2)
        """
        self.client = boto3.client('logs', region_name=region_name)
        self.region_name = region_name

    def list_log_groups(self, prefix: str = '') -> List[str]:
        """로그 그룹 목록 조회"""
        log_groups = []

        try:
            paginator = self.client.get_paginator('describe_log_groups')

            for page in paginator.paginate(logGroupNamePrefix=prefix):
                for log_group in page['logGroups']:
                    log_groups.append(log_group['logGroupName'])

            return log_groups

        except Exception as e:
            print(f"Error listing log groups: {e}")
            return []

    def list_log_streams(self, log_group_name: str, limit: int = 50) -> List[str]:
        """로그 스트림 목록 조회"""
        log_streams = []

        try:
            paginator = self.client.get_paginator('describe_log_streams')

            for page in paginator.paginate(
                logGroupName=log_group_name,
                orderBy='LastEventTime',
                descending=True
            ):
                for stream in page['logStreams']:
                    log_streams.append(stream['logStreamName'])

                    if len(log_streams) >= limit:
                        break

            return log_streams[:limit]

        except Exception as e:
            print(f"Error listing log streams: {e}")
            return []

    def get_log_events(
        self,
        log_group_name: str,
        log_stream_name: Optional[str] = None,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        filter_pattern: str = '',
        limit: int = 10000
    ) -> List[Dict[str, Any]]:
        """CloudWatch 로그 이벤트 조회"""

        if start_time is None:
            start_time = datetime.now() - timedelta(hours=24)

        if end_time is None:
            end_time = datetime.now()

        start_timestamp = int(start_time.timestamp() * 1000)
        end_timestamp = int(end_time.timestamp() * 1000)

        events = []

        try:
            if log_stream_name:
                # 특정 스트림에서 조회
                response = self.client.get_log_events(
                    logGroupName=log_group_name,
                    logStreamName=log_stream_name,
                    startTime=start_timestamp,
                    endTime=end_timestamp,
                    limit=limit
                )
                events.extend(response.get('events', []))

            else:
                # 로그 그룹 전체에서 필터 쿼리
                paginator = self.client.get_paginator('filter_log_events')

                for page in paginator.paginate(
                    logGroupName=log_group_name,
                    startTime=start_timestamp,
                    endTime=end_timestamp,
                    filterPattern=filter_pattern
                ):
                    events.extend(page.get('events', []))

                    if len(events) >= limit:
                        break

            return events[:limit]

        except Exception as e:
            print(f"Error getting log events: {e}")
            return []

    def parse_security_logs(self, events: List[Dict]) -> List[Dict]:
        """보안 로그 파싱 (공격 탐지)"""
        parsed_logs = []

        attack_patterns = {
            'SQL_INJECTION': [
                r"(?i)(union\s+select|' or '1'='1|'; drop table|sleep\(\d+\))",
                r"(?i)(information_schema|load_file|into outfile)"
            ],
            'XSS': [
                r"(?i)(<script|onerror=|onload=|javascript:)",
                r"(?i)(alert\(|document\.cookie|eval\()"
            ],
            'COMMAND_INJECTION': [
                r"(?i)(\||&&|;|\$\(|`)(ls|whoami|cat|wget|curl|nc\s)",
                r"(?i)(bash|sh|/bin/)"
            ],
            'FILE_INCLUSION': [
                r"(?i)(\.\.\/|\.\.\\|/etc/passwd|/etc/shadow)",
                r"(?i)(php://|file://|http://.*\.txt)"
            ],
            'BRUTE_FORCE': [
                r"(?i)(failed login|authentication failed|invalid password)",
                r"(?i)(too many attempts|account locked)"
            ],
            'AUTHENTICATION_FAILURE': [
                r"(?i)(401 unauthorized|403 forbidden|access denied)",
                r"(?i)(invalid token|expired session)"
            ]
        }

        for event in events:
            message = event.get('message', '')
            timestamp = datetime.fromtimestamp(event['timestamp'] / 1000)

            # 각 공격 패턴 확인
            for attack_type, patterns in attack_patterns.items():
                for pattern in patterns:
                    if re.search(pattern, message):
                        # IP 추출
                        ip_match = re.search(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b', message)
                        source_ip = ip_match.group(1) if ip_match else 'UNKNOWN'

                        # 성공/실패 판단
                        success = not any(word in message.lower() for word in ['failed', 'error', 'blocked', 'denied'])

                        parsed_logs.append({
                            'timestamp': timestamp.strftime('%Y-%m-%d %H:%M:%S'),
                            'attack_type': attack_type,
                            'status': 'SUCCESS' if success else 'FAILURE',
                            'payload': message[:200],  # 최대 200자
                            'source_ip': source_ip,
                            'session_id': f"CW_{event.get('eventId', 'UNKNOWN')[:16]}"
                        })
                        break  # 한 이벤트당 하나의 공격 타입만

        return parsed_logs

    def export_to_llm_format(self, events: List[Dict], output_file: str):
        """LLM CTI 형식으로 내보내기"""
        parsed_logs = self.parse_security_logs(events)

        with open(output_file, 'w', encoding='utf-8') as f:
            f.write("# CloudWatch Logs - Exported for LLM CTI\n")
            f.write("# Format: TIMESTAMP | ATTACK_TYPE | STATUS | PAYLOAD | SOURCE_IP | SESSION_ID\n\n")

            for log in parsed_logs:
                line = f"{log['timestamp']} | {log['attack_type']} | {log['status']} | {log['payload']} | {log['source_ip']} | {log['session_id']}\n"
                f.write(line)

        print(f"✓ Exported {len(parsed_logs)} security events to {output_file}")
        return len(parsed_logs)

    def create_log_stream(self, log_group_name: str, stream_name: str):
        """로그 스트림 생성"""
        try:
            self.client.create_log_stream(
                logGroupName=log_group_name,
                logStreamName=stream_name
            )
            print(f"✓ Created log stream: {stream_name}")
            return True
        except self.client.exceptions.ResourceAlreadyExistsException:
            print(f"Log stream already exists: {stream_name}")
            return True
        except Exception as e:
            print(f"Error creating log stream: {e}")
            return False

    def send_analysis_result(
        self,
        log_group_name: str,
        stream_name: str,
        analysis_result: Dict[str, Any]
    ):
        """분석 결과를 CloudWatch로 전송"""
        try:
            # 스트림이 없으면 생성
            self.create_log_stream(log_group_name, stream_name)

            # 로그 메시지 준비
            message = json.dumps(analysis_result, ensure_ascii=False)

            # CloudWatch에 전송
            response = self.client.put_log_events(
                logGroupName=log_group_name,
                logStreamName=stream_name,
                logEvents=[
                    {
                        'timestamp': int(datetime.now().timestamp() * 1000),
                        'message': message
                    }
                ]
            )

            print(f"✓ Sent analysis result to CloudWatch")
            return True

        except Exception as e:
            print(f"Error sending to CloudWatch: {e}")
            return False


def setup_aws_credentials():
    """AWS 자격 증명 설정 가이드"""
    print("\n" + "=" * 80)
    print("AWS 자격 증명 설정")
    print("=" * 80)
    print("\n다음 방법 중 하나로 AWS 자격 증명을 설정하세요:\n")
    print("방법 1: AWS CLI 설정")
    print("  $ aws configure")
    print("  AWS Access Key ID: YOUR_ACCESS_KEY")
    print("  AWS Secret Access Key: YOUR_SECRET_KEY")
    print("  Default region name: ap-northeast-2")
    print()
    print("방법 2: 환경 변수 설정")
    print("  $ export AWS_ACCESS_KEY_ID=YOUR_ACCESS_KEY")
    print("  $ export AWS_SECRET_ACCESS_KEY=YOUR_SECRET_KEY")
    print("  $ export AWS_DEFAULT_REGION=ap-northeast-2")
    print()
    print("방법 3: IAM Role (EC2에서 실행 시)")
    print("  EC2 인스턴스에 CloudWatch Logs 읽기 권한이 있는 IAM Role 할당")
    print()


def main():
    import sys

    if len(sys.argv) < 2:
        print("Usage:")
        print("  List log groups:")
        print("    python cloudwatch_connector.py list-groups [prefix]")
        print()
        print("  List log streams:")
        print("    python cloudwatch_connector.py list-streams <log-group-name>")
        print()
        print("  Export logs:")
        print("    python cloudwatch_connector.py export <log-group-name> <output-file> [hours]")
        print()
        print("  Example:")
        print("    python cloudwatch_connector.py export /aws/lambda/security-function logs/cloudwatch.log 24")
        print()
        setup_aws_credentials()
        sys.exit(1)

    command = sys.argv[1]

    try:
        connector = CloudWatchConnector()

        if command == 'list-groups':
            prefix = sys.argv[2] if len(sys.argv) > 2 else ''
            log_groups = connector.list_log_groups(prefix)

            print(f"\nLog Groups ({len(log_groups)}):")
            for group in log_groups:
                print(f"  - {group}")

        elif command == 'list-streams':
            if len(sys.argv) < 3:
                print("Error: Please provide log group name")
                sys.exit(1)

            log_group = sys.argv[2]
            streams = connector.list_log_streams(log_group)

            print(f"\nLog Streams for {log_group} ({len(streams)}):")
            for stream in streams:
                print(f"  - {stream}")

        elif command == 'export':
            if len(sys.argv) < 4:
                print("Error: Please provide log group name and output file")
                sys.exit(1)

            log_group = sys.argv[2]
            output_file = sys.argv[3]
            hours = int(sys.argv[4]) if len(sys.argv) > 4 else 24

            print(f"\nFetching logs from CloudWatch...")
            print(f"  Log Group: {log_group}")
            print(f"  Time Range: Last {hours} hours")

            start_time = datetime.now() - timedelta(hours=hours)
            events = connector.get_log_events(
                log_group_name=log_group,
                start_time=start_time
            )

            print(f"  Retrieved: {len(events)} events")

            if events:
                connector.export_to_llm_format(events, output_file)
                print(f"\n✓ Logs exported successfully!")
                print(f"\nNext steps:")
                print(f"  python pipeline.py {output_file}")
            else:
                print("\n⚠ No events found in the specified time range")

    except Exception as e:
        print(f"\n✗ Error: {e}")
        print("\nAWS 자격 증명이 올바르게 설정되어 있는지 확인하세요.")
        setup_aws_credentials()
        sys.exit(1)


if __name__ == '__main__':
    main()
