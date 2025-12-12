#!/usr/bin/env python3
"""
Attack-Automation과 LLM CTI 통합 스크립트
실제 공격 로그를 생성하고 자동으로 분석 파이프라인 실행
"""

import os
import sys
import subprocess
import json
from datetime import datetime
import re


class AttackLogIntegrator:
    """attack-automation 로그를 LLM CTI 형식으로 변환"""

    def __init__(self, attack_automation_path: str):
        self.attack_automation_path = attack_automation_path
        self.attack_log_dir = os.path.join(attack_automation_path, "logs")

    def find_latest_log(self) -> str:
        """가장 최신 attack 로그 찾기"""
        log_files = []

        if os.path.exists(self.attack_log_dir):
            for file in os.listdir(self.attack_log_dir):
                if file.endswith('.log'):
                    full_path = os.path.join(self.attack_log_dir, file)
                    log_files.append((full_path, os.path.getmtime(full_path)))

        # 현재 디렉토리의 로그도 확인
        for file in os.listdir('.'):
            if file.startswith('attack_') and file.endswith('.log'):
                full_path = os.path.join('.', file)
                log_files.append((full_path, os.path.getmtime(full_path)))

        if not log_files:
            return None

        # 가장 최신 파일 반환
        log_files.sort(key=lambda x: x[1], reverse=True)
        return log_files[0][0]

    def convert_log_format(self, input_log: str, output_log: str) -> bool:
        """attack-automation 로그를 LLM CTI 형식으로 변환"""
        print(f"Converting log format...")
        print(f"  Input: {input_log}")
        print(f"  Output: {output_log}")

        try:
            with open(input_log, 'r', encoding='utf-8') as f:
                content = f.read()

            # 로그 파싱 (attack-automation 형식에 맞게)
            converted_lines = []
            session_counter = {}

            # 각 라인 파싱
            for line in content.split('\n'):
                if not line.strip() or line.startswith('#'):
                    continue

                # attack-automation 로그 형식 파싱 시도
                # 예: [2025-12-12 10:35:12] [SQL_INJECTION] [SUCCESS] Payload: ' OR '1'='1
                match = re.match(r'\[([^\]]+)\]\s*\[([^\]]+)\]\s*\[([^\]]+)\]\s*(?:Payload:|Target:|Attack:)?\s*(.+)', line)

                if match:
                    timestamp = match.group(1)
                    attack_type = match.group(2).upper().replace(' ', '_')
                    status = match.group(3).upper()
                    payload = match.group(4).strip()

                    # IP 추출 (없으면 기본값)
                    ip_match = re.search(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b', payload)
                    source_ip = ip_match.group(1) if ip_match else "192.168.1.100"

                    # 세션 ID 생성
                    session_key = f"{source_ip}_{attack_type}"
                    if session_key not in session_counter:
                        session_counter[session_key] = len(session_counter) + 1
                    session_id = f"SESSION_{session_counter[session_key]:03d}"

                    # LLM CTI 형식으로 변환
                    # TIMESTAMP | ATTACK_TYPE | STATUS | PAYLOAD | SOURCE_IP | SESSION_ID
                    converted_line = f"{timestamp} | {attack_type} | {status} | {payload} | {source_ip} | {session_id}"
                    converted_lines.append(converted_line)

            if not converted_lines:
                print("  Warning: No logs converted. Trying alternative parsing...")
                # 대체 파싱: 단순 텍스트 로그
                return self._copy_as_is(input_log, output_log)

            # 변환된 로그 저장
            with open(output_log, 'w', encoding='utf-8') as f:
                f.write("# Converted from attack-automation logs\n")
                f.write("# Format: TIMESTAMP | ATTACK_TYPE | STATUS | PAYLOAD | SOURCE_IP | SESSION_ID\n\n")
                f.write('\n'.join(converted_lines))

            print(f"  ✓ Converted {len(converted_lines)} log entries")
            return True

        except Exception as e:
            print(f"  ✗ Error converting log: {e}")
            return False

    def _copy_as_is(self, input_log: str, output_log: str) -> bool:
        """로그를 그대로 복사 (이미 올바른 형식인 경우)"""
        try:
            with open(input_log, 'r') as f:
                content = f.read()

            with open(output_log, 'w') as f:
                f.write(content)

            print(f"  ✓ Copied log file as-is")
            return True
        except Exception as e:
            print(f"  ✗ Error copying log: {e}")
            return False


def run_attack_automation(attack_path: str) -> str:
    """attack-automation 실행하여 로그 생성"""
    print("=" * 80)
    print("STEP 1: Running attack-automation to generate logs")
    print("=" * 80)

    os.chdir(attack_path)

    print("\nattack-automation 도구로 공격을 실행하세요.")
    print("예시:")
    print("  python3 dvwa_attacker.py")
    print("\n또는 이미 생성된 로그 파일이 있다면 엔터를 눌러 계속하세요.")

    input("\nPress Enter to continue...")

    # 최신 로그 찾기
    integrator = AttackLogIntegrator(attack_path)
    latest_log = integrator.find_latest_log()

    if latest_log:
        print(f"\n✓ Found log file: {latest_log}")
        return latest_log
    else:
        print("\n✗ No log files found!")
        return None


def run_llm_cti_pipeline(log_file: str, cti_path: str) -> bool:
    """LLM CTI 파이프라인 실행"""
    print("\n" + "=" * 80)
    print("STEP 2: Converting log format for LLM CTI")
    print("=" * 80)

    os.chdir(cti_path)

    # 로그 변환
    integrator = AttackLogIntegrator(os.path.dirname(log_file))
    output_log = f"data/raw_logs/attack_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"

    if not integrator.convert_log_format(log_file, output_log):
        print("Failed to convert log format")
        return False

    print("\n" + "=" * 80)
    print("STEP 3: Running LLM CTI Analysis Pipeline")
    print("=" * 80)

    # 파이프라인 실행
    cmd = ['python3', 'pipeline.py', output_log]
    result = subprocess.run(cmd)

    return result.returncode == 0


def main():
    print("\n" + "=" * 80)
    print("Attack-Automation + LLM CTI Integration")
    print("=" * 80)
    print("\n이 스크립트는 다음을 자동으로 수행합니다:")
    print("1. attack-automation으로 실제 공격 실행 및 로그 생성")
    print("2. 로그 형식을 LLM CTI 형식으로 변환")
    print("3. LLM CTI 분석 파이프라인 실행")
    print("4. Fine-tuning 데이터 생성\n")

    # 경로 설정
    base_path = "/Users/hwangjunha/Desktop/22sec"
    attack_automation_path = os.path.join(base_path, "attack-automation")
    llm_cti_path = os.path.join(base_path, "LLM CTI")

    if not os.path.exists(attack_automation_path):
        print(f"Error: attack-automation not found at {attack_automation_path}")
        sys.exit(1)

    if not os.path.exists(llm_cti_path):
        print(f"Error: LLM CTI not found at {llm_cti_path}")
        sys.exit(1)

    # Step 1: attack-automation 실행
    log_file = run_attack_automation(attack_automation_path)

    if not log_file:
        print("\nNo log file available. Exiting...")
        sys.exit(1)

    # Step 2 & 3: LLM CTI 파이프라인 실행
    success = run_llm_cti_pipeline(log_file, llm_cti_path)

    if success:
        print("\n" + "=" * 80)
        print("INTEGRATION COMPLETED SUCCESSFULLY!")
        print("=" * 80)
        print("\n생성된 파일:")
        print("  - 파싱된 로그: data/parsed_logs/")
        print("  - 학습 데이터: data/datasets/training.json")
        print("  - Fine-tuning 데이터: data/datasets/finetune/")
        print("\n다음 단계:")
        print("  1. data/datasets/finetune/ 에서 학습 데이터 확인")
        print("  2. GPU 서버에서 Fine-tuning 실행")
        print("  3. 더 많은 공격 로그 수집하여 반복\n")
    else:
        print("\n" + "=" * 80)
        print("INTEGRATION FAILED")
        print("=" * 80)
        sys.exit(1)


if __name__ == '__main__':
    main()
