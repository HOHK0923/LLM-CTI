# 2SeC SIEM + LLM 통합 보안 분석 시스템

DVWA 기반 공격 로그를 활용한 SIEM + SOAR + LLM 연동 보안 자동화 프로젝트

## 프로젝트 개요

본 프로젝트는 실제 공격 로그를 기반으로 하여:
- C 언어 기반 고성능 로그 파싱 엔진
- LLM 학습용 데이터셋 자동 생성
- RAG 기반 공격 패턴 분석
- SIEM 시스템 연동
- SOAR 자동 대응 시스템

을 통합하여 보안 분석을 자동화하는 전체 파이프라인을 구현합니다.

## 아키텍처

```
[공격 로그]
    ↓
[C 기반 로그 정제 엔진]
    ↓
[JSON 데이터셋]
    ↓
[RAG 분석] ← [Fine-tuned LLM]
    ↓
[SIEM 연동] → [SOAR 자동 대응]
```

## 디렉토리 구조

```
.
├── src/
│   ├── c_engine/          # C 기반 로그 파싱 엔진
│   │   ├── log_parser.h
│   │   ├── log_parser.c
│   │   ├── main.c
│   │   └── Makefile
│   └── python/
│       ├── dataset_builder.py          # 데이터셋 생성
│       ├── rag/
│       │   └── rag_analyzer.py         # RAG 기반 분석
│       ├── finetune/
│       │   └── prepare_finetune_data.py # Fine-tuning 데이터 준비
│       ├── siem/
│       │   └── siem_connector.py       # SIEM 연동
│       └── soar/
│           └── soar_orchestrator.py    # SOAR 자동 대응
├── data/
│   ├── raw_logs/          # 원본 공격 로그
│   ├── parsed_logs/       # 파싱된 JSON 로그
│   └── datasets/          # LLM 학습 데이터셋
├── config/                # 설정 파일
├── tests/                 # 테스트
└── docs/                  # 문서
```

## 설치 및 실행

### 1. C 로그 파싱 엔진 빌드

```bash
cd src/c_engine
make
```

### 2. Python 의존성 설치

```bash
pip install requests
```

### 3. 전체 파이프라인 실행

#### Step 1: 로그 파싱 (C 엔진)
```bash
cd src/c_engine
./log_parser ../../data/raw_logs/dvwa_attack.log ../../data/parsed_logs/attack.json
```

#### Step 2: 학습 데이터셋 생성
```bash
cd src/python
python dataset_builder.py ../data/parsed_logs/attack.json ../data/datasets/training.json
```

#### Step 3: Fine-tuning 데이터 준비
```bash
python finetune/prepare_finetune_data.py ../data/datasets/training.json ../data/datasets/finetune
```

#### Step 4: RAG 분석 실행
```bash
python rag/rag_analyzer.py ../data/datasets/training.json session_data.json report.json
```

#### Step 5: SIEM 연동 설정
```bash
python siem/siem_connector.py create-config ../config/siem_config.json
```

#### Step 6: SOAR 자동 대응
```bash
python soar/soar_orchestrator.py create-playbook SQL_INJECTION 8
```

## 주요 기능

### 1. C 기반 로그 파싱 엔진

- 고성능 텍스트 로그 파싱
- 공격 유형 자동 분류 (SQL Injection, XSS, Command Injection 등)
- 세션 단위 타임라인 생성
- JSON 형식 출력

**지원 공격 유형:**
- SQL_INJECTION
- XSS
- COMMAND_INJECTION
- FILE_INCLUSION
- BRUTE_FORCE
- CSRF

### 2. 데이터셋 빌더

- 세션별 공격 타임라인 분석
- 공격 단계 판별 (정찰/공격/데이터 탈취)
- 위험도 점수 계산
- LLM 학습용 instruction-response 형식 생성

### 3. RAG 기반 분석

- 벡터 데이터베이스 기반 유사 공격 패턴 검색
- 공격 지식 베이스 활용
- MITRE ATT&CK 프레임워크 매핑
- 상세 분석 리포트 생성

### 4. Fine-tuning 데이터 준비

**지원 형식:**
- Alpaca (LoRA fine-tuning)
- ChatML
- OpenAI JSONL
- LoRA 설정 자동 생성

### 5. SIEM 연동

**지원 SIEM:**
- Splunk (HEC)
- Elasticsearch (ELK Stack)
- Syslog

### 6. SOAR 자동 대응

**대응 액션:**
- IP 차단
- Rate Limiting
- SOC 팀 알림
- WAF 규칙 활성화
- 서버 격리
- 로그 모니터링 강화

## 사용 예제

### 로그 형식

```
2025-12-12 10:39:15 | SQL_INJECTION | SUCCESS | ' AND SLEEP(3) | 192.168.1.100 | SESSION_001
```

### 파싱 결과 (JSON)

```json
{
  "timestamp": "2025-12-12 10:39:15",
  "attack_type": "SQL_INJECTION",
  "success": true,
  "payload": "' AND SLEEP(3)",
  "source_ip": "192.168.1.100",
  "session_id": "SESSION_001",
  "severity": 8
}
```

### 학습 데이터 형식

```json
{
  "instruction": "다음은 보안 시스템에서 탐지된 공격 로그입니다...",
  "response": "### 공격 분석 결과\n**공격 단계**: EXPLOITATION\n...",
  "metadata": {
    "session_id": "SESSION_001",
    "risk_score": 8,
    "attack_types": ["SQL_INJECTION"]
  }
}
```

## 학습 전략

### 1. RAG 기반 분석
- 실시간 공격 패턴 검색
- 기존 사례 기반 분석

### 2. LoRA Fine-tuning
- 보안 도메인 특화 학습
- 효율적인 파라미터 업데이트

### 3. SIEM/SOAR 통합
- 자동 탐지 및 대응
- 보안 운영 자동화

## 기대 효과

- SIEM 자동 분석 및 대응
- 공격 타임라인 인식
- 보안 운영 효율성 향상
- 실무형 보안 + AI 역량 강화

## 라이센스

MIT License

## 기여자

2SeC Team

## 문의

프로젝트 관련 문의사항은 이슈를 통해 남겨주세요.
