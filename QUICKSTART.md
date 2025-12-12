# LLM CTI 빠른 시작 가이드

## 전체 파이프라인 실행 (한 줄 명령어)

```bash
python3 pipeline.py data/raw_logs/dvwa_attack.log
```

이 명령어 하나로 다음이 모두 실행됩니다:
1. C 엔진으로 로그 파싱
2. LLM 학습 데이터셋 생성
3. Fine-tuning 데이터 준비 (Alpaca, ChatML, OpenAI)
4. RAG 기반 공격 분석
5. SOAR 자동 대응 플레이북 생성

## 단계별 실행

### 1. C 로그 파싱 엔진 빌드

```bash
cd src/c_engine
make
```

### 2. 로그 파싱

```bash
./src/c_engine/log_parser data/raw_logs/dvwa_attack.log data/parsed_logs/attack.json
```

**출력**: `data/parsed_logs/attack.json` - 39개 공격 이벤트 파싱 완료

### 3. 학습 데이터셋 생성

```bash
python3 src/python/dataset_builder.py data/parsed_logs/attack.json data/datasets/training.json
```

**출력**: `data/datasets/training.json` - 12개 세션 분석, LLM 학습용 데이터 생성

### 4. Fine-tuning 데이터 준비

```bash
python3 src/python/finetune/prepare_finetune_data.py data/datasets/training.json data/datasets/finetune
```

**출력**:
- `data/datasets/finetune/alpaca_train.json` - Alpaca 형식 (LoRA)
- `data/datasets/finetune/chatml_train.json` - ChatML 형식
- `data/datasets/finetune/openai_train.jsonl` - OpenAI 형식
- `data/datasets/finetune/lora_config.json` - LoRA 설정
- `data/datasets/finetune/train_lora.py` - 학습 스크립트

### 5. RAG 분석 (선택사항)

```bash
python3 src/python/rag/rag_analyzer.py data/datasets/training.json session_data.json report.json
```

### 6. SOAR 플레이북 생성

```bash
# SQL Injection 공격에 대한 플레이북 (위험도 8)
python3 src/python/soar/soar_orchestrator.py create-playbook SQL_INJECTION 8
```

## 실행 결과

### 파싱 결과 예시
```json
{
  "timestamp": "2025-12-12 10:39:15",
  "attack_type": "SQL_INJECTION",
  "success": true,
  "payload": "' AND SLEEP(3)--",
  "source_ip": "192.168.1.100",
  "session_id": "SESSION_001",
  "severity": 8
}
```

### 학습 데이터 예시
```json
{
  "instruction": "다음은 보안 시스템에서 탐지된 공격 로그입니다...",
  "response": "### 공격 분석 결과\n**공격 단계**: RECONNAISSANCE\n**위험도 점수**: 10/10...",
  "metadata": {
    "session_id": "SESSION_001",
    "risk_score": 10,
    "attack_stage": "RECONNAISSANCE",
    "attack_types": ["SQL_INJECTION"]
  }
}
```

## 자신의 로그 사용하기

### 로그 형식
```
TIMESTAMP | ATTACK_TYPE | STATUS | PAYLOAD | SOURCE_IP | SESSION_ID
```

### 예제
```
2025-12-12 10:39:15 | SQL_INJECTION | SUCCESS | ' OR 1=1-- | 192.168.1.100 | SESSION_001
2025-12-12 10:40:23 | XSS | FAILURE | <script>alert(1)</script> | 192.168.1.101 | SESSION_002
```

### 지원 공격 유형
- `SQL_INJECTION`
- `XSS`
- `COMMAND_INJECTION`
- `FILE_INCLUSION`
- `BRUTE_FORCE`
- `CSRF`

### 실행
```bash
# 1. 로그 파일을 data/raw_logs/ 폴더에 넣기
cp your_attack.log data/raw_logs/

# 2. 파이프라인 실행
python3 pipeline.py data/raw_logs/your_attack.log
```

## LLM Fine-tuning 하기

### LoRA Fine-tuning (권장)

```bash
cd data/datasets/finetune

# 필요한 라이브러리 설치
pip install transformers peft datasets bitsandbytes accelerate

# Fine-tuning 실행 (GPU 필요)
python3 train_lora.py
```

### OpenAI API Fine-tuning

```bash
# OpenAI CLI 설치
pip install openai

# Fine-tuning 시작
openai api fine_tunes.create \
  -t data/datasets/finetune/openai_train.jsonl \
  -v data/datasets/finetune/openai_test.jsonl \
  --model gpt-3.5-turbo
```

## SIEM 연동하기

### 1. SIEM 설정 파일 생성

```bash
python3 src/python/siem/siem_connector.py create-config config/siem_config.json
```

### 2. 설정 파일 수정

`config/siem_config.json`에서 실제 SIEM 정보 입력:
- Splunk HEC URL 및 토큰
- Elasticsearch URL 및 인증 정보
- Syslog 서버 정보

### 3. 테스트

```bash
python3 src/python/siem/siem_connector.py test config/siem_config.json
```

## 출력 파일 구조

```
data/
├── raw_logs/
│   └── dvwa_attack.log              # 원본 로그
├── parsed_logs/
│   └── attack.json                  # 파싱된 JSON (39개 이벤트)
├── datasets/
│   ├── training.json                # 학습 데이터 (12개 세션)
│   └── finetune/
│       ├── alpaca_train.json        # Alpaca 형식 (10개)
│       ├── alpaca_test.json         # 테스트 데이터 (2개)
│       ├── chatml_train.json        # ChatML 형식
│       ├── openai_train.jsonl       # OpenAI 형식
│       ├── lora_config.json         # LoRA 설정
│       └── train_lora.py            # 학습 스크립트
└── analysis/
    └── analysis_SESSION_*.json      # RAG 분석 결과 (12개)
```

## 성능

- 전체 파이프라인: 약 1초 (39개 이벤트 기준)
- C 파싱 엔진: 초당 수천 개 로그 처리 가능
- 메모리 사용량: 최소

## 다음 단계

1. **더 많은 로그 수집**: attack-automation 도구로 실제 공격 로그 생성
2. **Fine-tuning 실행**: GPU 서버에서 LoRA fine-tuning
3. **SIEM 연동**: 실제 SIEM 시스템과 통합
4. **SOAR 자동화**: 실제 방화벽/WAF API와 연동

## 문제 해결

### C 컴파일 오류
```bash
# gcc 설치 확인
gcc --version

# 재빌드
cd src/c_engine
make clean
make
```

### Python 모듈 오류
```bash
# 기본 모듈만 사용 (추가 설치 불필요)
python3 --version  # Python 3.6 이상 필요
```

### 로그 파싱 실패
- 로그 형식이 올바른지 확인
- `|` 구분자로 필드가 분리되어 있는지 확인
- 주석 라인은 `#`으로 시작

## 지원

이슈나 질문은 GitHub Issues에 남겨주세요.
