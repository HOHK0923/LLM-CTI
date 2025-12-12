# 다음 단계 가이드

## 전체 워크플로우

```
[칼리 리눅스] 2SeChain 공격 실행
    ↓
[로그 생성] attack_*.log
    ↓
[AWS CloudWatch] 로그 업로드 (선택사항)
    ↓
[LLM CTI] 로그 분석 및 데이터셋 생성
    ↓
[Fine-tuning] LLM 학습
    ↓
[배포] 보안 분석 자동화
```

## Option 1: 로컬 파일 방식 (빠른 시작)

### 1단계: 칼리 리눅스에서 2SeChain 실행

```bash
# 칼리 리눅스에서
cd /path/to/attack-automation
python3 dvwa_attacker.py

# 로그 파일 생성됨: logs/attack_YYYYMMDD_HHMMSS.log
```

### 2단계: 로그 파일을 LLM CTI로 복사

```bash
# 로그 파일을 Mac으로 전송 (scp, USB 등)
scp kali@192.168.x.x:/path/to/attack-automation/logs/attack_*.log \
    ~/Desktop/22sec/LLM\ CTI/data/raw_logs/
```

### 3단계: LLM CTI 파이프라인 실행

```bash
cd ~/Desktop/22sec/LLM\ CTI
python3 pipeline.py data/raw_logs/attack_YYYYMMDD_HHMMSS.log
```

**결과**:
- 파싱된 로그, 학습 데이터셋, Fine-tuning 데이터 자동 생성
- 실행 시간: ~1초

---

## Option 2: AWS CloudWatch 연동 방식

### 1단계: 칼리 리눅스에서 CloudWatch로 로그 전송

#### AWS CLI 설치 및 설정

```bash
# 칼리 리눅스에서
sudo apt-get update
sudo apt-get install awscli -y

# AWS 자격 증명 설정
aws configure
# Access Key ID: YOUR_KEY
# Secret Access Key: YOUR_SECRET
# Region: ap-northeast-2 (서울)
```

#### CloudWatch 로그 그룹 생성

```bash
aws logs create-log-group --log-group-name /security/attack-logs
aws logs create-log-stream --log-group-name /security/attack-logs --log-stream-name attack-stream
```

#### 로그 전송 스크립트

```bash
# 칼리에서 2SeChain 실행 후 로그를 CloudWatch로 전송
LOG_FILE="logs/attack_$(date +%Y%m%d_%H%M%S).log"

# CloudWatch로 로그 업로드
aws logs put-log-events \
  --log-group-name /security/attack-logs \
  --log-stream-name attack-stream \
  --log-events file://<(cat $LOG_FILE | jq -R -s -c 'split("\n") | map(select(length > 0)) | map({timestamp: (now * 1000 | floor), message: .})')
```

### 2단계: Mac에서 CloudWatch 로그 다운로드

```bash
cd ~/Desktop/22sec/LLM\ CTI

# CloudWatch에서 로그 가져오기 (최근 24시간)
python3 src/python/cloudwatch/cloudwatch_connector.py export \
  /security/attack-logs \
  data/raw_logs/cloudwatch_logs.log \
  24
```

### 3단계: LLM CTI 파이프라인 실행

```bash
python3 pipeline.py data/raw_logs/cloudwatch_logs.log
```

---

## Fine-tuning 실행

### 준비사항
- GPU 서버 (NVIDIA GPU 권장)
- Python 3.8+
- CUDA 11.x+

### 라이브러리 설치

```bash
pip install torch torchvision torchaudio --index-url https://download.pytorch.org/whl/cu118
pip install transformers peft datasets bitsandbytes accelerate sentencepiece
```

### LoRA Fine-tuning 실행

```bash
cd data/datasets/finetune

# 학습 시작
python3 train_lora.py
```

**학습 설정** (lora_config.json):
- Base Model: llama-2-7b (또는 다른 모델)
- LoRA rank (r): 8
- Training epochs: 3
- Batch size: 4
- Learning rate: 2e-4

### OpenAI API Fine-tuning

```bash
# OpenAI CLI 설치
pip install openai

# Fine-tuning 시작
openai api fine_tunes.create \
  -t data/datasets/finetune/openai_train.jsonl \
  -v data/datasets/finetune/openai_test.jsonl \
  --model gpt-3.5-turbo \
  --n_epochs 3

# 진행 상황 확인
openai api fine_tunes.follow -i <FINE_TUNE_ID>
```

---

## 데이터 축적 전략

### 1. 반복적인 공격 실행

```bash
# 칼리 리눅스에서 주기적으로 실행
for i in {1..10}; do
  echo "Attack session $i"
  python3 dvwa_attacker.py --auto-attack
  sleep 300  # 5분 대기
done
```

### 2. 다양한 공격 시나리오

- SQL Injection (다양한 페이로드)
- XSS (Stored, Reflected, DOM)
- Command Injection
- File Upload
- Brute Force
- CSRF

### 3. 데이터셋 병합

```bash
# 여러 로그 파일을 하나로 병합
cat data/raw_logs/attack_*.log > data/raw_logs/combined.log

# 전체 파이프라인 실행
python3 pipeline.py data/raw_logs/combined.log
```

---

## 추천 워크플로우

### 초기 단계 (1-2주)
1. 칼리에서 2SeChain으로 100+ 공격 실행
2. 로그 파일 수집 (로컬 방식)
3. LLM CTI로 학습 데이터 생성
4. 작은 모델로 Fine-tuning 테스트

### 중급 단계 (2-4주)
1. CloudWatch 연동 설정
2. 자동화 스크립트 작성
3. 1000+ 공격 데이터 수집
4. 본격적인 Fine-tuning

### 고급 단계 (1-2개월)
1. 실제 환경 로그 통합
2. SIEM 시스템 연동
3. SOAR 자동 대응 구현
4. 프로덕션 배포

---

## 예상 데이터량

| 공격 횟수 | 로그 이벤트 | 학습 예제 | Fine-tuning 권장 |
|----------|------------|----------|-----------------|
| 10회     | ~100개     | ~10개    | ❌ 부족          |
| 100회    | ~1,000개   | ~100개   | ⚠️ 최소          |
| 1,000회  | ~10,000개  | ~1,000개 | ✅ 적정          |
| 10,000회 | ~100,000개 | ~10,000개| ✅✅ 이상적       |

**권장**: 최소 500-1000개 학습 예제 확보 후 Fine-tuning 시작

---

## 트러블슈팅

### Q: 로그 파일이 파싱되지 않아요
**A**: 로그 형식 확인
```bash
head -5 data/raw_logs/your_log.log
```
형식: `TIMESTAMP | ATTACK_TYPE | STATUS | PAYLOAD | SOURCE_IP | SESSION_ID`

### Q: CloudWatch 연동 실패
**A**: AWS 자격 증명 확인
```bash
aws sts get-caller-identity
aws logs describe-log-groups
```

### Q: Fine-tuning 메모리 부족
**A**: Batch size 줄이기
```json
"per_device_train_batch_size": 2  # 4 → 2로 변경
```

### Q: 학습 데이터가 너무 적어요
**A**:
1. 2SeChain 자동 실행 스크립트 사용
2. 기존 SIEM 로그 활용
3. 공개 데이터셋 추가

---

## 참고 자료

- **2SeChain (attack-automation)**: `/path/to/attack-automation/README.md`
- **LLM CTI**: `README.md`, `QUICKSTART.md`
- **AWS CloudWatch Logs**: https://docs.aws.amazon.com/cloudwatch/
- **LoRA Fine-tuning**: https://github.com/huggingface/peft

---

## 다음 질문?

- 특정 단계에서 막히는 부분이 있나요?
- 더 자세한 설명이 필요한 부분이 있나요?
- 자동화 스크립트가 필요하신가요?

언제든 문의하세요!
