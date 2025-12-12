#!/usr/bin/env python3
"""
Fine-tuning Data Preparation Script
Converts training dataset to various fine-tuning formats (Alpaca, ChatML, etc.)
"""

import json
import os
from typing import List, Dict, Any
from datetime import datetime


class FineTuneDataPreparator:
    """Prepare data for LLM fine-tuning"""

    def __init__(self):
        self.formats = ['alpaca', 'chatml', 'openai', 'jsonl']

    def load_training_data(self, file_path: str) -> List[Dict]:
        """Load training dataset"""
        with open(file_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        return data.get('training_data', [])

    def convert_to_alpaca(self, examples: List[Dict]) -> List[Dict]:
        """Convert to Alpaca format for LoRA fine-tuning"""
        alpaca_data = []

        for example in examples:
            alpaca_example = {
                'instruction': example['instruction'],
                'input': '',
                'output': example['response']
            }
            alpaca_data.append(alpaca_example)

        return alpaca_data

    def convert_to_chatml(self, examples: List[Dict]) -> List[Dict]:
        """Convert to ChatML format"""
        chatml_data = []

        for example in examples:
            chatml_example = {
                'messages': [
                    {
                        'role': 'system',
                        'content': '당신은 보안 전문가입니다. 공격 로그를 분석하고 적절한 대응 방안을 제시하는 역할을 수행합니다.'
                    },
                    {
                        'role': 'user',
                        'content': example['instruction']
                    },
                    {
                        'role': 'assistant',
                        'content': example['response']
                    }
                ]
            }
            chatml_data.append(chatml_example)

        return chatml_data

    def convert_to_openai(self, examples: List[Dict]) -> List[Dict]:
        """Convert to OpenAI fine-tuning format"""
        openai_data = []

        for example in examples:
            openai_example = {
                'messages': [
                    {
                        'role': 'system',
                        'content': '보안 로그 분석 및 대응 전문가'
                    },
                    {
                        'role': 'user',
                        'content': example['instruction']
                    },
                    {
                        'role': 'assistant',
                        'content': example['response']
                    }
                ]
            }
            openai_data.append(openai_example)

        return openai_data

    def convert_to_jsonl(self, data: List[Dict]) -> str:
        """Convert list of dicts to JSONL format"""
        lines = []
        for item in data:
            lines.append(json.dumps(item, ensure_ascii=False))
        return '\n'.join(lines)

    def create_lora_config(self, model_name: str = 'llama-2-7b') -> Dict:
        """Create LoRA configuration for fine-tuning"""
        config = {
            'base_model': model_name,
            'lora_config': {
                'r': 8,
                'lora_alpha': 16,
                'target_modules': ['q_proj', 'v_proj', 'k_proj', 'o_proj'],
                'lora_dropout': 0.05,
                'bias': 'none',
                'task_type': 'CAUSAL_LM'
            },
            'training_args': {
                'num_train_epochs': 3,
                'per_device_train_batch_size': 4,
                'gradient_accumulation_steps': 4,
                'learning_rate': 2e-4,
                'fp16': True,
                'logging_steps': 10,
                'save_steps': 100,
                'eval_steps': 100,
                'warmup_steps': 100,
                'max_grad_norm': 0.3,
                'weight_decay': 0.001,
                'optim': 'paged_adamw_32bit'
            },
            'dataset_config': {
                'max_seq_length': 2048,
                'dataset_text_field': 'text',
                'split': 'train'
            }
        }
        return config

    def split_train_test(self, data: List[Dict], test_ratio: float = 0.1) -> tuple:
        """Split data into train and test sets"""
        import random

        random.seed(42)
        shuffled = data.copy()
        random.shuffle(shuffled)

        split_idx = int(len(shuffled) * (1 - test_ratio))
        train_data = shuffled[:split_idx]
        test_data = shuffled[split_idx:]

        return train_data, test_data

    def prepare_all_formats(self, input_file: str, output_dir: str):
        """Prepare data in all supported formats"""
        print(f"Loading training data from: {input_file}")
        examples = self.load_training_data(input_file)
        print(f"Total examples: {len(examples)}")

        # Create output directory
        os.makedirs(output_dir, exist_ok=True)

        # Split into train/test
        train_data, test_data = self.split_train_test(examples)
        print(f"Train examples: {len(train_data)}")
        print(f"Test examples: {len(test_data)}")

        # Convert to Alpaca format
        print("\n[1/4] Converting to Alpaca format...")
        alpaca_train = self.convert_to_alpaca(train_data)
        alpaca_test = self.convert_to_alpaca(test_data)

        with open(f"{output_dir}/alpaca_train.json", 'w', encoding='utf-8') as f:
            json.dump(alpaca_train, f, ensure_ascii=False, indent=2)

        with open(f"{output_dir}/alpaca_test.json", 'w', encoding='utf-8') as f:
            json.dump(alpaca_test, f, ensure_ascii=False, indent=2)

        print(f"  ✓ Saved: {output_dir}/alpaca_train.json")
        print(f"  ✓ Saved: {output_dir}/alpaca_test.json")

        # Convert to ChatML format
        print("\n[2/4] Converting to ChatML format...")
        chatml_train = self.convert_to_chatml(train_data)
        chatml_test = self.convert_to_chatml(test_data)

        with open(f"{output_dir}/chatml_train.json", 'w', encoding='utf-8') as f:
            json.dump(chatml_train, f, ensure_ascii=False, indent=2)

        with open(f"{output_dir}/chatml_test.json", 'w', encoding='utf-8') as f:
            json.dump(chatml_test, f, ensure_ascii=False, indent=2)

        print(f"  ✓ Saved: {output_dir}/chatml_train.json")
        print(f"  ✓ Saved: {output_dir}/chatml_test.json")

        # Convert to OpenAI format (JSONL)
        print("\n[3/4] Converting to OpenAI format...")
        openai_train = self.convert_to_openai(train_data)
        openai_test = self.convert_to_openai(test_data)

        with open(f"{output_dir}/openai_train.jsonl", 'w', encoding='utf-8') as f:
            f.write(self.convert_to_jsonl(openai_train))

        with open(f"{output_dir}/openai_test.jsonl", 'w', encoding='utf-8') as f:
            f.write(self.convert_to_jsonl(openai_test))

        print(f"  ✓ Saved: {output_dir}/openai_train.jsonl")
        print(f"  ✓ Saved: {output_dir}/openai_test.jsonl")

        # Create LoRA config
        print("\n[4/4] Creating LoRA configuration...")
        lora_config = self.create_lora_config()

        with open(f"{output_dir}/lora_config.json", 'w', encoding='utf-8') as f:
            json.dump(lora_config, f, ensure_ascii=False, indent=2)

        print(f"  ✓ Saved: {output_dir}/lora_config.json")

        # Create metadata
        metadata = {
            'created_at': datetime.now().isoformat(),
            'total_examples': len(examples),
            'train_examples': len(train_data),
            'test_examples': len(test_data),
            'formats': ['alpaca', 'chatml', 'openai'],
            'files': {
                'alpaca': ['alpaca_train.json', 'alpaca_test.json'],
                'chatml': ['chatml_train.json', 'chatml_test.json'],
                'openai': ['openai_train.jsonl', 'openai_test.jsonl'],
                'config': ['lora_config.json']
            }
        }

        with open(f"{output_dir}/metadata.json", 'w', encoding='utf-8') as f:
            json.dump(metadata, f, ensure_ascii=False, indent=2)

        print(f"\n✓ All formats prepared successfully!")
        print(f"Output directory: {output_dir}")

    def create_training_script(self, output_dir: str):
        """Create sample training script for LoRA fine-tuning"""
        script = """#!/usr/bin/env python3
\"\"\"
Sample LoRA Fine-tuning Script
Requires: transformers, peft, datasets, bitsandbytes
\"\"\"

from transformers import (
    AutoModelForCausalLM,
    AutoTokenizer,
    TrainingArguments,
    Trainer
)
from peft import LoraConfig, get_peft_model, prepare_model_for_kbit_training
from datasets import load_dataset
import torch
import json

def load_config(config_path):
    with open(config_path, 'r') as f:
        return json.load(f)

def main():
    # Load configuration
    config = load_config('lora_config.json')

    # Load model and tokenizer
    print("Loading model...")
    model_name = config['base_model']

    model = AutoModelForCausalLM.from_pretrained(
        model_name,
        load_in_8bit=True,
        device_map='auto',
        torch_dtype=torch.float16
    )

    tokenizer = AutoTokenizer.from_pretrained(model_name)
    tokenizer.pad_token = tokenizer.eos_token

    # Prepare model for training
    model = prepare_model_for_kbit_training(model)

    # Configure LoRA
    lora_config = LoraConfig(**config['lora_config'])
    model = get_peft_model(model, lora_config)

    print("Model parameters:")
    model.print_trainable_parameters()

    # Load dataset
    print("Loading dataset...")
    dataset = load_dataset('json', data_files={
        'train': 'alpaca_train.json',
        'test': 'alpaca_test.json'
    })

    # Training arguments
    training_args = TrainingArguments(
        output_dir='./output',
        **config['training_args']
    )

    # Create trainer
    trainer = Trainer(
        model=model,
        args=training_args,
        train_dataset=dataset['train'],
        eval_dataset=dataset['test']
    )

    # Train
    print("Starting training...")
    trainer.train()

    # Save model
    print("Saving model...")
    model.save_pretrained('./output/final_model')
    tokenizer.save_pretrained('./output/final_model')

    print("Training complete!")

if __name__ == '__main__':
    main()
"""

        with open(f"{output_dir}/train_lora.py", 'w', encoding='utf-8') as f:
            f.write(script)

        print(f"  ✓ Created training script: {output_dir}/train_lora.py")


def main():
    import sys

    if len(sys.argv) < 3:
        print("Usage: python prepare_finetune_data.py <training_dataset> <output_directory>")
        print("Example: python prepare_finetune_data.py ../../data/datasets/training.json ../../data/datasets/finetune")
        sys.exit(1)

    input_file = sys.argv[1]
    output_dir = sys.argv[2]

    preparator = FineTuneDataPreparator()
    preparator.prepare_all_formats(input_file, output_dir)
    preparator.create_training_script(output_dir)


if __name__ == '__main__':
    main()
