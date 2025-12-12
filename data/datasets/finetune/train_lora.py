#!/usr/bin/env python3
"""
Sample LoRA Fine-tuning Script
Requires: transformers, peft, datasets, bitsandbytes
"""

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
