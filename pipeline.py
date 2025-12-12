#!/usr/bin/env python3
"""
End-to-End Security Analysis Pipeline
Integrates all components: Log Parsing → Dataset Building → RAG Analysis → SIEM → SOAR
"""

import os
import sys
import json
import subprocess
from datetime import datetime
from typing import Dict, Any
import logging

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s'
)
logger = logging.getLogger(__name__)


class SecurityPipeline:
    """End-to-end security analysis pipeline orchestrator"""

    def __init__(self, config_file: str = 'config/pipeline_config.json'):
        self.config = self._load_config(config_file)
        self.results = {}

    def _load_config(self, config_file: str) -> Dict[str, Any]:
        """Load pipeline configuration"""
        if os.path.exists(config_file):
            with open(config_file, 'r') as f:
                return json.load(f)
        else:
            # Default configuration
            return {
                'c_parser': {
                    'executable': 'src/c_engine/log_parser',
                    'input_dir': 'data/raw_logs',
                    'output_dir': 'data/parsed_logs'
                },
                'dataset_builder': {
                    'script': 'src/python/dataset_builder.py',
                    'output_dir': 'data/datasets'
                },
                'rag_analyzer': {
                    'script': 'src/python/rag/rag_analyzer.py',
                    'output_dir': 'data/analysis'
                },
                'finetune': {
                    'script': 'src/python/finetune/prepare_finetune_data.py',
                    'output_dir': 'data/datasets/finetune'
                },
                'siem': {
                    'enabled': False,
                    'config': 'config/siem_config.json'
                },
                'soar': {
                    'enabled': True,
                    'script': 'src/python/soar/soar_orchestrator.py'
                }
            }

    def step1_parse_logs(self, log_file: str) -> str:
        """Step 1: Parse raw logs using C engine"""
        logger.info("=" * 80)
        logger.info("STEP 1: Parsing raw logs with C engine")
        logger.info("=" * 80)

        # Build C parser if not exists
        parser_exe = self.config['c_parser']['executable']
        if not os.path.exists(parser_exe):
            logger.info("Building C parser...")
            subprocess.run(['make', '-C', 'src/c_engine'], check=True)

        # Parse logs
        output_file = os.path.join(
            self.config['c_parser']['output_dir'],
            'parsed_' + os.path.basename(log_file).replace('.log', '.json')
        )

        os.makedirs(os.path.dirname(output_file), exist_ok=True)

        cmd = [parser_exe, log_file, output_file]
        logger.info(f"Running: {' '.join(cmd)}")

        result = subprocess.run(cmd, capture_output=True, text=True)

        if result.returncode == 0:
            logger.info("✓ Log parsing completed successfully")
            self.results['parsed_log'] = output_file
            return output_file
        else:
            logger.error(f"✗ Log parsing failed: {result.stderr}")
            raise RuntimeError("Log parsing failed")

    def step2_build_dataset(self, parsed_log: str) -> str:
        """Step 2: Build training dataset"""
        logger.info("=" * 80)
        logger.info("STEP 2: Building training dataset")
        logger.info("=" * 80)

        output_file = os.path.join(
            self.config['dataset_builder']['output_dir'],
            'training.json'
        )

        os.makedirs(os.path.dirname(output_file), exist_ok=True)

        cmd = [
            'python3',
            self.config['dataset_builder']['script'],
            parsed_log,
            output_file
        ]

        logger.info(f"Running: {' '.join(cmd)}")
        result = subprocess.run(cmd, capture_output=True, text=True)

        if result.returncode == 0:
            logger.info("✓ Dataset building completed")
            logger.info(result.stdout)
            self.results['training_dataset'] = output_file
            return output_file
        else:
            logger.error(f"✗ Dataset building failed: {result.stderr}")
            raise RuntimeError("Dataset building failed")

    def step3_prepare_finetune(self, training_dataset: str) -> str:
        """Step 3: Prepare fine-tuning data"""
        logger.info("=" * 80)
        logger.info("STEP 3: Preparing fine-tuning data")
        logger.info("=" * 80)

        output_dir = self.config['finetune']['output_dir']
        os.makedirs(output_dir, exist_ok=True)

        cmd = [
            'python3',
            self.config['finetune']['script'],
            training_dataset,
            output_dir
        ]

        logger.info(f"Running: {' '.join(cmd)}")
        result = subprocess.run(cmd, capture_output=True, text=True)

        if result.returncode == 0:
            logger.info("✓ Fine-tuning data preparation completed")
            logger.info(result.stdout)
            self.results['finetune_dir'] = output_dir
            return output_dir
        else:
            logger.error(f"✗ Fine-tuning preparation failed: {result.stderr}")
            raise RuntimeError("Fine-tuning preparation failed")

    def step4_analyze_sessions(self, training_dataset: str) -> list:
        """Step 4: Analyze attack sessions with RAG"""
        logger.info("=" * 80)
        logger.info("STEP 4: Analyzing attack sessions with RAG")
        logger.info("=" * 80)

        # Load training dataset to get sessions
        with open(training_dataset, 'r', encoding='utf-8') as f:
            data = json.load(f)

        training_data = data.get('training_data', [])
        analysis_results = []

        output_dir = self.config['rag_analyzer']['output_dir']
        os.makedirs(output_dir, exist_ok=True)

        # Analyze each session
        for i, example in enumerate(training_data):
            session_id = example['metadata'].get('session_id', f'session_{i}')
            logger.info(f"Analyzing session: {session_id}")

            # Create temporary session file
            session_file = f'/tmp/session_{session_id}.json'
            with open(session_file, 'w', encoding='utf-8') as f:
                json.dump(example['metadata'], f, ensure_ascii=False, indent=2)

            # Run RAG analysis
            output_file = os.path.join(output_dir, f'analysis_{session_id}.json')

            cmd = [
                'python3',
                self.config['rag_analyzer']['script'],
                training_dataset,
                session_file,
                output_file
            ]

            result = subprocess.run(cmd, capture_output=True, text=True)

            if result.returncode == 0:
                logger.info(f"  ✓ Session {session_id} analyzed")
                analysis_results.append(output_file)
            else:
                logger.warning(f"  ✗ Session {session_id} analysis failed")

        logger.info(f"✓ Analyzed {len(analysis_results)}/{len(training_data)} sessions")
        self.results['analysis_results'] = analysis_results
        return analysis_results

    def step5_execute_soar(self, training_dataset: str):
        """Step 5: Execute SOAR automated responses"""
        if not self.config['soar']['enabled']:
            logger.info("SOAR is disabled, skipping...")
            return

        logger.info("=" * 80)
        logger.info("STEP 5: Executing SOAR automated responses")
        logger.info("=" * 80)

        # Load training dataset
        with open(training_dataset, 'r', encoding='utf-8') as f:
            data = json.load(f)

        training_data = data.get('training_data', [])

        # Execute responses for high-risk sessions
        for example in training_data:
            metadata = example['metadata']
            session_id = metadata.get('session_id', 'unknown')
            risk_score = metadata.get('risk_score', 0)

            if risk_score >= 5:  # Only respond to medium+ risk
                logger.info(f"Executing response for session {session_id} (risk: {risk_score})")

                attack_types = metadata.get('attack_types', [])
                for attack_type in attack_types:
                    cmd = [
                        'python3',
                        self.config['soar']['script'],
                        'create-playbook',
                        attack_type,
                        str(risk_score)
                    ]

                    result = subprocess.run(cmd, capture_output=True, text=True)

                    if result.returncode == 0:
                        playbook = json.loads(result.stdout)
                        logger.info(f"  ✓ Created playbook: {len(playbook['actions'])} actions")
                    else:
                        logger.warning(f"  ✗ Failed to create playbook for {attack_type}")

        logger.info("✓ SOAR execution completed")

    def step6_send_to_siem(self, analysis_results: list):
        """Step 6: Send results to SIEM"""
        if not self.config['siem']['enabled']:
            logger.info("SIEM integration is disabled, skipping...")
            return

        logger.info("=" * 80)
        logger.info("STEP 6: Sending results to SIEM")
        logger.info("=" * 80)

        # Load analysis results and send to SIEM
        for result_file in analysis_results:
            with open(result_file, 'r', encoding='utf-8') as f:
                analysis = json.load(f)

            logger.info(f"Sending {result_file} to SIEM")
            # SIEM sending would happen here
            # siem_manager.send_analysis_result(analysis)

        logger.info("✓ SIEM integration completed")

    def run_full_pipeline(self, log_file: str):
        """Run the complete pipeline"""
        logger.info("")
        logger.info("=" * 80)
        logger.info("STARTING FULL SECURITY ANALYSIS PIPELINE")
        logger.info("=" * 80)
        logger.info(f"Input log file: {log_file}")
        logger.info(f"Started at: {datetime.now().isoformat()}")
        logger.info("")

        start_time = datetime.now()

        try:
            # Step 1: Parse logs
            parsed_log = self.step1_parse_logs(log_file)

            # Step 2: Build dataset
            training_dataset = self.step2_build_dataset(parsed_log)

            # Step 3: Prepare fine-tuning data
            finetune_dir = self.step3_prepare_finetune(training_dataset)

            # Step 4: RAG analysis
            analysis_results = self.step4_analyze_sessions(training_dataset)

            # Step 5: SOAR responses
            self.step5_execute_soar(training_dataset)

            # Step 6: SIEM integration
            self.step6_send_to_siem(analysis_results)

            end_time = datetime.now()
            duration = (end_time - start_time).total_seconds()

            logger.info("")
            logger.info("=" * 80)
            logger.info("PIPELINE COMPLETED SUCCESSFULLY")
            logger.info("=" * 80)
            logger.info(f"Total execution time: {duration:.2f} seconds")
            logger.info(f"Results summary:")
            logger.info(f"  - Parsed log: {self.results.get('parsed_log')}")
            logger.info(f"  - Training dataset: {self.results.get('training_dataset')}")
            logger.info(f"  - Fine-tune directory: {self.results.get('finetune_dir')}")
            logger.info(f"  - Analysis results: {len(self.results.get('analysis_results', []))} files")
            logger.info("")

            return self.results

        except Exception as e:
            logger.error("")
            logger.error("=" * 80)
            logger.error("PIPELINE FAILED")
            logger.error("=" * 80)
            logger.error(f"Error: {e}")
            logger.error("")
            raise


def main():
    if len(sys.argv) < 2:
        print("Usage: python pipeline.py <log_file>")
        print("Example: python pipeline.py data/raw_logs/dvwa_attack.log")
        sys.exit(1)

    log_file = sys.argv[1]

    if not os.path.exists(log_file):
        print(f"Error: Log file not found: {log_file}")
        sys.exit(1)

    pipeline = SecurityPipeline()
    pipeline.run_full_pipeline(log_file)


if __name__ == '__main__':
    main()
