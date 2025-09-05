#!/usr/bin/env python3
"""
Simplified Pickle File Merger for Shadow WF Processing with Consistent Labeling

This script merges individual simulation pickle files that already use consistent
labeling (via reference labels) into final training datasets.

Author: Claude
Date: 2025
"""

import pickle
import argparse
import numpy as np
from pathlib import Path
from collections import defaultdict, Counter
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class ConsistentLabelMerger:
    def __init__(self, input_dir: str, output_dir: str):
        self.input_dir = Path(input_dir)
        self.output_dir = Path(output_dir)
        
    def _verify_label_consistency(self, all_labels_data: list) -> dict:
        """Verify that all simulation files use consistent labeling"""
        
        if not all_labels_data:
            logger.error("No label data found")
            return {}
        
        # Use the first simulation's labels as reference
        reference_labels = all_labels_data[0]
        reference_url_to_label = reference_labels['url_to_label']
        reference_label_to_url = reference_labels['label_to_url']
        
        logger.info(f"Using reference labeling with {len(reference_url_to_label)} URLs")
        
        # Verify consistency across all simulations
        inconsistencies = []
        all_urls = set()
        
        for i, labels_data in enumerate(all_labels_data):
            url_to_label = labels_data['url_to_label']
            all_urls.update(url_to_label.keys())
            
            # Check for label inconsistencies
            for url, label in url_to_label.items():
                if url in reference_url_to_label:
                    if reference_url_to_label[url] != label:
                        inconsistencies.append(f"Simulation {i}: URL '{url}' has label {label}, expected {reference_url_to_label[url]}")
        
        if inconsistencies:
            logger.warning("Label inconsistencies found:")
            for issue in inconsistencies[:10]:  # Show first 10
                logger.warning(f"  {issue}")
            if len(inconsistencies) > 10:
                logger.warning(f"  ... and {len(inconsistencies) - 10} more")
        else:
            logger.info("✅ All simulations use consistent labeling")
        
        # Create final consolidated label mapping
        final_url_to_label = {}
        final_label_to_url = {}
        
        # Start with reference labels
        final_url_to_label.update(reference_url_to_label)
        final_label_to_url.update(reference_label_to_url)
        
        # Add any new URLs found in other simulations
        next_label = max(reference_label_to_url.keys()) + 1 if reference_label_to_url else 0
        
        for url in all_urls:
            if url not in final_url_to_label:
                final_url_to_label[url] = next_label
                final_label_to_url[next_label] = url
                logger.info(f"Added new URL '{url}' with label {next_label}")
                next_label += 1
        
        return {
            'url_to_label': final_url_to_label,
            'label_to_url': final_label_to_url
        }
    
    def _split_data(self, X: np.ndarray, y: np.ndarray, 
                   train_ratio: float = 0.7, val_ratio: float = 0.15, test_ratio: float = 0.15):
        """Split data into train/validation/test sets with stratification"""
        assert abs(train_ratio + val_ratio + test_ratio - 1.0) < 1e-6, "Ratios must sum to 1"
        
        n_samples = len(X)
        
        # Create stratified split to ensure balanced representation
        from collections import defaultdict
        
        # Group indices by label
        label_indices = defaultdict(list)
        for i, label in enumerate(y):
            label_indices[label].append(i)
        
        train_indices = []
        val_indices = []
        test_indices = []
        
        # Split each label proportionally
        for label, indices in label_indices.items():
            np.random.shuffle(indices)
            
            n_label = len(indices)
            train_end = int(train_ratio * n_label)
            val_end = int((train_ratio + val_ratio) * n_label)
            
            train_indices.extend(indices[:train_end])
            val_indices.extend(indices[train_end:val_end])
            test_indices.extend(indices[val_end:])
        
        # Shuffle the final indices
        np.random.shuffle(train_indices)
        np.random.shuffle(val_indices)
        np.random.shuffle(test_indices)
        
        return (X[train_indices], X[val_indices], X[test_indices],
                y[train_indices], y[val_indices], y[test_indices])
    
    def _save_dataset(self, X_train, X_val, X_test, y_train, y_val, y_test,
                     output_dir: Path, dataset_name: str, final_labels: dict):
        """Save final dataset in required format"""
        output_dir.mkdir(parents=True, exist_ok=True)
        
        # Save training data
        with open(output_dir / f"X_train_{dataset_name}.pkl", 'wb') as f:
            pickle.dump(X_train, f)
        with open(output_dir / f"y_train_{dataset_name}.pkl", 'wb') as f:
            pickle.dump(y_train, f)
        
        # Save validation data (note: using 'val' not 'valid' for consistency)
        with open(output_dir / f"X_valid_{dataset_name}.pkl", 'wb') as f:
            pickle.dump(X_val, f)
        with open(output_dir / f"y_valid_{dataset_name}.pkl", 'wb') as f:
            pickle.dump(y_val, f)
        
        # Save test data
        with open(output_dir / f"X_test_{dataset_name}.pkl", 'wb') as f:
            pickle.dump(X_test, f)
        with open(output_dir / f"y_test_{dataset_name}.pkl", 'wb') as f:
            pickle.dump(y_test, f)
        
        # Save label mapping
        with open(output_dir / f"url_labels_{dataset_name}.pkl", 'wb') as f:
            pickle.dump(final_labels, f)
        
        logger.info(f"Saved dataset to {output_dir}")
        logger.info(f"Train: {len(X_train)}, Val: {len(X_val)}, Test: {len(X_test)}")
        logger.info(f"Number of classes: {len(final_labels['url_to_label'])}")
        
        # Show label distribution
        train_label_counts = Counter(y_train)
        logger.info(f"Training samples per class: min={min(train_label_counts.values())}, "
                   f"max={max(train_label_counts.values())}, "
                   f"avg={len(y_train)/len(train_label_counts):.1f}")
        
        # Log sample URLs
        sample_urls = list(final_labels['label_to_url'].values())[:10]
        logger.info(f"Sample URLs: {sample_urls}")
    
    def merge_all_simulations(self):
        """Merge all simulations with consistent labeling"""
        logger.info("Merging all simulations with consistent labeling")
        
        # Find all simulation files
        x_files = list(self.input_dir.glob("X_*.pkl"))
        sim_names = [f.name[2:-4] for f in x_files]  # Remove 'X_' and '.pkl'
        
        if not sim_names:
            logger.error(f"No simulation files found in {self.input_dir}")
            return
        
        logger.info(f"Found {len(sim_names)} simulations to merge: {sim_names}")
        
        all_X = []
        all_y = []
        all_labels_data = []
        
        # Load all simulations
        for sim_name in sim_names:
            try:
                X_file = self.input_dir / f"X_{sim_name}.pkl"
                y_file = self.input_dir / f"y_{sim_name}.pkl"
                labels_file = self.input_dir / f"labels_{sim_name}.pkl"
                
                if not all([X_file.exists(), y_file.exists(), labels_file.exists()]):
                    logger.warning(f"Missing files for {sim_name}, skipping...")
                    continue
                
                with open(X_file, 'rb') as f:
                    X_sim = pickle.load(f)
                with open(y_file, 'rb') as f:
                    y_sim = pickle.load(f)
                with open(labels_file, 'rb') as f:
                    labels_sim = pickle.load(f)
                
                logger.info(f"Loaded {sim_name}: {len(X_sim)} sequences, "
                           f"{len(labels_sim['url_to_label'])} unique URLs")
                
                # Since labels are consistent, no remapping needed
                all_X.append(X_sim)
                all_y.append(y_sim)
                all_labels_data.append(labels_sim)
                
            except Exception as e:
                logger.error(f"Error loading {sim_name}: {e}")
                continue
        
        if not all_X:
            logger.error("No valid data found")
            return
        
        # Verify label consistency and create final mapping
        final_labels = self._verify_label_consistency(all_labels_data)
        
        if not final_labels:
            logger.error("Could not create consistent label mapping")
            return
        
        # Combine data (no label remapping needed due to consistency)
        X_combined = np.vstack(all_X)
        y_combined = np.hstack(all_y)
        
        logger.info(f"Combined data: {len(X_combined)} total sequences, "
                   f"{len(final_labels['url_to_label'])} classes")
        
        # Verify combined labels are within expected range
        unique_labels = np.unique(y_combined)
        max_expected_label = len(final_labels['url_to_label']) - 1
        
        if np.max(unique_labels) > max_expected_label:
            logger.error(f"Label {np.max(unique_labels)} exceeds expected maximum {max_expected_label}")
            return
        
        logger.info(f"✅ Label verification passed: labels 0-{np.max(unique_labels)}")
        
        # Split and save
        X_train, X_val, X_test, y_train, y_val, y_test = self._split_data(X_combined, y_combined)
        
        output_dir = self.output_dir / "ClosedWorld"
        self._save_dataset(X_train, X_val, X_test, y_train, y_val, y_test,
                          output_dir, "NoDef", final_labels)


def main():
    parser = argparse.ArgumentParser(description='Merge Shadow WF pickle files with consistent labeling')
    parser.add_argument('input_dir', help='Directory containing individual simulation pickle files')
    parser.add_argument('output_dir', help='Output directory for final datasets')
    parser.add_argument('--seed', type=int, default=42,
                        help='Random seed for reproducibility')
    parser.add_argument('--verbose', action='store_true',
                        help='Enable verbose logging')
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # Set random seed
    np.random.seed(args.seed)
    
    # Initialize merger
    merger = ConsistentLabelMerger(args.input_dir, args.output_dir)
    
    merger.merge_all_simulations()
    
    logger.info("Merging complete!")


if __name__ == "__main__":
    main()