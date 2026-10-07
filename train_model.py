import os
import joblib
import numpy as np
import pandas as pd
from sklearn.compose import ColumnTransformer
from sklearn.ensemble import RandomForestClassifier
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import MinMaxScaler, OneHotEncoder

# Define NSL-KDD Feature Schema
CATEGORICAL_FEATURES = ['protocol_type', 'service', 'flag']
NUMERICAL_FEATURES = [
    'duration', 'src_bytes', 'dst_bytes', 'land', 'wrong_fragment', 'urgent',
    'hot', 'num_failed_logins', 'logged_in', 'num_compromised', 'root_shell',
    'su_attempted', 'num_root', 'num_file_creations', 'num_shells',
    'num_access_files', 'num_outbound_cmds', 'is_host_login', 'is_guest_login',
    'count', 'srv_count', 'serror_rate', 'srv_serror_rate', 'rerror_rate',
    'srv_rerror_rate', 'same_srv_rate', 'diff_srv_rate', 'srv_diff_host_rate',
    'dst_host_count', 'dst_host_srv_count', 'dst_host_same_srv_rate',
    'dst_host_diff_srv_rate', 'dst_host_same_src_port_rate',
    'dst_host_srv_diff_host_rate', 'dst_host_serror_rate',
    'dst_host_srv_serror_rate', 'dst_host_rerror_rate', 'dst_host_srv_rerror_rate'
]

CLASSES = ['Normal', 'DoS', 'Probe', 'R2L', 'U2R']


def generate_synthetic_nsl_kdd(n_samples=2000, random_state=42):
    """Generates synthetic NSL-KDD data for training pipeline serialization."""
    np.random.seed(random_state)
    
    protocols = ['tcp', 'udp', 'icmp']
    services = ['http', 'private', 'smtp', 'ftp_data', 'domain_u', 'other', 'echo']
    flags = ['SF', 'S0', 'REJ', 'RSTO', 'SH', 'S1']
    
    data = {
        'protocol_type': np.random.choice(protocols, size=n_samples),
        'service': np.random.choice(services, size=n_samples),
        'flag': np.random.choice(flags, size=n_samples)
    }
    
    for col in NUMERICAL_FEATURES:
        if 'bytes' in col:
            data[col] = np.random.exponential(scale=1000, size=n_samples)
        elif 'rate' in col:
            data[col] = np.random.uniform(0.0, 1.0, size=n_samples)
        elif col in ['duration', 'count', 'srv_count', 'dst_host_count']:
            data[col] = np.random.randint(0, 100, size=n_samples)
        else:
            data[col] = np.random.binomial(n=1, p=0.1, size=n_samples)
            
    df = pd.DataFrame(data)
    labels = np.random.choice(CLASSES, size=n_samples, p=[0.53, 0.35, 0.09, 0.02, 0.01])
    return df, labels


def build_and_train_pipeline():
    """Builds ColumnTransformer preprocessing and Random Forest Classifier pipeline."""
    print("Generating NSL-KDD dataset...")
    X, y = generate_synthetic_nsl_kdd()
    
    preprocessor = ColumnTransformer(
        transformers=[
            ('cat', OneHotEncoder(handle_unknown='ignore', sparse_output=False), CATEGORICAL_FEATURES),
            ('num', MinMaxScaler(), NUMERICAL_FEATURES)
        ]
    )
    
    pipeline = Pipeline(steps=[
        ('preprocessor', preprocessor),
        ('classifier', RandomForestClassifier(
            n_estimators=100,
            max_depth=15,
            class_weight='balanced',
            random_state=42,
            n_jobs=-1
        ))
    ])
    
    print("Fitting Random Forest NIDS pipeline...")
    pipeline.fit(X, y)
    
    model_path = "nids_random_forest_pipeline.joblib"
    joblib.dump(pipeline, model_path)
    print(f"Successfully trained and serialized model pipeline to {model_path}!")
    return pipeline


if __name__ == "__main__":
    build_and_train_pipeline()
