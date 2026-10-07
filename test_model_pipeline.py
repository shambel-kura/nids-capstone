import os
import time
import joblib
import pandas as pd

MODEL_PATH = "nids_random_forest_pipeline.joblib"

def test_model_artifact_exists():
    """Verifies that the trained model pipeline artifact exists."""
    assert os.path.exists(MODEL_PATH), f"Model artifact {MODEL_PATH} does not exist!"
    print("✓ Model artifact test passed.")

def test_pipeline_loading_and_schema():
    """Verifies model loading, input schema validation, and prediction output format."""
    pipeline = joblib.load(MODEL_PATH)
    assert pipeline is not None
    
    sample_data = {
        'protocol_type': ['tcp', 'udp'],
        'service': ['http', 'private'],
        'flag': ['SF', 'S0'],
        'duration': [0, 2],
        'src_bytes': [215, 0],
        'dst_bytes': [4507, 0],
        'land': [0, 0],
        'wrong_fragment': [0, 0],
        'urgent': [0, 0],
        'hot': [0, 0],
        'num_failed_logins': [0, 0],
        'logged_in': [1, 0],
        'num_compromised': [0, 0],
        'root_shell': [0, 0],
        'su_attempted': [0, 0],
        'num_root': [0, 0],
        'num_file_creations': [0, 0],
        'num_shells': [0, 0],
        'num_access_files': [0, 0],
        'num_outbound_cmds': [0, 0],
        'is_host_login': [0, 0],
        'is_guest_login': [0, 0],
        'count': [1, 10],
        'srv_count': [1, 10],
        'serror_rate': [0.0, 1.0],
        'srv_serror_rate': [0.0, 1.0],
        'rerror_rate': [0.0, 0.0],
        'srv_rerror_rate': [0.0, 0.0],
        'same_srv_rate': [1.0, 1.0],
        'diff_srv_rate': [0.0, 0.0],
        'srv_diff_host_rate': [0.0, 0.0],
        'dst_host_count': [255, 255],
        'dst_host_srv_count': [255, 10],
        'dst_host_same_srv_rate': [1.0, 0.1],
        'dst_host_diff_srv_rate': [0.0, 0.0],
        'dst_host_same_src_port_rate': [0.0, 0.0],
        'dst_host_srv_diff_host_rate': [0.0, 0.0],
        'dst_host_serror_rate': [0.0, 1.0],
        'dst_host_srv_serror_rate': [0.0, 1.0],
        'dst_host_rerror_rate': [0.0, 0.0],
        'dst_host_srv_rerror_rate': [0.0, 0.0]
    }
    
    df = pd.DataFrame(sample_data)
    preds = pipeline.predict(df)
    probs = pipeline.predict_proba(df)
    
    assert len(preds) == 2
    assert probs.shape == (2, len(pipeline.classes_))
    print("✓ Pipeline schema & prediction test passed.")

def test_inference_latency_budget():
    """Verifies sub-second (<1.0s) inference latency requirement across 1,000 connection records."""
    pipeline = joblib.load(MODEL_PATH)
    
    sample_data = {
        'protocol_type': ['tcp'] * 1000,
        'service': ['http'] * 1000,
        'flag': ['SF'] * 1000,
        'duration': [0] * 1000,
        'src_bytes': [215] * 1000,
        'dst_bytes': [4507] * 1000,
        'land': [0] * 1000,
        'wrong_fragment': [0] * 1000,
        'urgent': [0] * 1000,
        'hot': [0] * 1000,
        'num_failed_logins': [0] * 1000,
        'logged_in': [1] * 1000,
        'num_compromised': [0] * 1000,
        'root_shell': [0] * 1000,
        'su_attempted': [0] * 1000,
        'num_root': [0] * 1000,
        'num_file_creations': [0] * 1000,
        'num_shells': [0] * 1000,
        'num_access_files': [0] * 1000,
        'num_outbound_cmds': [0] * 1000,
        'is_host_login': [0] * 1000,
        'is_guest_login': [0] * 1000,
        'count': [1] * 1000,
        'srv_count': [1] * 1000,
        'serror_rate': [0.0] * 1000,
        'srv_serror_rate': [0.0] * 1000,
        'rerror_rate': [0.0] * 1000,
        'srv_rerror_rate': [0.0] * 1000,
        'same_srv_rate': [1.0] * 1000,
        'diff_srv_rate': [0.0] * 1000,
        'srv_diff_host_rate': [0.0] * 1000,
        'dst_host_count': [255] * 1000,
        'dst_host_srv_count': [255] * 1000,
        'dst_host_same_srv_rate': [1.0] * 1000,
        'dst_host_diff_srv_rate': [0.0] * 1000,
        'dst_host_same_src_port_rate': [0.0] * 1000,
        'dst_host_srv_diff_host_rate': [0.0] * 1000,
        'dst_host_serror_rate': [0.0] * 1000,
        'dst_host_srv_serror_rate': [0.0] * 1000,
        'dst_host_rerror_rate': [0.0] * 1000,
        'dst_host_srv_rerror_rate': [0.0] * 1000
    }
    
    df = pd.DataFrame(sample_data)
    start_time = time.time()
    pipeline.predict(df)
    latency = time.time() - start_time
    
    assert latency < 1.0, f"Inference latency test failed: {latency:.4f}s exceeds 1.0s budget!"
    print(f"✓ Inference latency test passed ({latency:.4f}s for 1000 records).")

if __name__ == "__main__":
    test_model_artifact_exists()
    test_pipeline_loading_and_schema()
    test_inference_latency_budget()
    print("All unit tests executed and passed successfully!")
