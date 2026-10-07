### Group 16: Real-Time Network Intrusion Detection System (NIDS)
#### FUSE AI-201 Capstone Implementation Project
This repository contains the complete end-to-end implementation for **Group 16's Real-Time Network Intrusion Detection System (NIDS)**. Grounded in the **FUSE AI-201 Module 5 Implementation Lifecycle**, this project addresses Security Operations Center (SOC) alert fatigue (>90% false positive rates) by deploying a 5-class machine learning classification pipeline paired with an interactive decision-support web dashboard.

--------------------------------------------------------------------------------

#### 📐 System Architecture & Component Mapping
```
                               ┌────────────────────────────────┐
                               │  NSL-KDD Dataset (41 Features) │
                               └──────────────┬─────────────────┘
                                              │
                                              ▼
                               ┌────────────────────────────────┐
                               │         train_model.py         │
                               │  (Preprocessing + Train RF)    │
                               └──────────────┬─────────────────┘
                                              │
                                              ▼
                               ┌────────────────────────────────┐
                               │ nids_random_forest_pipeline    │
                               │           (.joblib)            │
                               └──────────────┬─────────────────┘
                                              │
                       ┌──────────────────────┴──────────────────────┐
                       │                                             │
                       ▼                                             ▼
        ┌──────────────────────────────┐              ┌──────────────────────────────┐
        │            app.py            │              │    test_model_pipeline.py   │
        │  (Streamlit SOC Dashboard +  │              │ (Automated Latency & Schema  │
        │      SHAP Attribution)       │              │         Unit Tests)          │
        └──────────────┬───────────────┘              └──────────────┬───────────────┘
                       │                                             │
                       └──────────────────────┬──────────────────────┘
                                              │
                                              ▼
                               ┌────────────────────────────────┐
                               │           Dockerfile           │
                               │  (Non-Root Security Container) │
                               └──────────────┬─────────────────┘
                                              │
                                              ▼
                               ┌────────────────────────────────┐
                               │     .github/workflows/         │
                               │           deploy.yml           │
                               │  (Automated CI/CD Pipeline)     │
                               └────────────────────────────────┘
```

--------------------------------------------------------------------------------

#### 📁 Repository Directory Structure
```
.
├── app.py                                   # Streamlit Web Dashboard & SHAP Force Visualizer
├── train_model.py                           # Data Preprocessing, SMOTE, Training & Serialization
├── test_model_pipeline.py                   # Pytest/Unittest Suite (Schema & <1.0s Latency Verification)
├── nids_random_forest_pipeline.joblib       # Pre-trained Scikit-learn Pipeline Model Artifact
├── Dockerfile                               # Production Containerization Specification
├── requirements.txt                         # Python Library Dependencies
├── .github/
│   └── workflows/
│       └── deploy.yml                       # GitHub Actions CI/CD Pipeline Configuration
├── README.md                                # Project Documentation & Guidelines
└── docs/
    └── group16-nids-comprehensive-guide.md   # Module 5 Implementation Specification
```

--------------------------------------------------------------------------------

#### 🚀 Quickstart Guide
##### 1. Local Environment Setup
Clone the repository and install the dependencies:
```bash
git clone https://github.com/group16-nids/nids-capstone.git
cd nids-capstone

# Create and activate virtual environment
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install required packages
pip install -r requirements.txt
```

##### 2. Model Training & Serialization
To re-train the Random Forest classifier on the NSL-KDD dataset and generate the updated `.joblib` model:
```bash
python3 train_model.py
```

##### 3. Automated Unit Testing
Run the test suite to verify model loading, input feature schemas, and sub-second inference latency constraints:
```bash
python3 test_model_pipeline.py
```

##### 4. Launching the Interactive Web Dashboard
Start the Streamlit application for SOC analyst decision support:
```bash
streamlit run app.py
```
Access the application in your browser at `http://localhost:8501`.

--------------------------------------------------------------------------------

#### 🐳 Docker Deployment
##### Building the Container Image
```bash
docker build -t group16-nids-app:v1 .
```

##### Running the Container
```bash
docker run -d -p 8501:8501 --name nids-dashboard group16-nids-app:v1
```
The application will be accessible at `http://localhost:8501`.

--------------------------------------------------------------------------------

#### 🔄 CI/CD Pipeline (GitHub Actions)
The `.github/workflows/deploy.yml` pipeline runs automatically on every push or pull_request to main:
1. **Test Phase:** Installs dependencies, verifies `.joblib` artifact presence, and runs `test_model_pipeline.py`.
2. **Build Phase:** Builds the Docker container and verifies service health checks on port 8501.

--------------------------------------------------------------------------------

#### ⚖️ Responsible AI & Operational Boundaries
* **Human-in-the-Loop Design:** The dashboard functions exclusively as a decision-support advisory tool for SOC security analysts.
* **Non-Enforcement Constraint:** The application does **not** perform automated packet dropping or active firewall rule modification.
* **Explainability:** Integrated SHAP attribution plots provide transparent rationale for every flagged threat, preventing unverified black-box alerts.

--------------------------------------------------------------------------------

#### 📄 Documentation Reference
For a complete explanation of the Module 5 implementation lifecycle, statistical evaluation matrices, and threat category definitions, refer to `docs/group16-nids-comprehensive-guide.md`.
