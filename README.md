cat << 'EOF' > README.md
# AI-Wazuh Malware Detection System

This project integrates an AI-based malware detection model into the open-source Wazuh SIEM platform. It uses static analysis of Windows executable files and a Random Forest classifier to detect and automatically respond to malware threats. The system can scan new files in real-time and delete malicious ones automatically based on AI predictions.

---

## 🔧 Features

- Static feature extraction from Windows PE files
- Machine learning classification using a Random Forest model
- Real-time folder monitoring using a Bash script
- Custom Wazuh decoder and rule integration
- Active response script to automatically delete detected malware
- Log entries for predictions and deletions

---

## 📁 Project Structure

| File/Folder               | Description                                             |
|--------------------------|---------------------------------------------------------|
| feature_extractor.py     | Extracts PE file features into a CSV                    |
| random_forest.py         | Trains the Random Forest model using labeled data       |
| predict_file.py          | Loads the model and predicts if a file is malicious     |
| watch_dir.sh             | Monitors a directory for new files and triggers scanning|
| malware_model.pkl        | Trained Random Forest model file                        |
| features.csv             | Extracted features from test files                      |
| features_with_labels.csv | Dataset with labels for model training                 |
| test_after/              | Folder containing benign and malicious test files       |
| README.md                | Project documentation                                   |

---

## 🚀 How to Use

1. Clone the repository:
    git clone https://github.com/moamenfarwan/ai-wazuh-automation.git
    cd ai-wazuh-automation

2. Train the AI model:
    python3 random_forest.py

3. Predict a new file:
    python3 predict_file.py /path/to/file.exe

4. Run real-time file monitoring:
    bash watch_dir.sh

This script watches for new files in a specified directory and runs predictions automatically.

---

## ⚙️ Wazuh Integration Overview

- The AI prediction result is written to a log file.
- Wazuh monitors that log using a custom decoder and rule.
- If a file is flagged as malicious, Wazuh raises an alert (rule ID 100100).
- An active response script (delete-malware.sh) deletes the malicious file automatically.

---

## ⚠️ Disclaimer

This project was created for academic research in a controlled virtual environment. It uses synthetic and publicly available malware samples. Do not use this system in production environments.

---

## 📚 References

The machine learning model used in this project is adapted from a publicly available implementation. The system was extended and integrated into Wazuh as part of an academic dissertation project.

---

## 🧠 Author

Moamen Farwan  
University of Derby – BSc Cybersecurity Final Year Project  
GitHub: https://github.com/moamenfarwan

---

## 📜 License

This project is for educational and research purposes only.
EOF
