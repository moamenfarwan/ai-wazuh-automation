import sys
import os
import joblib
import pandas as pd
import pefile
import json
from datetime import datetime

# Load the trained model
model = joblib.load('/root/ML-Based-Malware-Detection/malware_model.pkl')  # full path (recommended)

# Load required feature names
with open('/root/ML-Based-Malware-Detection/features.json') as f:
    required_features = json.load(f)

def extract_features(filepath):
    try:
        pe = pefile.PE(filepath)
        
        features = {
            'SizeOfOptionalHeader': pe.FILE_HEADER.SizeOfOptionalHeader,
            'Characteristics': pe.FILE_HEADER.Characteristics,
            'NumberOfSections': len(pe.sections),
            'MajorLinkerVersion': pe.OPTIONAL_HEADER.MajorLinkerVersion,
            'MinorLinkerVersion': pe.OPTIONAL_HEADER.MinorLinkerVersion,
            'SizeOfCode': pe.OPTIONAL_HEADER.SizeOfCode,
            'SizeOfInitializedData': pe.OPTIONAL_HEADER.SizeOfInitializedData,
            'SizeOfUninitializedData': pe.OPTIONAL_HEADER.SizeOfUninitializedData,
            'AddressOfEntryPoint': pe.OPTIONAL_HEADER.AddressOfEntryPoint,
            'BaseOfCode': pe.OPTIONAL_HEADER.BaseOfCode,
            'ImageBase': pe.OPTIONAL_HEADER.ImageBase,
            'Subsystem': pe.OPTIONAL_HEADER.Subsystem,
            'DllCharacteristics': pe.OPTIONAL_HEADER.DllCharacteristics,
            'FileAlignment': pe.OPTIONAL_HEADER.FileAlignment,
            'MajorOperatingSystemVersion': pe.OPTIONAL_HEADER.MajorOperatingSystemVersion,
            'MinorOperatingSystemVersion': pe.OPTIONAL_HEADER.MinorOperatingSystemVersion,
            'MajorImageVersion': pe.OPTIONAL_HEADER.MajorImageVersion,
            'MinorImageVersion': pe.OPTIONAL_HEADER.MinorImageVersion,
            'MajorSubsystemVersion': pe.OPTIONAL_HEADER.MajorSubsystemVersion,
            'MinorSubsystemVersion': pe.OPTIONAL_HEADER.MinorSubsystemVersion,
            'SizeOfImage': pe.OPTIONAL_HEADER.SizeOfImage,
            'SizeOfHeaders': pe.OPTIONAL_HEADER.SizeOfHeaders,
            'SectionMaxEntropy': max(section.get_entropy() for section in pe.sections),
            'SectionMinEntropy': min(section.get_entropy() for section in pe.sections),
            'SectionMeanEntropy': sum(section.get_entropy() for section in pe.sections) / len(pe.sections),
            'SectionMaxRawsize': max(section.SizeOfRawData for section in pe.sections),
            'SectionMinRawsize': min(section.SizeOfRawData for section in pe.sections),
            'SectionMeanRawsize': sum(section.SizeOfRawData for section in pe.sections) / len(pe.sections),
            'SectionMaxVirtualsize': max(section.Misc_VirtualSize for section in pe.sections),
            'SectionMinVirtualsize': min(section.Misc_VirtualSize for section in pe.sections),
            'SectionMeanVirtualsize': sum(section.Misc_VirtualSize for section in pe.sections) / len(pe.sections),
            'NumberOfImports': len(pe.DIRECTORY_ENTRY_IMPORT) if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT') else 0,
            'NumberOfExports': len(pe.DIRECTORY_ENTRY_EXPORT.symbols) if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT') else 0,
        }

        return features
    except Exception as e:
        print(f"Error extracting features: {e}")
        return None

if len(sys.argv) != 2:
    print("Usage: python3 predict_file.py <file_path>")
    sys.exit(1)

file_path = sys.argv[1]
features = extract_features(file_path)

if features is None:
    print("Feature extraction failed.")
    sys.exit(1)

# Build DataFrame, align columns to training features
features_df = pd.DataFrame([features])
features_df = features_df.reindex(columns=required_features, fill_value=0)

# Predict
prediction = model.predict(features_df)[0]

# Log the prediction

log_data = {
    "timestamp": str(datetime.utcnow()),
    "file_path": file_path,
    "file_name": os.path.basename(file_path),
    "label": "MALICIOUS" if prediction == 0 else "BENIGN"
}

with open('/var/log/ai_malware_detection.log', 'a') as log_file:
    log_file.write(json.dumps(log_data) + '\n')

print(f"Prediction: {'MALICIOUS' if prediction == 0 else 'BENIGN'}")

print("Prediction columns:", list(features_df.columns))

