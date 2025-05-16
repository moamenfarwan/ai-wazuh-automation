import os
import csv
import pandas as pd
import pefile
import argparse

# Function to extract features from a single file
def extract_features(file_path):
    try:
        pe = pefile.PE(file_path)

        features = {
            "Filename": os.path.basename(file_path),
            "NumberOfSections": len(pe.sections),
            "SizeOfOptionalHeader": pe.FILE_HEADER.SizeOfOptionalHeader,
            "Characteristics": pe.FILE_HEADER.Characteristics,
            "MajorLinkerVersion": pe.OPTIONAL_HEADER.MajorLinkerVersion,
            "MinorLinkerVersion": pe.OPTIONAL_HEADER.MinorLinkerVersion,
            "SizeOfCode": pe.OPTIONAL_HEADER.SizeOfCode,
            "SizeOfInitializedData": pe.OPTIONAL_HEADER.SizeOfInitializedData,
            "SizeOfUninitializedData": pe.OPTIONAL_HEADER.SizeOfUninitializedData,
            "AddressOfEntryPoint": pe.OPTIONAL_HEADER.AddressOfEntryPoint,
            "BaseOfCode": pe.OPTIONAL_HEADER.BaseOfCode,
            "ImageBase": pe.OPTIONAL_HEADER.ImageBase,
            "SectionEntropy": sum([s.get_entropy() for s in pe.sections]) / len(pe.sections) if len(pe.sections) > 0 else 0
        }
        return features

    except Exception as e:
        print(f"Error extracting features from {file_path}: {e}")
        return None

# Function to extract features from all files in a directory
def extract_features_from_directory(directory):
    data = []
    for filename in os.listdir(directory):
        file_path = os.path.join(directory, filename)
        if os.path.isfile(file_path):
            features = extract_features(file_path)
            if features:
                data.append(features)
    return data

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('--input_dir', required=True, help='Directory containing .exe files')
    parser.add_argument('--output_file', required=True, help='Path to output CSV file')
    args = parser.parse_args()

    print(f"Extracting features from: {args.input_dir}")
    feature_data = extract_features_from_directory(args.input_dir)

    if feature_data:
        df = pd.DataFrame(feature_data)
        df.to_csv(args.output_file, index=False)
        print(f"Saved extracted features to: {args.output_file}")
    else:
        print("No features extracted.")
