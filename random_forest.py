import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score
import joblib

# Load dataset
data = pd.read_csv('MalwareData.csv')

# Feature columns
feature_columns = [
    'NumberOfSections',
    'SizeOfOptionalHeader',
    'Characteristics',
    'MajorLinkerVersion',
    'MinorLinkerVersion',
    'SizeOfCode',
    'SizeOfInitializedData',
    'SizeOfUninitializedData',
    'AddressOfEntryPoint',
    'BaseOfCode',
    'ImageBase',
    'SectionEntropy'
]

X = data[feature_columns]
y = data['legitimate']

# Train/test split
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.25, random_state=42, stratify=y)

# Train Random Forest with better parameters
model = RandomForestClassifier(
    n_estimators=300,  # Increase the number of trees
    max_depth=20,  # Try deeper trees
    min_samples_split=4,  # Reduce splitting conditions to create deeper trees
    min_samples_leaf=2,  # Allow deeper leaf nodes
    class_weight='balanced',
    random_state=42
)
model.fit(X_train, y_train)

# Predict on the test set
y_pred = model.predict(X_test)

# Evaluate the model performance
accuracy = accuracy_score(y_test, y_pred)
print(f"Model Accuracy: {accuracy * 100:.2f}%")

# Save the trained model to a file
joblib.dump(model, 'malware_model.pkl')

print("[+] Improved Model trained and saved successfully!")
