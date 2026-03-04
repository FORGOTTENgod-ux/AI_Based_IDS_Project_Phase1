#!/usr/bin/env python3
"""
train_rf_on_aggregated.py
-------------------------------------
Trains a Random Forest classifier on the aggregated IDS dataset.

Input  : data/aggregated_csv/aggregated_dataset.csv
Output : models/rf_ids_model.joblib
"""

import os
import argparse
import joblib
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score
from sklearn.pipeline import Pipeline
from sklearn.compose import ColumnTransformer
from sklearn.impute import SimpleImputer

def main(data_path, output_dir):
    print(f"[INFO] Loading dataset: {data_path}")
    df = pd.read_csv(data_path)

    if "label" not in df.columns:
        raise ValueError("The dataset must contain a 'label' column.")

    # Separate features and labels
    X = df.drop(columns=["label"])
    y = df["label"]

    # Identify numeric features
    numeric_features = X.select_dtypes(include=[np.number]).columns.tolist()

    print(f"[INFO] Feature columns: {numeric_features}")

    # Label encode the target
    le = LabelEncoder()
    y_encoded = le.fit_transform(y)

    # Split dataset
    X_train, X_test, y_train, y_test = train_test_split(
        X, y_encoded, test_size=0.2, random_state=42, stratify=y_encoded
    )

    # Preprocessing pipeline
    numeric_transformer = Pipeline(
        steps=[
            ("imputer", SimpleImputer(strategy="median")),
            ("scaler", StandardScaler())
        ]
    )

    preprocessor = ColumnTransformer(
        transformers=[
            ("num", numeric_transformer, numeric_features)
        ]
    )

    # Model pipeline
    clf = Pipeline(
        steps=[
            ("preprocessor", preprocessor),
            ("rf", RandomForestClassifier(
                n_estimators=150,
                max_depth=None,
                random_state=42,
                n_jobs=-1,
                class_weight="balanced"
            ))
        ]
    )

    print("[INFO] Training Random Forest model...")
    clf.fit(X_train, y_train)

    # Evaluation
    y_pred = clf.predict(X_test)
    acc = accuracy_score(y_test, y_pred)
    print(f"\n✅ Model accuracy: {acc * 100:.2f}%\n")
    print("=== Classification Report ===")
    print(classification_report(y_test, y_pred, target_names=le.classes_))
    print("\n=== Confusion Matrix ===")
    print(confusion_matrix(y_test, y_pred))

    # Save model and metadata
    os.makedirs(output_dir, exist_ok=True)
    model_bundle = {
        "pipeline": clf,
        "label_encoder": le,
        "feature_columns": numeric_features
    }
    model_path = os.path.join(output_dir, "rf_ids_model.joblib")
    joblib.dump(model_bundle, model_path)

    print(f"\n💾 Model saved to: {os.path.abspath(model_path)}")
    print(f"🧠 Classes: {list(le.classes_)}")
    print("\n✅ Training completed successfully!")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Train Random Forest IDS model.")
    parser.add_argument("--data", default="data/aggregated_csv/aggregated_dataset.csv", help="Path to aggregated dataset")
    parser.add_argument("--out-dir", default="models", help="Output directory for model")
    args = parser.parse_args()

    main(args.data, args.out_dir)
