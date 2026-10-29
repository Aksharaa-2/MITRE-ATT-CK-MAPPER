import os
import sys
import pandas as pd
import numpy as np

from sklearn.metrics import (
    precision_score,
    recall_score,
    f1_score,
    accuracy_score,
    classification_report
)

# --------------------------------------------------
# PROJECT ROOT
# --------------------------------------------------

BASE_DIR = os.path.dirname(
    os.path.dirname(os.path.abspath(__file__))
)

sys.path.insert(0, BASE_DIR)

# --------------------------------------------------
# IMPORT MODEL
# --------------------------------------------------

from core.ml_mapper import MLMapper


# --------------------------------------------------
# FILE PATH
# --------------------------------------------------

EVALUATION_FILE = os.path.join(
    BASE_DIR,
    "data",
    "evaluation.csv"
)


# --------------------------------------------------
# LOAD DATASET
# --------------------------------------------------

def load_evaluation_data():

    if not os.path.exists(EVALUATION_FILE):
        raise FileNotFoundError(
            f"Evaluation dataset not found:\n{EVALUATION_FILE}"
        )

    df = pd.read_csv(EVALUATION_FILE)

    required_columns = ["text", "technique_id"]

    for column in required_columns:
        if column not in df.columns:
            raise ValueError(
                f"Missing required column: {column}"
            )

    df = df.dropna(
        subset=["text", "technique_id"]
    )

    df["text"] = df["text"].astype(str)
    df["technique_id"] = df["technique_id"].astype(str)

    return df


# --------------------------------------------------
# TOP-K EVALUATION
# --------------------------------------------------

def evaluate_top_k(mapper, df, k):

    correct = 0
    total = len(df)

    details = []

    for _, row in df.iterrows():

        text = row["text"]
        expected = row["technique_id"]

        predictions = mapper.predict(
            text,
            top_k=k
        )

        predicted_ids = [
            item["technique_id"]
            for item in predictions
        ]

        is_correct = expected in predicted_ids

        if is_correct:
            correct += 1

        details.append({
            "text": text,
            "expected": expected,
            "predictions": predicted_ids,
            "correct": is_correct
        })

    accuracy = correct / total if total > 0 else 0

    return accuracy, details


# --------------------------------------------------
# TOP-1 PREDICTIONS
# --------------------------------------------------

def get_top1_predictions(mapper, df):

    y_true = []
    y_pred = []

    details = []

    for _, row in df.iterrows():

        text = row["text"]
        expected = row["technique_id"]

        predictions = mapper.predict(
            text,
            top_k=1
        )

        if not predictions:
            continue

        predicted = predictions[0]["technique_id"]

        y_true.append(expected)
        y_pred.append(predicted)

        details.append({
            "text": text,
            "expected": expected,
            "predicted": predicted,
            "correct": expected == predicted
        })

    return y_true, y_pred, details


# --------------------------------------------------
# MAIN
# --------------------------------------------------

def main():

    print("=" * 70)
    print("MITRE ATT&CK TECHNIQUE MAPPER - MODEL EVALUATION")
    print("=" * 70)

    # Load dataset

    df = load_evaluation_data()

    print()
    print("Evaluation samples:", len(df))
    print(
        "Unique techniques:",
        df["technique_id"].nunique()
    )

    # Load model

    print()
    print("Loading trained model...")

    mapper = MLMapper()

    print("Model loaded successfully.")

    # --------------------------------------------------
    # TOP-K
    # --------------------------------------------------

    print()
    print("-" * 70)
    print("TOP-K ACCURACY")
    print("-" * 70)

    top1, top1_details = evaluate_top_k(
        mapper,
        df,
        1
    )

    top3, top3_details = evaluate_top_k(
        mapper,
        df,
        3
    )

    top5, top5_details = evaluate_top_k(
        mapper,
        df,
        5
    )

    print(
        f"Top-1 Accuracy : {top1:.4f} ({top1 * 100:.2f}%)"
    )

    print(
        f"Top-3 Accuracy : {top3:.4f} ({top3 * 100:.2f}%)"
    )

    print(
        f"Top-5 Accuracy : {top5:.4f} ({top5 * 100:.2f}%)"
    )

    # --------------------------------------------------
    # PRECISION / RECALL / F1
    # --------------------------------------------------

    print()
    print("-" * 70)
    print("CLASSIFICATION METRICS")
    print("-" * 70)

    y_true, y_pred, details = get_top1_predictions(
        mapper,
        df
    )

    accuracy = accuracy_score(
        y_true,
        y_pred
    )

    precision = precision_score(
        y_true,
        y_pred,
        average="weighted",
        zero_division=0
    )

    recall = recall_score(
        y_true,
        y_pred,
        average="weighted",
        zero_division=0
    )

    f1 = f1_score(
        y_true,
        y_pred,
        average="weighted",
        zero_division=0
    )

    print(
        f"Accuracy  : {accuracy:.4f}"
    )

    print(
        f"Precision : {precision:.4f}"
    )

    print(
        f"Recall    : {recall:.4f}"
    )

    print(
        f"F1 Score  : {f1:.4f}"
    )

    # --------------------------------------------------
    # CLASSIFICATION REPORT
    # --------------------------------------------------

    print()
    print("-" * 70)
    print("DETAILED CLASSIFICATION REPORT")
    print("-" * 70)

    print(
        classification_report(
            y_true,
            y_pred,
            zero_division=0
        )
    )

    # --------------------------------------------------
    # WRONG PREDICTIONS
    # --------------------------------------------------

    print()
    print("-" * 70)
    print("ERROR ANALYSIS")
    print("-" * 70)

    wrong_predictions = [
        item
        for item in details
        if not item["correct"]
    ]

    print(
        "Incorrect predictions:",
        len(wrong_predictions)
    )

    print(
        "Correct predictions:",
        len(details) - len(wrong_predictions)
    )

    print()

    for index, item in enumerate(
        wrong_predictions,
        start=1
    ):

        print(f"[ERROR {index}]")

        print(
            "Text:",
            item["text"]
        )

        print(
            "Expected:",
            item["expected"]
        )

        print(
            "Predicted:",
            item["predicted"]
        )

        print("-" * 50)

    # --------------------------------------------------
    # SAVE RESULTS
    # --------------------------------------------------

    results = []

    for item in details:

        results.append({
            "text": item["text"],
            "expected": item["expected"],
            "predicted": item["predicted"],
            "correct": item["correct"]
        })

    results_df = pd.DataFrame(results)

    output_file = os.path.join(
        BASE_DIR,
        "data",
        "evaluation_results.csv"
    )

    results_df.to_csv(
        output_file,
        index=False
    )

    print()
    print("=" * 70)
    print("Evaluation completed.")
    print(
        "Results saved to:",
        output_file
    )
    print("=" * 70)


if __name__ == "__main__":
    main()