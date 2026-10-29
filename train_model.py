import os
import sys
import re
import pandas as pd
import numpy as np
import joblib

from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
from sklearn.pipeline import FeatureUnion
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.svm import LinearSVC

from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    classification_report
)

# ============================================================
# PATHS
# ============================================================

BASE_DIR = os.path.dirname(
    os.path.dirname(os.path.abspath(__file__))
)

sys.path.insert(0, BASE_DIR)

from core.text_normalizer import normalize_training_text


DATA_FILE = os.path.join(
    BASE_DIR,
    "data",
    "mitre_training.csv"
)

MODEL_DIR = os.path.join(
    BASE_DIR,
    "models"
)

os.makedirs(MODEL_DIR, exist_ok=True)


# ============================================================
# START
# ============================================================

print("=" * 75)
print("MITRE ATT&CK HIGH-ACCURACY MODEL TRAINING")
print("=" * 75)


# ============================================================
# 1. LOAD DATA
# ============================================================

print("\n[1] Loading dataset...")

df = pd.read_csv(DATA_FILE)

print("Original samples :", len(df))
print("Original classes :", df["technique_id"].nunique())


# ============================================================
# 2. CLEAN TEXT
# ============================================================

print("\n[2] Cleaning text...")

df = df.dropna(
    subset=["text", "technique_id"]
)

df["text"] = df["text"].apply(
    normalize_training_text
)

df["technique_id"] = (
    df["technique_id"]
    .astype(str)
    .str.strip()
)

df = df[
    (df["text"] != "") &
    (df["technique_id"] != "")
]

# Remove duplicate examples
df = df.drop_duplicates(
    subset=["text", "technique_id"]
)

print("After cleaning :", len(df))


# ============================================================
# 3. REMOVE MITRE PROCEDURE NOISE
# ============================================================

print("\n[3] Removing procedure noise...")


def remove_mitre_noise(text):

    text = str(text)

    # Remove [Operation Name], [Group Name], etc.
    text = re.sub(
        r"\[[^\]]+\]",
        " ",
        text
    )

    # Remove citation information
    text = re.sub(
        r"\(Citation:[^)]+\)",
        " ",
        text,
        flags=re.IGNORECASE
    )

    # Convert markdown links to visible text
    text = re.sub(
        r"\[([^\]]+)\]\([^)]+\)",
        r"\1",
        text
    )

    # Remove URLs
    text = re.sub(
        r"https?://\S+",
        " ",
        text
    )

    # Remove backticks
    text = text.replace(
        "`",
        " "
    )

    # Normalize spaces
    text = re.sub(
        r"\s+",
        " ",
        text
    )

    return text.strip()


df["text"] = df["text"].apply(
    remove_mitre_noise
)


# ============================================================
# 4. CLASS DISTRIBUTION
# ============================================================

print("\n[4] Analysing class distribution...")

class_counts = df["technique_id"].value_counts()

print(
    class_counts.describe()
)


# ============================================================
# 5. SELECT WELL REPRESENTED TECHNIQUES
# ============================================================

print("\n[5] Selecting techniques for supervised ML...")

# Techniques with very few examples are not reliable
# for supervised classification.
#
# They will later be handled by semantic retrieval.

MIN_EXAMPLES = 10

valid_classes = class_counts[
    class_counts >= MIN_EXAMPLES
].index

ml_df = df[
    df["technique_id"].isin(valid_classes)
].copy()

print(
    "Minimum examples per technique :",
    MIN_EXAMPLES
)

print(
    "Classes used by SVM :",
    ml_df["technique_id"].nunique()
)

print(
    "Samples used by SVM :",
    len(ml_df)
)

print(
    "Rare classes handled by semantic retrieval :",
    df["technique_id"].nunique()
    - ml_df["technique_id"].nunique()
)


# ============================================================
# 6. LIGHTWEIGHT TEXT AUGMENTATION
# ============================================================

print("\n[6] Creating training augmentation...")


def augment_text(text):

    text = str(text)

    variations = []

    # Original
    variations.append(text)

    # Remove common subject prefixes
    cleaned = re.sub(
        r"^(the )?(attacker|threat actor|malware|group|adversary)\s+",
        "",
        text,
        flags=re.IGNORECASE
    )

    if cleaned != text:
        variations.append(cleaned)

    # Lowercase version
    variations.append(
        text.lower()
    )

    # Remove "the attacker" style wording
    cleaned2 = re.sub(
        r"\b(the attacker|the threat actor|the adversary)\b",
        "",
        text,
        flags=re.IGNORECASE
    )

    cleaned2 = re.sub(
        r"\s+",
        " ",
        cleaned2
    ).strip()

    if cleaned2:
        variations.append(cleaned2)

    # Remove duplicate variants
    return list(
        dict.fromkeys(variations)
    )


augmented_rows = []

for _, row in ml_df.iterrows():

    variants = augment_text(
        row["text"]
    )

    for variant in variants:

        augmented_rows.append({
            "text": variant,
            "technique_id": row["technique_id"]
        })


augmented_df = pd.DataFrame(
    augmented_rows
)

augmented_df = augmented_df.drop_duplicates(
    subset=["text", "technique_id"]
)

print(
    "Original ML samples :",
    len(ml_df)
)

print(
    "Augmented samples   :",
    len(augmented_df)
)


# ============================================================
# 7. LABEL ENCODING
# ============================================================

print("\n[7] Encoding labels...")

X = augmented_df["text"]

y = augmented_df["technique_id"]

label_encoder = LabelEncoder()

y_encoded = label_encoder.fit_transform(
    y
)

print(
    "Number of classes :",
    len(label_encoder.classes_)
)


# ============================================================
# 8. TRAIN / VALIDATION SPLIT
# ============================================================

print("\n[8] Creating stratified validation split...")

X_train, X_test, y_train, y_test = train_test_split(
    X,
    y_encoded,
    test_size=0.20,
    random_state=42,
    stratify=y_encoded
)

print(
    "Training samples   :",
    len(X_train)
)

print(
    "Validation samples :",
    len(X_test)
)


# ============================================================
# 9. WORD TF-IDF
# ============================================================

print("\n[9] Building WORD TF-IDF...")

word_vectorizer = TfidfVectorizer(
    lowercase=True,
    strip_accents="unicode",
    analyzer="word",
    ngram_range=(1, 3),
    min_df=1,
    max_df=0.98,
    sublinear_tf=True,
    max_features=250000,
    norm="l2"
)


# ============================================================
# 10. CHARACTER TF-IDF
# ============================================================

print("\n[10] Building CHARACTER TF-IDF...")

char_vectorizer = TfidfVectorizer(
    lowercase=True,
    analyzer="char_wb",
    ngram_range=(3, 6),
    min_df=1,
    sublinear_tf=True,
    max_features=150000,
    norm="l2"
)


# ============================================================
# 11. COMBINE WORD + CHARACTER FEATURES
# ============================================================

print("\n[11] Combining TF-IDF features...")

vectorizer = FeatureUnion([
    (
        "word",
        word_vectorizer
    ),
    (
        "char",
        char_vectorizer
    )
])


# ============================================================
# 12. CREATE FEATURE MATRIX
# ============================================================

print("\n[12] Creating feature matrix...")

X_train_vectorized = vectorizer.fit_transform(
    X_train
)

X_test_vectorized = vectorizer.transform(
    X_test
)

print(
    "Feature matrix :",
    X_train_vectorized.shape
)


# ============================================================
# 13. TEST DIFFERENT SVM PARAMETERS
# ============================================================

print("\n[13] Testing SVM configurations...")

C_VALUES = [
    0.5,
    1.0,
    1.5,
    2.0,
    3.0,
    4.0
]

best_model = None

best_accuracy = 0.0

best_C = None

best_predictions = None


for C in C_VALUES:

    print(
        "\n----------------------------------------"
    )

    print(
        "Training LinearSVC"
    )

    print(
        "C =",
        C
    )

    print(
        "----------------------------------------"
    )

    model = LinearSVC(
        C=C,
        class_weight="balanced",
        max_iter=20000,
        tol=1e-4
    )

    model.fit(
        X_train_vectorized,
        y_train
    )

    predictions = model.predict(
        X_test_vectorized
    )

    accuracy = accuracy_score(
        y_test,
        predictions
    )

    print(
        f"Validation accuracy: {accuracy:.4f}"
    )

    if accuracy > best_accuracy:

        best_accuracy = accuracy

        best_model = model

        best_C = C

        best_predictions = predictions


# ============================================================
# 14. FINAL METRICS
# ============================================================

print("\n")

print("=" * 75)
print("BEST VALIDATION RESULTS")
print("=" * 75)

precision = precision_score(
    y_test,
    best_predictions,
    average="weighted",
    zero_division=0
)

recall = recall_score(
    y_test,
    best_predictions,
    average="weighted",
    zero_division=0
)

f1 = f1_score(
    y_test,
    best_predictions,
    average="weighted",
    zero_division=0
)

print(
    f"Best C       : {best_C}"
)

print(
    f"Accuracy     : {best_accuracy:.4f}"
)

print(
    f"Precision    : {precision:.4f}"
)

print(
    f"Recall       : {recall:.4f}"
)

print(
    f"F1 Score     : {f1:.4f}"
)


# ============================================================
# 15. CLASSIFICATION REPORT
# ============================================================

validation_labels = np.unique(
    y_test
)

validation_names = (
    label_encoder.inverse_transform(
        validation_labels
    )
)

print("\nClassification Report:\n")

print(
    classification_report(
        y_test,
        best_predictions,
        labels=validation_labels,
        target_names=validation_names,
        zero_division=0
    )
)


# ============================================================
# 16. SAVE VECTORIZER
# ============================================================

print("\n[14] Saving vectorizer...")

vectorizer_path = os.path.join(
    MODEL_DIR,
    "tfidf_vectorizer.pkl"
)

joblib.dump(
    vectorizer,
    vectorizer_path
)


# ============================================================
# 17. SAVE MODEL
# ============================================================

print("[15] Saving SVM model...")

model_path = os.path.join(
    MODEL_DIR,
    "svm_model.pkl"
)

joblib.dump(
    best_model,
    model_path
)


# ============================================================
# 18. SAVE LABEL ENCODER
# ============================================================

print("[16] Saving label encoder...")

encoder_path = os.path.join(
    MODEL_DIR,
    "label_encoder.pkl"
)

joblib.dump(
    label_encoder,
    encoder_path
)


# ============================================================
# 19. SAVE MODEL METADATA
# ============================================================

print("[17] Saving model metadata...")

metadata = {

    "model_type":
        "Word + Character TF-IDF + LinearSVC",

    "best_C":
        float(best_C),

    "min_examples_per_class":
        MIN_EXAMPLES,

    "training_samples":
        int(len(X_train)),

    "validation_samples":
        int(len(X_test)),

    "classifier_classes":
        int(len(label_encoder.classes_)),

    "total_mitre_techniques":
        int(df["technique_id"].nunique()),

    "accuracy":
        float(best_accuracy),

    "precision":
        float(precision),

    "recall":
        float(recall),

    "f1":
        float(f1)
}

metadata_path = os.path.join(
    MODEL_DIR,
    "model_metadata.pkl"
)

joblib.dump(
    metadata,
    metadata_path
)


# ============================================================
# 20. COMPLETE
# ============================================================

print("\n")

print("=" * 75)
print("MODEL TRAINING COMPLETE")
print("=" * 75)

print(
    "\nVectorizer :",
    vectorizer_path
)

print(
    "Model      :",
    model_path
)

print(
    "Encoder    :",
    encoder_path
)

print(
    "Metadata   :",
    metadata_path
)

print(
    "\nBest validation accuracy:",
    f"{best_accuracy * 100:.2f}%"
)

print("\nTraining finished successfully.")