import pandas as pd

from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline

from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    classification_report
)


# -----------------------------
# Load dataset
# -----------------------------

data = pd.read_csv(
    "data/examples.csv"
)


X = data["text"]
y = data["label"]


# -----------------------------
# Split dataset
# -----------------------------

X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.25,
    random_state=42,
    stratify=y
)


# -----------------------------
# Create model
# -----------------------------

model = Pipeline([

    (
        "tfidf",
        TfidfVectorizer(
            lowercase=True,
            ngram_range=(1, 2)
        )
    ),

    (
        "classifier",
        LogisticRegression(
            max_iter=1000
        )
    )

])


# -----------------------------
# Train
# -----------------------------

model.fit(
    X_train,
    y_train
)


# -----------------------------
# Predict unseen data
# -----------------------------

predictions = model.predict(
    X_test
)


# -----------------------------
# Calculate metrics
# -----------------------------

accuracy = accuracy_score(
    y_test,
    predictions
)

precision = precision_score(
    y_test,
    predictions,
    pos_label="scam"
)

recall = recall_score(
    y_test,
    predictions,
    pos_label="scam"
)

f1 = f1_score(
    y_test,
    predictions,
    pos_label="scam"
)


# -----------------------------
# Display results
# -----------------------------

print("\n==============================")
print("SafeGuard AI Evaluation")
print("==============================")

print(
    f"\nAccuracy:  {accuracy * 100:.2f}%"
)

print(
    f"Precision: {precision * 100:.2f}%"
)

print(
    f"Recall:    {recall * 100:.2f}%"
)

print(
    f"F1 Score:  {f1 * 100:.2f}%"
)


print("\nClassification Report:")
print(
    classification_report(
        y_test,
        predictions
    )
)
