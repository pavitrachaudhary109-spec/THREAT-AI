import pandas as pd
import joblib

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline


# Load training data
data = pd.read_csv(
    "data/examples.csv"
)


# Create AI pipeline
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


# Train model
model.fit(
    data["text"],
    data["label"]
)


# Save model locally
joblib.dump(
    model,
    "scam_model.joblib"
)


print("================================")
print("SafeGuard AI model trained!")
print("Model saved as scam_model.joblib")
print("================================")
