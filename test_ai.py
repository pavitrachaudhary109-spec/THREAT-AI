import joblib


# Load local model
model = joblib.load(
    "scam_model.joblib"
)


messages = [

    "URGENT! Your bank account will be blocked. Verify immediately.",

    "Congratulations! You won a prize. Claim your reward now.",

    "Hey, are we meeting tomorrow?",

    "Your package has been delivered."

]


for message in messages:

    prediction = model.predict(
        [message]
    )[0]

    probabilities = model.predict_proba(
        [message]
    )[0]

    classes = model.classes_

    probability_map = dict(
        zip(
            classes,
            probabilities
        )
    )

    scam_probability = probability_map.get(
        "scam",
        0
    )

    print("\n----------------------------")

    print("Message:")
    print(message)

    print("Prediction:")
    print(prediction)

    print(
        "Scam probability:",
        round(
            scam_probability * 100,
            2
        ),
        "%"
    )
