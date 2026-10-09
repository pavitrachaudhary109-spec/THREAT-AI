import re
import joblib
import os
import socket
from urllib.parse import urlparse


# ============================================================
# LOAD MACHINE LEARNING MODEL
# ============================================================

MODEL_PATH = "scam_model.joblib"

if not os.path.exists(MODEL_PATH):
    raise FileNotFoundError(
        f"Model file '{MODEL_PATH}' not found. "
        "Please run train_model.py first."
    )

model = joblib.load(MODEL_PATH)


# ============================================================
# SCAM KEYWORDS
# ============================================================

SCAM_WORDS = {
    "urgent": 8,
    "immediately": 8,
    "verify": 7,
    "blocked": 8,
    "suspended": 8,
    "winner": 10,
    "congratulations": 8,
    "prize": 10,
    "reward": 8,
    "claim": 7,
    "otp": 10,
    "password": 8,
    "bank": 8,
    "refund": 6,
    "payment": 6,
    "click": 7,
    "account": 5,
    "login": 7,
    "wallet": 7,
    "upi": 8,
    "transaction": 7,
    "debit": 6,
    "credit": 6,
    "lottery": 10,
    "investment": 7,
    "profit": 6,
    "crypto": 6,
    "salary": 5,
    "job": 4,
    "parcel": 5,
    "package": 5,
    "delivery": 5
}


# ============================================================
# THREAT CATEGORIES
# ============================================================

THREAT_CATEGORIES = {

    "Banking Scam": [
        "bank",
        "account",
        "upi",
        "transaction",
        "payment",
        "debit",
        "credit",
        "atm",
        "net banking",
        "banking"
    ],

    "Phishing": [
        "verify",
        "verification",
        "login",
        "password",
        "username",
        "account",
        "click",
        "sign in",
        "security"
    ],

    "OTP Scam": [
        "otp",
        "one time password",
        "verification code",
        "security code"
    ],

    "Prize / Lottery Scam": [
        "winner",
        "won",
        "prize",
        "lottery",
        "reward",
        "claim",
        "lucky winner",
        "cash prize"
    ],

    "Investment Scam": [
        "investment",
        "profit",
        "crypto",
        "trading",
        "returns",
        "double your money",
        "guaranteed return",
        "stock"
    ],

    "Job Scam": [
        "job",
        "salary",
        "work from home",
        "vacancy",
        "registration fee",
        "interview",
        "part time",
        "earning"
    ],

    "Delivery Scam": [
        "package",
        "parcel",
        "delivery",
        "courier",
        "shipment",
        "address",
        "delivery fee"
    ],

    "Refund Scam": [
        "refund",
        "cashback",
        "money back",
        "refund amount",
        "refund process"
    ]
}


# ============================================================
# AI PREDICTION
# ============================================================

def ai_prediction(message):
    """
    Uses the trained ML model to predict whether
    a message is scam or normal.
    """

    try:
        prediction = model.predict([message])[0]

        probabilities = model.predict_proba([message])[0]

        classes = list(model.classes_)

        scam_probability = 0.0

        # Try to find the scam class automatically
        for index, class_name in enumerate(classes):

            class_text = str(class_name).lower()

            if class_text in ["scam", "1", "fraud", "phishing"]:
                scam_probability = probabilities[index] * 100
                break

        # Fallback if scam class was not found
        if scam_probability == 0.0 and len(probabilities) == 2:
            scam_probability = probabilities[-1] * 100

        prediction_text = str(prediction).lower()

        if prediction_text in ["scam", "1", "fraud", "phishing"]:
            label = "scam"
        else:
            label = "normal"

        return label, round(scam_probability, 2)

    except Exception as error:

        print("AI prediction error:", error)

        return "unknown", 0.0


# ============================================================
# THREAT CATEGORY DETECTOR
# ============================================================

def detect_threat_category(message):
    """
    Detects the most likely type of threat
    using keyword-based classification.
    """

    text = message.lower()

    category_scores = {}

    for category, keywords in THREAT_CATEGORIES.items():

        score = 0

        for keyword in keywords:

            if keyword in text:
                score += 1

        category_scores[category] = score

    best_category = max(
        category_scores,
        key=category_scores.get
    )

    if category_scores[best_category] == 0:
        return "General Suspicious Message"

    return best_category


# ============================================================
# MESSAGE ANALYZER
# ============================================================

def analyze_message(message):

    if not message or not message.strip():

        return {
            "score": 0,
            "risk": "LOW",
            "category": "No Input",
            "ai_score": 0,
            "ai_prediction": "unknown",
            "reasons": ["Please enter a message or URL."],
            "urls": [],
            "url_analysis": []
        }

    message = message.strip()

    text = message.lower()

    # --------------------------------------------------------
    # RULE BASED SCORE
    # --------------------------------------------------------

    rule_score = 0

    reasons = []

    for word, points in SCAM_WORDS.items():

        if word in text:

            rule_score += points

            reasons.append(
                f"Suspicious keyword detected: '{word}'"
            )

    # --------------------------------------------------------
    # URGENCY DETECTION
    # --------------------------------------------------------

    urgency_words = [
        "urgent",
        "immediately",
        "act now",
        "within 24 hours",
        "last chance",
        "account will be blocked",
        "account will be suspended"
    ]

    urgency_found = False

    for word in urgency_words:

        if word in text:

            urgency_found = True

            rule_score += 8

            reasons.append(
                f"Pressure/urgency detected: '{word}'"
            )

            break

    # --------------------------------------------------------
    # PERSONAL INFORMATION REQUEST
    # --------------------------------------------------------

    sensitive_requests = [
        "share otp",
        "send otp",
        "provide otp",
        "share password",
        "send password",
        "enter password",
        "share pin",
        "send pin",
        "card number",
        "cvv",
        "account number"
    ]

    for phrase in sensitive_requests:

        if phrase in text:

            rule_score += 15

            reasons.append(
                f"Sensitive information request detected: '{phrase}'"
            )

    # --------------------------------------------------------
    # URL DETECTION
    # --------------------------------------------------------

    urls = re.findall(
        r"https?://[^\s]+",
        message
    )

    url_results = []

    if urls:

        rule_score += 10

        reasons.append(
            f"{len(urls)} URL/link detected in the message"
        )

        for url in urls:

            result = analyze_url(url)

            url_results.append({
                "url": url,
                "score": result["score"],
                "reasons": result["reasons"]
            })

            for url_reason in result["reasons"]:

                reasons.append(
                    f"URL: {url_reason}"
                )

            rule_score += result["score"]

    # --------------------------------------------------------
    # CAP RULE SCORE
    # --------------------------------------------------------

    rule_score = min(rule_score, 100)

    # --------------------------------------------------------
    # AI MODEL
    # --------------------------------------------------------

    ai_label, ai_score = ai_prediction(message)

    # --------------------------------------------------------
    # FINAL SCORE
    # --------------------------------------------------------

    final_score = (
        (rule_score * 0.60)
        +
        (ai_score * 0.40)
    )

    final_score = min(
        round(final_score, 2),
        100
    )

    # --------------------------------------------------------
    # RISK LEVEL
    # --------------------------------------------------------

    risk = risk_level(final_score)

    # --------------------------------------------------------
    # THREAT CATEGORY
    # --------------------------------------------------------

    category = detect_threat_category(message)

    # --------------------------------------------------------
    # ADD AI EXPLANATION
    # --------------------------------------------------------

    if ai_label == "scam":

        reasons.append(
            "AI model identified patterns similar to scam messages"
        )

    elif ai_label == "normal":

        reasons.append(
            "AI model did not identify strong scam patterns"
        )

    # --------------------------------------------------------
    # RECOMMENDATION
    # --------------------------------------------------------

    recommendation = get_recommendation(
        risk,
        category
    )

    # --------------------------------------------------------
    # RETURN RESULT
    # --------------------------------------------------------

    return {

        "score": final_score,

        "risk": risk,

        "category": category,

        "ai_score": ai_score,

        "ai_prediction": ai_label,

        "rule_score": rule_score,

        "reasons": reasons,

        "urls": urls,

        "url_analysis": url_results,

        "recommendation": recommendation
    }


# ============================================================
# URL ANALYZER
# ============================================================

def analyze_url(url):

    score = 0

    reasons = []

    try:

        parsed = urlparse(url)

        # ----------------------------------------------------
        # HTTPS CHECK
        # ----------------------------------------------------

        if parsed.scheme.lower() != "https":

            score += 15

            reasons.append(
                "URL is not using HTTPS"
            )

        # ----------------------------------------------------
        # URL LENGTH
        # ----------------------------------------------------

        if len(url) > 100:

            score += 10

            reasons.append(
                "URL is unusually long"
            )

        # ----------------------------------------------------
        # @ SYMBOL
        # ----------------------------------------------------

        if "@" in url:

            score += 20

            reasons.append(
                "URL contains '@', which can hide the real destination"
            )

        # ----------------------------------------------------
        # IP ADDRESS
        # ----------------------------------------------------

        hostname = parsed.hostname

        if hostname:

            ip_parts = hostname.split(".")

            if (
                len(ip_parts) == 4
                and all(
                    part.isdigit()
                    and 0 <= int(part) <= 255
                    for part in ip_parts
                )
            ):

                score += 25

                reasons.append(
                    "URL uses an IP address instead of a normal domain"
                )

        # ----------------------------------------------------
        # SUSPICIOUS URL WORDS
        # ----------------------------------------------------

        suspicious_url_words = [
            "login",
            "verify",
            "account",
            "password",
            "bank",
            "wallet",
            "claim",
            "secure",
            "update",
            "signin",
            "confirm"
        ]

        for word in suspicious_url_words:

            if word in url.lower():

                score += 5

                reasons.append(
                    f"Suspicious URL keyword detected: '{word}'"
                )

        # ----------------------------------------------------
        # MULTIPLE SUBDOMAINS
        # ----------------------------------------------------

        if hostname:

            domain_parts = hostname.split(".")

            if len(domain_parts) >= 4:

                score += 10

                reasons.append(
                    "URL contains an unusually complex subdomain structure"
                )

        # ----------------------------------------------------
        # URL ENCODING
        # ----------------------------------------------------

        if "%" in url:

            score += 5

            reasons.append(
                "URL contains encoded characters"
            )

        # ----------------------------------------------------
        # PORT CHECK
        # ----------------------------------------------------

        try:

            if parsed.port not in [None, 80, 443]:

                score += 10

                reasons.append(
                    "URL uses a non-standard network port"
                )

        except ValueError:

            score += 10

            reasons.append(
                "URL contains an invalid port"
            )

        # ----------------------------------------------------
        # DOMAIN CHECK
        # ----------------------------------------------------

        if hostname:

            if hostname.startswith("xn--"):

                score += 15

                reasons.append(
                    "Domain uses punycode encoding"
                )

        # ----------------------------------------------------
        # FINAL SCORE
        # ----------------------------------------------------

        score = min(score, 100)

        return {
            "score": score,
            "reasons": reasons
        }

    except Exception as error:

        return {
            "score": 0,
            "reasons": [
                f"Could not analyze URL: {error}"
            ]
        }


# ============================================================
# RISK LEVEL
# ============================================================

def risk_level(score):

    if score >= 60:

        return "HIGH"

    elif score >= 30:

        return "MEDIUM"

    else:

        return "LOW"


# ============================================================
# RECOMMENDATION
# ============================================================

def get_recommendation(risk, category):

    if risk == "HIGH":

        return (
            "Do not click links or provide passwords, "
            "OTPs, PINs, card details, or financial information. "
            "Verify the message through the organization's "
            "official website or application."
        )

    if risk == "MEDIUM":

        return (
            "Be careful before responding. "
            "Do not share sensitive information. "
            "Verify the sender using an official website, "
            "application, or trusted contact."
        )

    return (
        "No major threat indicators were detected. "
        "Still avoid sharing sensitive information "
        "and verify unexpected requests."
    )