import re
import math
from urllib.parse import urlparse


def extract_features(url):

    features = {}

    url = str(url).strip()

    parsed = urlparse(url)

    hostname = parsed.netloc
    path = parsed.path
    query = parsed.query

    # ==========================================
    # BASIC URL FEATURES
    # ==========================================

    features["url_length"] = len(url)

    features["hostname_length"] = len(hostname)

    features["path_length"] = len(path)

    features["query_length"] = len(query)


    # ==========================================
    # CHARACTER FEATURES
    # ==========================================

    features["num_dots"] = url.count(".")

    features["num_hyphens"] = url.count("-")

    features["num_slashes"] = url.count("/")

    features["num_question_marks"] = url.count("?")

    features["num_equals"] = url.count("=")

    features["num_at"] = url.count("@")

    features["num_ampersands"] = url.count("&")

    features["num_percent"] = url.count("%")

    features["num_digits"] = sum(
        char.isdigit() for char in url
    )

    features["num_letters"] = sum(
        char.isalpha() for char in url
    )


    # ==========================================
    # URL RATIOS
    # ==========================================

    if len(url) > 0:

        features["digit_ratio"] = (
            features["num_digits"] / len(url)
        )

        features["special_char_ratio"] = (
            sum(
                not char.isalnum()
                for char in url
            ) / len(url)
        )

    else:

        features["digit_ratio"] = 0

        features["special_char_ratio"] = 0


    # ==========================================
    # PROTOCOL FEATURES
    # ==========================================

    features["has_https"] = (
        1 if url.lower().startswith("https://") else 0
    )

    features["has_http"] = (
        1 if url.lower().startswith("http://") else 0
    )


    # ==========================================
    # IP ADDRESS DETECTION
    # ==========================================

    ip_pattern = r"^(?:\d{1,3}\.){3}\d{1,3}$"

    hostname_clean = hostname.split(":")[0]

    features["has_ip"] = (
        1 if re.match(ip_pattern, hostname_clean)
        else 0
    )


    # ==========================================
    # SUBDOMAIN FEATURES
    # ==========================================

    hostname_parts = hostname.split(".")

    features["subdomain_count"] = max(
        0,
        len(hostname_parts) - 2
    )


    # ==========================================
    # SUSPICIOUS WORDS
    # ==========================================

    suspicious_words = [

        "login",
        "signin",
        "verify",
        "verification",
        "account",
        "update",
        "secure",
        "security",
        "bank",
        "banking",
        "password",
        "confirm",
        "confirmation",
        "payment",
        "wallet",
        "credential",
        "authenticate",
        "authentication",
        "recover",
        "unlock",
        "suspended",
        "limited",
        "free",
        "bonus",
        "claim",
        "urgent"

    ]

    url_lower = url.lower()

    features["suspicious_words"] = sum(
        1
        for word in suspicious_words
        if word in url_lower
    )


    # ==========================================
    # BRAND IMPERSONATION WORDS
    # ==========================================

    brands = [

        "paypal",
        "apple",
        "google",
        "microsoft",
        "amazon",
        "facebook",
        "instagram",
        "netflix",
        "linkedin",
        "whatsapp"

    ]

    features["brand_words"] = sum(
        1
        for brand in brands
        if brand in url_lower
    )


    # ==========================================
    # URL ENCODING
    # ==========================================

    features["encoded_characters"] = len(
        re.findall(
            r"%[0-9a-fA-F]{2}",
            url
        )
    )


    # ==========================================
    # DOUBLE SLASH
    # ==========================================

    features["double_slash"] = (
        1 if "//" in path else 0
    )


    # ==========================================
    # DOMAIN HYPHEN
    # ==========================================

    features["domain_has_hyphen"] = (
        1 if "-" in hostname else 0
    )


    # ==========================================
    # LONG DOMAIN
    # ==========================================

    features["long_domain"] = (
        1 if len(hostname) > 30 else 0
    )


    # ==========================================
    # LONG URL
    # ==========================================

    features["long_url"] = (
        1 if len(url) > 75 else 0
    )


    # ==========================================
    # URL ENTROPY
    # ==========================================

    if len(url) > 0:

        probabilities = [

            url.count(char) / len(url)

            for char in set(url)

        ]

        features["url_entropy"] = -sum(

            p * math.log2(p)

            for p in probabilities

            if p > 0

        )

    else:

        features["url_entropy"] = 0


    return features