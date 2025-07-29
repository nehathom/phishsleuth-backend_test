import pytest
from fastapi.testclient import TestClient
from main import app

client = TestClient(app)

# Sample input matching your new feature schema
sample_input = {
    "URLLength": 80,
    "DomainLength": 12,
    "IsDomainIP": 0,
    "NoOfSubDomain": 1,
    "HasObfuscation": 0,
    "NoOfObfuscatedChar": 0,
    "ObfuscationRatio": 0.0,
    "NoOfLettersInURL": 45,
    "LetterRatioInURL": 0.56,
    "NoOfDegitsInURL": 5,
    "DegitRatioInURL": 0.12,
    "NoOfEqualsInURL": 1,
    "NoOfQMarkInURL": 1,
    "NoOfAmpersandInURL": 0,
    "NoOfOtherSpecialCharsInURL": 2,
    "SpacialCharRatioInURL": 0.03,
    "IsHTTPS": 1,
    "LineOfCode": 150,
    "LargestLineLength": 300,
    "HasTitle": 1,
    "Title": "Welcome to Amazon",
    "DomainTitleMatchScore": 0.9,
    "URLTitleMatchScore": 0.85,
    "HasFavicon": 1,
    "Robots": 1,
    "IsResponsive": 1,
    "NoOfURLRedirect": 0,
    "NoOfSelfRedirect": 0,
    "HasDescription": 1,
    "NoOfPopup": 0,
    "NoOfiFrame": 0,
    "HasExternalFormSubmit": 0,
    "HasSocialNet": 1,
    "HasSubmitButton": 1,
    "HasHiddenFields": 0,
    "HasPasswordField": 1,
    "Bank": 0,
    "Pay": 1,
    "Crypto": 0,
    "HasCopyrightInfo": 1,
    "NoOfImage": 8,
    "NoOfCSS": 2,
    "NoOfJS": 5,
    "NoOfSelfRef": 12,
    "NoOfEmptyRef": 0,
    "NoOfExternalRef": 4
}

def test_analyze_endpoint():
    response = client.post("/analyze", json=sample_input)
    assert response.status_code == 200
    data = response.json()
    assert "prediction" in data
    assert "top_shap_features" in data
    assert isinstance(data["top_shap_features"], dict)

def test_analyze_batch_endpoint():
    response = client.post("/analyze_batch", json={
        "inputs": [sample_input, sample_input]
    })
    assert response.status_code == 200
    print("Response JSON:", response.json())

