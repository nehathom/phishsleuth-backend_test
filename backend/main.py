# /opt/anaconda3/bin/python -m pip install FastAPI

from fastapi import FastAPI, Request, status 
from pydantic import BaseModel
import pandas as pd
import joblib
import shap
from typing import List
from fastapi.responses import JSONResponse
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
import traceback
from typing import Optional
from fastapi.exceptions import RequestValidationError
import json
from urllib.parse import urlparse

SAFE_DOMAINS = [
    'linkedin.com', 'google.com', 'github.com',
    'microsoft.com', 'apple.com', 'amazon.com',
    'stackoverflow.com', 'facebook.com'
]


# Init limiter
limiter = Limiter(key_func=get_remote_address)
app = FastAPI()
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# Load trained model and SHAP explainer
model = joblib.load("xgb_model_retrained_newdata.pkl")
explainer = shap.TreeExplainer(model)




feature_explanations = {
    "URLLength": "Length of the URL",
    "DomainLength": "Length of the domain part of the URL",
    "IsDomainIP": "Whether the domain is an IP address",
    "NoOfSubDomain": "Number of subdomains",
    "HasObfuscation": "Presence of obfuscation techniques",
    "NoOfLettersInURL": "Count of letters in the URL",
    "LetterRatioInURL": "Ratio of letters in the URL",
    "NoOfDegitsInURL": "Count of digits in the URL",
    "DegitRatioInURL": "Ratio of digits in the URL",
    "NoOfEqualsInURL": "Number of '=' characters",
    "NoOfQMarkInURL": "Number of '?' characters",
    "NoOfAmpersandInURL": "Number of '&' characters",
    "IsHTTPS": "Whether HTTPS protocol is used",
    "NoOfURLRedirect": "Number of URL redirects",
    "HasFavicon": "Presence of favicon",
    "NoOfPopup": "Number of popups",
    "NoOfiFrame": "Number of iframe tags",
    "HasExternalFormSubmit": "Form submits data externally",
    "HasSubmitButton": "Presence of submit buttons",
    "HasPasswordField": "Presence of password input fields",
    "HasCopyrightInfo": "Presence of copyright info",
    "label": "Target variable: phishing (1) or legitimate (0)"
    # Add more as needed
}

# Define your Pydantic model with all features from the new dataset
class URLFeatures(BaseModel):
    URLLength: int
    DomainLength: int
    IsDomainIP: int
    NoOfSubDomain: int
    HasObfuscation: int
    NoOfObfuscatedChar: int
    ObfuscationRatio: float
    NoOfLettersInURL: int
    LetterRatioInURL: float
    NoOfDegitsInURL: int
    DegitRatioInURL: float
    NoOfEqualsInURL: int
    NoOfQMarkInURL: int
    NoOfAmpersandInURL: int
    NoOfOtherSpecialCharsInURL: int
    SpacialCharRatioInURL: float
    IsHTTPS: int
    LineOfCode: int
    LargestLineLength: int
    HasFavicon: int
    Robots: int
    IsResponsive: int
    NoOfURLRedirect: int
    NoOfSelfRedirect: int
    HasDescription: int
    NoOfPopup: int
    NoOfiFrame: int
    HasExternalFormSubmit: int
    HasSocialNet: int
    HasSubmitButton: int
    HasHiddenFields: int
    HasPasswordField: int
    Bank: int
    Pay: int
    Crypto: int
    HasCopyrightInfo: int
    NoOfImage: int
    NoOfCSS: int
    NoOfJS: int
    NoOfSelfRef: int
    NoOfEmptyRef: int
    NoOfExternalRef: int

    # Make these optional or provide defaults if not in training
    HasTitle: Optional[int] = None
    Title: Optional[str] = None
    DomainTitleMatchScore: Optional[float] = None
    URLTitleMatchScore: Optional[float] = None

class BatchFeatures(BaseModel):
    inputs: List[URLFeatures]

@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    return JSONResponse(
        status_code=422,
        content={
            "detail": exc.errors(),
            "body": json.loads(await request.body())
        },
    )

@app.post("/analyze")
@limiter.limit("10/minute")
async def analyze(features: URLFeatures, request: Request):
    print("Received data:", await request.body())
    try:
       
        # Convert pydantic model to dict
        data_dict = features.model_dump()

        # Remove 'Title' before prediction because it's a string
        for key in ['Title', 'HasTitle', 'DomainTitleMatchScore', 'URLTitleMatchScore']:
            data_dict.pop(key, None)


        input_df = pd.DataFrame([data_dict])
        prediction = model.predict(input_df)[0]
        label = "legitimate" if prediction == 1 else "phishing"

        shap_output = explainer(input_df)
        shap_values = shap_output.values[0]

        feature_impact = {
            key: float(val)
            for key, val in zip(input_df.columns, shap_values)
        }

        sorted_impact = sorted(
            feature_impact.items(), key=lambda x: abs(x[1]), reverse=True
        )

        top_features = {
            feature: {
                "shap_value": shap_val,
                "explanation": feature_explanations.get(feature, "No explanation available")
            }
            for feature, shap_val in sorted_impact[:5]
        }
        print("Prediction:", label)
        print("Top features:", top_features)

        return {
            "prediction": label,
            "top_shap_features": top_features,
            "shap_explanation": feature_impact
        }

    except ValueError as ve:
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={"error": f"ValueError: {str(ve)}"}
        )
    except Exception as e:
        print("Unexpected error:", str(e))
        print(traceback.format_exc())
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={"error": f"Unexpected error:, {str(e)}"}
        )


@app.post("/analyze_batch")
@limiter.limit("5/minute")
def analyze_batch(batch: BatchFeatures, request: Request):
    try:
        results = []
        inputs_for_model = []
        indexes_for_model = []

        # Preprocess inputs and do trusted domain check
        for idx, feature_obj in enumerate(batch.inputs):
            hostname = feature_obj.hostname.lower()
            if hostname.startswith("www."):
                hostname = hostname[4:]

            # If trusted domain, skip model prediction and add direct result
            if any(domain == hostname or hostname.endswith('.' + domain) for domain in SAFE_DOMAINS):
                results.append({
                    "prediction": "legitimate",
                    "top_shap_features": {},
                    "shap_explanation": {},
                    "reason": f"Trusted domain: {hostname}"
                })
            else:
                # Keep inputs for model prediction
                inputs_for_model.append(feature_obj.model_dump())
                indexes_for_model.append(idx)
                # Append placeholder to results for now
                results.append(None)

        # If there are inputs to predict
        if inputs_for_model:
            input_df = pd.DataFrame(inputs_for_model)

            # Remove string keys before prediction
            for key in ['Title', 'HasTitle', 'DomainTitleMatchScore', 'URLTitleMatchScore']:
                if key in input_df.columns:
                    input_df = input_df.drop(columns=[key])

            preds = model.predict(input_df)
            shap_values = explainer(input_df).values

            # Fill in the results for inputs that went through model
            for i, pred in enumerate(preds):
                label = "legitimate" if pred == 1 else "phishing"

                feature_impact = {
                    col: float(shap_values[i][j])
                    for j, col in enumerate(input_df.columns)
                }

                sorted_impact = sorted(
                    feature_impact.items(), key=lambda x: abs(x[1]), reverse=True
                )

                top_features = {
                    feature: {
                        "shap_value": shap_val,
                        "explanation": feature_explanations.get(feature, "No explanation available")
                    }
                    for feature, shap_val in sorted_impact[:5]
                }

                # Place result at correct index
                results[indexes_for_model[i]] = {
                    "prediction": label,
                    "top_shap_features": top_features,
                    "shap_explanation": feature_impact
                }

        return {"results": results}

    except ValueError as ve:
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={"error": f"ValueError: {str(ve)}"}
        )
    except Exception as e:
        print("Unexpected error:", str(e))
        print(traceback.format_exc())
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={"error": f"Unexpected error: {str(e)}"}
        )
