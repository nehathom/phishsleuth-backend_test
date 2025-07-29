import joblib
import pandas as pd
from sklearn.model_selection import train_test_split
import xgboost as xgb
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
from sklearn.preprocessing import LabelEncoder

# Load new dataset
df = pd.read_csv('/Users/nehathomas/Desktop/phishing/backend/PhiUSIIL_Phishing_URL_Dataset.csv')

# If label column already numeric (0 = legit, 1 = phishing), no mapping needed
# If not, map accordingly here, e.g.,
# df['label'] = df['label'].map({'phishing': 1, 'legitimate': 0})



# List of selected features from your new dataset (excluding text for now)
selected_features = [
    'URLLength',
    'DomainLength',
    'IsDomainIP',
    'NoOfSubDomain',
    'HasObfuscation',
    'NoOfObfuscatedChar',
    'ObfuscationRatio',
    'NoOfLettersInURL',
    'LetterRatioInURL',
    'NoOfDegitsInURL',
    'DegitRatioInURL',
    'NoOfEqualsInURL',
    'NoOfQMarkInURL',
    'NoOfAmpersandInURL',
    'NoOfOtherSpecialCharsInURL',
    'SpacialCharRatioInURL',
    'IsHTTPS',
    'LineOfCode',
    'LargestLineLength',
    'HasFavicon',
    'Robots',
    'IsResponsive',
    'NoOfURLRedirect',
    'NoOfSelfRedirect',
    'HasDescription',
    'NoOfPopup',
    'NoOfiFrame',
    'HasExternalFormSubmit',
    'HasSocialNet',
    'HasSubmitButton',
    'HasHiddenFields',
    'HasPasswordField',
    'Bank',
    'Pay',
    'Crypto',
    'HasCopyrightInfo',
    'NoOfImage',
    'NoOfCSS',
    'NoOfJS',
    'NoOfSelfRef',
    'NoOfEmptyRef',
    'NoOfExternalRef'
]

# Optional: encode categorical/binary columns (if any are strings)
# For example, if 'Bank', 'Pay', 'Crypto' are strings instead of 0/1:
# for col in ['Bank', 'Pay', 'Crypto']:
#     le = LabelEncoder()
#     df[col] = le.fit_transform(df[col].astype(str))


X = df[selected_features]
y = df['label']

# Train/test split
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# Initialize and train model
model = xgb.XGBClassifier(use_label_encoder=False, eval_metric='logloss')
model.fit(X_train, y_train)

# Predict and evaluate
y_pred = model.predict(X_test)
print("Accuracy:", accuracy_score(y_test, y_pred))
print("Confusion Matrix:\n", confusion_matrix(y_test, y_pred))
print("Classification Report:\n", classification_report(y_test, y_pred))

# Save the model
joblib.dump(model, "xgb_model.pkl")


