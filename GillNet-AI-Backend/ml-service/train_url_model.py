import pandas as pd
import pickle

from sklearn.model_selection import train_test_split, GridSearchCV
from sklearn.ensemble import RandomForestClassifier, ExtraTreesClassifier, GradientBoostingClassifier
from sklearn.svm import SVC
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix


# Load dataset
df = pd.read_csv("phishing.csv")

# URL-based features that we can realistically derive from a URL
URL_FEATURES = [
    "having_IP_Address",
    "URL_Length",
    "Shortining_Service",
    "having_At_Symbol",
    "double_slash_redirecting",
    "Prefix_Suffix",
    "having_Sub_Domain",
    "SSLfinal_State",
    "port"
]

print("URL-based features:")
for feature in URL_FEATURES:
    print("-", feature)

print("\nNumber of features:", len(URL_FEATURES))


# Check that all features exist
missing = [f for f in URL_FEATURES if f not in df.columns]

if missing:
    print("\nERROR: Missing features:", missing)
    exit()


# Input and target
X = df[URL_FEATURES]
y = df["Result"]


# Train/test split
X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.2,
    random_state=42,
    stratify=y
)

print("\nTraining samples:", len(X_train))
print("Testing samples:", len(X_test))


# --------------------------------------------------
# MODELS
# --------------------------------------------------

models = {

    "Random Forest": (
        RandomForestClassifier(
            random_state=42,
            n_jobs=-1
        ),
        {
            "n_estimators": [200, 300, 500],
            "max_depth": [None, 10, 20, 30],
            "min_samples_split": [2, 5],
            "min_samples_leaf": [1, 2]
        }
    ),

    "Extra Trees": (
        ExtraTreesClassifier(
            random_state=42,
            n_jobs=-1
        ),
        {
            "n_estimators": [200, 300, 500],
            "max_depth": [None, 10, 20, 30],
            "min_samples_split": [2, 5],
            "min_samples_leaf": [1, 2]
        }
    ),

    "Gradient Boosting": (
        GradientBoostingClassifier(
            random_state=42
        ),
        {
            "n_estimators": [100, 200],
            "learning_rate": [0.05, 0.1],
            "max_depth": [2, 3]
        }
    ),

    "SVM": (
        SVC(
            probability=True,
            random_state=42
        ),
        {
            "C": [0.5, 1, 2, 5],
            "kernel": ["rbf", "linear"],
            "gamma": ["scale", "auto"]
        }
    )
}


# --------------------------------------------------
# TRAIN MODELS
# --------------------------------------------------

results = {}

best_model = None
best_accuracy = 0
best_name = ""


for name, (model, params) in models.items():

    print("\n======================================")
    print("Training:", name)
    print("======================================")

    grid = GridSearchCV(
        model,
        params,
        cv=3,
        scoring="accuracy",
        n_jobs=-1,
        verbose=1
    )

    grid.fit(X_train, y_train)

    model_best = grid.best_estimator_

    predictions = model_best.predict(X_test)

    accuracy = accuracy_score(y_test, predictions)

    results[name] = accuracy

    print("\nBest Parameters:")
    print(grid.best_params_)

    print("\nAccuracy:", accuracy)

    print("\nClassification Report:")
    print(classification_report(y_test, predictions))

    print("\nConfusion Matrix:")
    print(confusion_matrix(y_test, predictions))


    if accuracy > best_accuracy:

        best_accuracy = accuracy
        best_model = model_best
        best_name = name


# --------------------------------------------------
# FINAL RESULT
# --------------------------------------------------

print("\n\n======================================")
print("FINAL BEST MODEL")
print("======================================")

print("Model:", best_name)
print("Accuracy:", best_accuracy)


# Save model
with open("phishing_url_model.pkl", "wb") as f:
    pickle.dump(best_model, f)


# Save feature names
with open("url_feature_names.pkl", "wb") as f:
    pickle.dump(URL_FEATURES, f)


# Save model information
with open("url_model_info.pkl", "wb") as f:
    pickle.dump({
        "model_name": best_name,
        "accuracy": best_accuracy,
        "features": URL_FEATURES,
        "all_results": results
    }, f)


print("\nModel saved as phishing_url_model.pkl")
print("Feature names saved as url_feature_names.pkl")
print("Model information saved as url_model_info.pkl")