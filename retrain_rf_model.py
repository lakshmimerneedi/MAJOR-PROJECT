import pandas as pd
from sklearn.ensemble import RandomForestClassifier
import pickle

# Load the crop dataset
df = pd.read_csv("crop_recommendation.csv")

# Features and target
X = df.drop("label", axis=1)
y = df["label"]

# Train the model
model = RandomForestClassifier()
model.fit(X, y)

# Save the new model (overwrites old rfmodel.pkl)
with open("rfmodel.pkl", "wb") as f:
    pickle.dump(model, f)

print("✅ New rfmodel.pkl generated successfully and safely.")
