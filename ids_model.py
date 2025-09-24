# ids_model.py
import numpy as np
from sklearn.ensemble import IsolationForest

class IDSModel:
    def __init__(self):
        # Initialize Isolation Forest (unsupervised anomaly detection)
        self.model = IsolationForest(
            n_estimators=100,
            contamination=0.05,  # expected anomaly ratio (tuneable)
            random_state=42
        )
        self.is_trained = False

    def train(self, X):
        """
        Train the Isolation Forest model on baseline "normal" traffic.
        X: numpy array with shape (n_samples, n_features)
        """
        self.model.fit(X)
        self.is_trained = True

    def predict(self, features: dict):
        """
        Predict if the given traffic sample is normal or anomalous.
        features: {"packet_size": int, "packet_time": float}
        Returns: (prediction_label, score)
        """
        if not self.is_trained:
            # Cold start: auto-train with synthetic baseline
            print("[INFO] Training IDS model with synthetic baseline...")
            baseline = np.array([[100, 0.01], [200, 0.05], [300, 0.1], [400, 0.2]])
            self.train(baseline)

        # Convert dict → numpy array
        X_test = np.array([[features["packet_size"], features["packet_time"]]])

        # Prediction (-1 = anomaly, 1 = normal)
        pred = self.model.predict(X_test)[0]
        score = self.model.decision_function(X_test)[0]

        label = "anomaly" if pred == -1 else "normal"
        return label, float(score)


# Quick test
if __name__ == "__main__":
    ids = IDSModel()

    # Example traffic
    sample = {"packet_size": 500, "packet_time": 0.02}
    label, score = ids.predict(sample)
    print(f"Prediction: {label}, Score: {score}")
