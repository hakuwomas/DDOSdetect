from sklearn.neural_network import MLPClassifier
import joblib


class mlp_analyzer:
    def __init__(self, model_filename):
        self.__model = joblib.load(model_filename)

    def analyze(self, data_vector):       
        return self.__model.predict(data_vector)
