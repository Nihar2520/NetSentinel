import requests

url = "http://127.0.0.1:5000/predict"
data = {"packet_size": 500, "packet_time": 0.02}

response = requests.post(url, json=data)
print(response.json())
