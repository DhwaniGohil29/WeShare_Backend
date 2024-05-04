from locust import HttpUser, task, between

class MyUser(HttpUser):
    wait_time = between(1, 3)
    registered = True

    @task
    def index(self):
        self.client.get("/")

    @task
    def login(self):
        payload = {
            "email": "test@example.com",
            "password": "password"
        }
        self.client.post("/login", json=payload)

    @task
    def set_preferences(self):
        payload = {
            "email": "test@example.com",
            "branch": "DS",
            "role": "Student",
            "year": "TE",
            "gender": "Male"
        }
        self.client.post("/preferences", json=payload)

    @task
    def find_matching_rides(self):
        payload = {
            "email": "test@example.com",
            "from_latitude": 19.2373887,
            "from_longitude": 72.855002,
            "to_latitude": 19.1187379,
            "to_longitude": 72.8463784
        }
        self.client.post("/find-matching-rides", json=payload)


 # Add more tasks for other endpoints as needed
