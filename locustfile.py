from locust import HttpUser, task, between
import re

class StudentUser(HttpUser):
    wait_time = between(1, 3)
    host = "http://localhost:5000"

    def on_start(self):
        self.client.post("/login", data={"username": "testuser", "password": "testusn"})

    @task
    def index(self):
        self.client.get("/")

    @task
    def dashboard(self):
        self.client.get("/dashboard")

    @task
    def request_page_get(self):
        self.client.get("/request")

    @task
    def request_page_post(self):
        self.client.post("/request", data={"request_message": "Please process my clearance."})

    @task
    def profile_get(self):
        self.client.get("/profile")

    @task
    def profile_post(self):
        self.client.post("/profile", data={
            "username": "testuser",
            "student_id": "testusn",
            "email": "testuser@example.com",
            "phone": "1234567890",
            "address": "Test Address"
        })

    @task
    def notifications(self):
        self.client.get("/notifications")

    @task
    def remarks(self):
        self.client.get("/remarks")

    @task
    def resubmit_remarks(self):
        self.client.post("/resubmit_remarks", data={"note": "Resubmitting my remarks."})

class OfficerUser(HttpUser):
    wait_time = between(1, 3)
    host = "http://localhost:5000"

    def on_start(self):
        self.client.post("/officer_login", data={"username": "BEDDean", "password": "2025"})

    @task
    def officer_dashboard(self):
        self.client.get("/officer_dashboard")

    @task
    def officer_requests(self):
        self.client.get("/officer_requests")

    @task
    def officer_departments(self):
        self.client.get("/officer_departments")

    @task
    def officer_notifications(self):
        self.client.get("/officer_notifications")

    @task
    def officer_logout(self):
        self.client.post("/officer_logout")

class AdminUser(HttpUser):
    wait_time = between(5, 10)  # Slower actions for admin
    host = "http://localhost:5000"

    def on_start(self):
        self.client.post("/admin_login", data={"username": "admin", "password": "2025"})
        self.deleted_ids = set()

    def get_valid_user_id(self):
        response = self.client.get("/admin_dashboard")
        matches = re.findall(r'/admin_edit_user/(\d+)', response.text)
        for uid in matches:
            if uid != "1" and uid not in self.deleted_ids:
                return uid
        return None

    @task
    def admin_edit_user(self):
        user_id = self.get_valid_user_id()
        if user_id:
            resp = self.client.get(f"/admin_edit_user/{user_id}", catch_response=True)
            if resp.status_code == 404:
                self.deleted_ids.add(user_id)

    @task(2)
    def admin_delete_user(self):
        user_id = self.get_valid_user_id()
        if user_id:
            resp = self.client.post(f"/admin_delete_user/{user_id}", catch_response=True)
            if resp.status_code == 404:
                self.deleted_ids.add(user_id)