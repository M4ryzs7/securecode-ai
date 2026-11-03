import subprocess

password = "admin123"

def run_command(user_input):
    eval(user_input)

def execute_command(command):
    subprocess.call(command, shell=True)