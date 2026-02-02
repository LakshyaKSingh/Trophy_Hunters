import json
import subprocess
import sys

def test_agent():
    # Example input from the task
    input_data = {
        "conversation_history": [{"role": "user", "content": "Hello, you won a prize!"}],
        "new_message": "Send UPI to claim."
    }

    # Run the agent script with the input
    process = subprocess.Popen(
        [sys.executable, 'agent.py'],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )
    stdout, stderr = process.communicate(input=json.dumps(input_data))

    if process.returncode != 0:
        print(f"Error: {stderr}")
        return

    output = json.loads(stdout)
    print("Test Output:")
    print(json.dumps(output, indent=2))

if __name__ == "__main__":
    test_agent()
