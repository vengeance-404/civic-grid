import requests
import json

# The URL of your local Flask server
url = 'http://127.0.0.1:5000/api/report'

# Open the image file safely
try:
    with open('test.jpg', 'rb') as img_file:
        files = {'image': img_file}
        print("Sending image to the AI...")
        
        # Send the POST request to our Flask app
        response = requests.post(url, files=files)
        
        # Print the structured JSON response
        print("\nAI Response:")
        print(json.dumps(response.json(), indent=2))
        
except FileNotFoundError:
    print("Error: Could not find 'test.jpg'. Make sure it is in the same folder!")