import argparse
import secrets
import string
import threading
import time
from urllib.error import URLError
import urllib.request
import json
from concurrent.futures import ThreadPoolExecutor

from tools.llm_chat_test import JsonClient, service_url

def random_string(length):
    return ''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(length))

def bot_task(base_url, agent_id, room, num_messages, delay_between_messages):
    client = JsonClient(base_url)
    username = f"bot_{agent_id}_{random_string(6)}"
    password = random_string(16)
    
    try:
        # Register
        status, _ = client.request("POST", "/register", {"username": username, "password": password})
        if status != 201: return False
        
        # Login
        status, body = client.request("POST", "/login", {"username": username, "password": password})
        if status != 200: return False
        token = body.get("token")
        
        # Join Room
        status, _ = client.request("POST", f"/rooms/{room}/join", token=token)
        if status not in (200, 201):
            # Try to create if it doesn't exist
            status, _ = client.request("POST", "/rooms", {"room": room}, token=token)
            if status != 201: return False

        # Send Messages
        for i in range(num_messages):
            msg = f"Hello from {username}! Message {i}"
            client.request("POST", f"/rooms/{room}/messages", {"message": msg}, token=token)
            time.sleep(delay_between_messages)

        # Logout
        client.request("POST", "/logout", token=token)
        return True
    except Exception as e:
        print(f"[{username}] Error: {e}")
        return False

def run_load_test(args):
    print(f"Starting load test with {args.users} users across {args.rooms} rooms...")
    print(f"Each user will send {args.messages} messages with a {args.delay}s delay.")
    
    start_time = time.time()
    success_count = 0
    
    with ThreadPoolExecutor(max_workers=args.users) as executor:
        futures = []
        for i in range(args.users):
            room_name = f"loadroom_{i % args.rooms}"
            futures.append(executor.submit(
                bot_task, args.server_url, i, room_name, args.messages, args.delay
            ))
            
        for future in futures:
            if future.result():
                success_count += 1
                
    end_time = time.time()
    duration = end_time - start_time
    
    print("\n--- Load Test Results ---")
    print(f"Duration: {duration:.2f} seconds")
    print(f"Successful bots: {success_count} / {args.users}")
    print(f"Total messages targeted: {args.users * args.messages}")
    print("-------------------------")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Load test for Chat REST API")
    parser.add_argument("--server-url", type=service_url, default="http://127.0.0.1:8000")
    parser.add_argument("--users", type=int, default=50, help="Number of concurrent users")
    parser.add_argument("--rooms", type=int, default=5, help="Number of rooms to distribute users across")
    parser.add_argument("--messages", type=int, default=10, help="Messages per user")
    parser.add_argument("--delay", type=float, default=0.2, help="Delay between messages in seconds")
    args = parser.parse_args()
    run_load_test(args)
