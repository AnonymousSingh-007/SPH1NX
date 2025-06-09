# app.py - SPH1NX Backend Server

from flask import Flask, render_template_string
from flask_socketio import SocketIO, emit
import subprocess
import threading
import os
import sys
import signal # For sending signals to processes

# Initialize Flask app and SocketIO
app = Flask(__name__)
# IMPORTANT: Change this secret key in a production environment!
app.config['SECRET_KEY'] = 'a_very_secret_key_for_sph1nx'
# Allow all origins for development purposes. Restrict in production.
socketio = SocketIO(app, cors_allowed_origins="*")

# Define the path to your SPH1NX Python script
# Make sure 'Tool_Code.py' is in the same directory as this 'app.py' file
SPHINX_SCRIPT_PATH = 'Tool_Code.py'

# Global variable to hold the subprocess Popen object
# This allows us to control the running script from different WebSocket events
current_sph1nx_process = None
process_lock = threading.Lock() # To prevent race conditions when accessing current_sph1nx_process

# This route is optional if you are serving the HTML directly from Canvas.
# It's here for completeness if you decide to serve the HTML from Flask later.
@app.route('/')
def index():
    # In a real setup, you would serve your HTML file here:
    # return render_template('index.html')
    # For this demonstration, we'll just return a simple message.
    return render_template_string("""
        <!DOCTYPE html>
        <html>
        <head><title>SPH1NX Backend</title></head>
        <body>
            <h1>SPH1NX Backend Server Running</h1>
            <p>This server is ready to stream logs from your SPH1NX script (Tool_Code.py) via WebSockets.</p>
            <p>Open the SPH1NX Cybersecurity Dashboard HTML in your browser to interact.</p>
        </body>
        </html>
    """)

# WebSocket event handler for client connection
@socketio.on('connect')
def handle_connect():
    """Logs when a new client connects via WebSocket."""
    print('Client connected')
    sys.stdout.flush() # Ensure print statements are immediately flushed

# WebSocket event handler for client disconnection
@socketio.on('disconnect')
def handle_disconnect():
    """Logs when a client disconnects from the WebSocket."""
    print('Client disconnected')
    sys.stdout.flush()
    # Optionally, stop the script if the client disconnects
    # stop_sph1nx_script() # Uncomment this line if you want the script to stop automatically on client disconnect

# WebSocket event handler to start the SPH1NX script
@socketio.on('start_sph1nx')
def start_sph1nx_script():
    """
    Starts the SPH1NX Python script (Tool_Code.py) in a new thread and streams its output
    back to the connected client via WebSocket.
    """
    global current_sph1nx_process

    with process_lock:
        if current_sph1nx_process and current_sph1nx_process.poll() is None:
            # Script is already running
            emit('log_update', "SPH1NX script is already running.")
            return

    print(f"Received 'start_sph1nx' event. Starting SPH1NX script: {SPHINX_SCRIPT_PATH}...")
    sys.stdout.flush()

    def run_script_in_thread():
        """
        Executes the SPH1NX script and captures its output.
        Each line of output is emitted to the connected client.
        """
        global current_sph1nx_process
        try:
            # Check if the script file exists
            if not os.path.exists(SPHINX_SCRIPT_PATH):
                error_msg = f"Error: SPH1NX script '{SPHINX_SCRIPT_PATH}' not found. Please ensure it's in the same directory as app.py."
                socketio.emit('log_update', error_msg)
                print(error_msg)
                sys.stdout.flush()
                return

            # Use subprocess.Popen to run the script and capture its output.
            process = subprocess.Popen(
                ['python', SPHINX_SCRIPT_PATH],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT, # Redirect stderr to stdout
                text=True,
                bufsize=1, # Line-buffered
                universal_newlines=True
            )

            with process_lock:
                current_sph1nx_process = process # Store the process object

            # Read output line by line and emit it to the client
            for line in iter(process.stdout.readline, ''):
                # Check if the process has been terminated externally
                if process.poll() is not None:
                    break # Exit loop if process has finished or was terminated
                socketio.emit('log_update', line.strip())
                print(f"Emitted: {line.strip()}")
                sys.stdout.flush()

            # Wait for the process to fully terminate (if not already)
            process.wait()

            with process_lock:
                # Clear the process reference after it finishes
                if current_sph1nx_process == process: # Only clear if it's still our process
                    current_sph1nx_process = None

            # Notify the client that the script has finished (if not stopped manually)
            # Only send message if it wasn't already sent by the stop_sph1nx_script function
            if not process.returncode is None: # Check if process has returned a code
                if process.returncode == 0: # Exited normally
                    socketio.emit('script_stopped', "SPH1NX script finished normally.")
                elif process.returncode != 0: # Terminated or crashed
                    socketio.emit('script_stopped', f"SPH1NX script terminated with exit code {process.returncode}.")

            print("SPH1NX script finished.")
            sys.stdout.flush()

        except FileNotFoundError:
            error_msg = "Error: Python interpreter not found. Ensure Python is installed and in your system's PATH."
            socketio.emit('log_update', error_msg)
            print(error_msg)
            sys.stdout.flush()
            with process_lock:
                current_sph1nx_process = None
            socketio.emit('script_stopped', "SPH1NX script failed to start (Python not found).")
        except Exception as e:
            error_msg = f"An unexpected error occurred during script execution: {e}"
            socketio.emit('log_update', error_msg)
            print(error_msg)
            sys.stdout.flush()
            with process_lock:
                current_sph1nx_process = None
            socketio.emit('script_stopped', "SPH1NX script encountered an error during execution.")

    # Start the script execution in a new thread
    thread = threading.Thread(target=run_script_in_thread)
    thread.daemon = True
    thread.start()

# WebSocket event handler to stop the SPH1NX script
@socketio.on('stop_sph1nx')
def stop_sph1nx_script():
    """
    Attempts to stop the currently running SPH1NX script.
    """
    global current_sph1nx_process
    print("Received 'stop_sph1nx' event. Attempting to stop SPH1NX script...")
    sys.stdout.flush()

    with process_lock:
        if current_sph1nx_process and current_sph1nx_process.poll() is None: # Check if it's running
            try:
                # Terminate the process
                current_sph1nx_process.terminate()
                # Wait a short time for it to terminate gracefully
                current_sph1nx_process.wait(timeout=5)
                message = "SPH1NX script stopped by user."
            except subprocess.TimeoutExpired:
                # If it doesn't terminate gracefully, kill it
                current_sph1nx_process.kill()
                message = "SPH1NX script forcefully stopped by user."
            except Exception as e:
                message = f"Error stopping script: {e}"
                print(message)
                sys.stdout.flush()
            finally:
                # Ensure the process reference is cleared after stopping
                if current_sph1nx_process and current_sph1nx_process.poll() is not None:
                     current_sph1nx_process = None
                emit('script_stopped', message) # Notify frontend
        else:
            message = "No SPH1NX script is currently running."
            emit('script_stopped', message) # Notify frontend
            print(message)
            sys.stdout.flush()

# Main entry point for running the Flask app
if __name__ == '__main__':
    print(f"Starting Flask-SocketIO server. Make sure '{SPHINX_SCRIPT_PATH}' is in the same directory.")
    print("Access the HTML dashboard in your browser to interact.")
    sys.stdout.flush()
    socketio.run(app, debug=True, allow_unsafe_werkzeug=True)
